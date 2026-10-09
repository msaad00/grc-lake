"""CLI coverage for the `risk` (server-mode) and `workflow` (lake-backed) groups.

The risk tests run the real Alembic migration against a throwaway SQLite
application-state database, so a green run proves the CLI, the migration, the
models, and the tenant-scoped repository all agree. The workflow tests exercise
the lake-backed engine end to end via a saved workflow.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from security_lakehouse.cli import main
from security_lakehouse.db import migrate
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.workflows import save_workflow


def _provision_tenant(lake: Path, slug: str = "acme") -> str:
    migrate.upgrade(lake)
    factory = session_factory(create_engine_for(lake))
    with session_scope(factory) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        return tenant.slug


# --- risk --------------------------------------------------------------------


def test_risk_add_then_list_round_trips(tmp_path: Path, capsys) -> None:
    slug = _provision_tenant(tmp_path)

    assert (
        main(
            [
                "risk",
                "add",
                "--lake",
                str(tmp_path),
                "--tenant",
                slug,
                "--title",
                "Unencrypted backups",
                "--severity",
                "high",
                "--likelihood",
                "medium",
                "--impact",
                "high",
                "--owner",
                "platform",
                "--category",
                "data-protection",
                "--control-id",
                "SOC2-CC6.1",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["title"] == "Unencrypted backups"
    assert created["severity"] == "high"
    assert created["impact"] == "high"
    assert created["owner"] == "platform"
    assert created["category"] == "data-protection"
    assert created["control_id"] == "SOC2-CC6.1"
    assert created["status"] == "open"
    risk_id = created["id"]

    assert main(["risk", "list", "--lake", str(tmp_path), "--tenant", slug]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["tenant"] == slug
    assert listed["count"] == 1
    assert listed["risks"][0]["id"] == risk_id
    assert listed["risks"][0]["title"] == "Unencrypted backups"


def test_risk_list_status_filter(tmp_path: Path, capsys) -> None:
    slug = _provision_tenant(tmp_path)
    main(["risk", "add", "--lake", str(tmp_path), "--tenant", slug, "--title", "R"])
    capsys.readouterr()

    assert main(["risk", "list", "--lake", str(tmp_path), "--tenant", slug, "--status", "closed"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 0

    assert main(["risk", "list", "--lake", str(tmp_path), "--tenant", slug, "--status", "open"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 1


def test_risk_unknown_tenant_errors(tmp_path: Path) -> None:
    _provision_tenant(tmp_path)
    # Mirrors the `auth` group: an unresolved tenant raises SystemExit with a
    # remediation hint rather than returning a non-zero code through main().
    with pytest.raises(SystemExit, match="no tenant"):
        main(["risk", "list", "--lake", str(tmp_path), "--tenant", "ghost"])


# --- workflow ----------------------------------------------------------------


def _seed_workflow(lake: Path) -> str:
    nodes = [
        {"id": "n1", "node_type": "check.evidence_exists", "params": {"control_id": "SOC2-CC6.1"}},
        {"id": "n2", "node_type": "action.snapshot", "params": {"reason": "cli-test"}},
    ]
    edges = [{"source": "n1", "target": "n2", "condition": "always"}]
    saved = save_workflow(
        lake,
        workflow_id="cli-flow",
        name="CLI Flow",
        description="seeded by cli test",
        nodes=nodes,
        edges=edges,
    )
    return saved["workflow_id"]


def test_workflow_list_shows_saved_workflow(tmp_path: Path, capsys) -> None:
    wid = _seed_workflow(tmp_path)
    assert main(["workflow", "list", "--lake", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["count"] == 1
    assert out["workflows"][0]["workflow_id"] == wid
    assert out["workflows"][0]["name"] == "CLI Flow"


def test_workflow_run_returns_run_record(tmp_path: Path, capsys) -> None:
    wid = _seed_workflow(tmp_path)
    assert main(["workflow", "run", "--lake", str(tmp_path), "--id", wid, "--actor", "api"]) == 0
    run = json.loads(capsys.readouterr().out)
    assert run["workflow_id"] == wid
    assert run["actor"] == "api"
    assert run["result"] in {"ok", "error"}
    node_ids = {entry["node_id"] for entry in run["node_results"]}
    assert node_ids == {"n1", "n2"}


def test_workflow_run_unknown_id_errors(tmp_path: Path, capsys) -> None:
    _seed_workflow(tmp_path)
    rc = main(["workflow", "run", "--lake", str(tmp_path), "--id", "does-not-exist"])
    assert rc == 1
    assert "unknown workflow_id" in capsys.readouterr().err
