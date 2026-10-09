"""The golden demo load seeds a small, synthetic, idempotent set of app-state records."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import func, select

from security_lakehouse.assessment import build_current_posture
from security_lakehouse.auth.authority import INSECURE_IDENTITY
from security_lakehouse.cli import main
from security_lakehouse.db.base import ENV_DATABASE_URL, create_engine_for, session_factory
from security_lakehouse.db.models import (
    PolicyDocument,
    PostureMetricPoint,
    RemediationTask,
    Risk,
    VendorAssessment,
)
from security_lakehouse.demo_seed import DEMO_SEED_ACTOR, SYNTHETIC_MARKER, seed_golden_demo
from security_lakehouse.fixtures import find_fixture
from security_lakehouse.pipeline import run_pipeline

DEMO_TENANT = INSECURE_IDENTITY.tenant_id


@pytest.fixture(autouse=True)
def _lake_local_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_DATABASE_URL, raising=False)


def _counts(lake: Path) -> dict[str, int]:
    factory = session_factory(create_engine_for(lake))
    with factory() as session:
        return {
            model.__tablename__: int(
                session.scalar(select(func.count()).select_from(model).where(model.tenant_id == DEMO_TENANT)) or 0
            )
            for model in (RemediationTask, Risk, PolicyDocument, VendorAssessment, PostureMetricPoint)
        }


def _lake_digest(lake: Path) -> dict[str, str]:
    """Hash every lake file outside the app-state database directory."""
    return {
        str(path.relative_to(lake)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(lake.rglob("*"))
        if path.is_file() and path.relative_to(lake).parts[0] != "server"
    }


def test_golden_load_seeds_linked_synthetic_demo_records(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    assert main(["fixtures", "load", "--company", "golden", "--out", str(lake), "--rebase-times"]) == 0

    counts = _counts(lake)
    assert counts["remediation_tasks"] >= 3
    assert 3 <= counts["risks"] <= 5
    assert counts["policy_documents"] == 1
    assert counts["vendor_assessments"] == 2
    assert counts["posture_metric_points"] >= 3

    open_violations = {row["control_id"]: row["violation_id"] for row in build_current_posture(lake)["violations"]}
    factory = session_factory(create_engine_for(lake))
    with factory() as session:
        tasks = list(session.scalars(select(RemediationTask)))
        risks = list(session.scalars(select(Risk)))
        policies = list(session.scalars(select(PolicyDocument)))
        vendors = list(session.scalars(select(VendorAssessment)))
        points = list(session.scalars(select(PostureMetricPoint).order_by(PostureMetricPoint.captured_at)))

    for task in tasks:
        assert task.tenant_id == DEMO_TENANT
        assert task.created_by == DEMO_SEED_ACTOR
        assert SYNTHETIC_MARKER in task.description
        # Every task points at a finding the golden pipeline actually opened.
        assert task.control_id in open_violations
        assert task.violation_id == open_violations[task.control_id]
    assert any(task.is_overdue() for task in tasks)
    assert all(task.is_open for task in tasks)

    for risk in risks:
        assert SYNTHETIC_MARKER in risk.description
    assert {risk.control_id for risk in risks if risk.control_id} <= set(open_violations)

    assert policies[0].status == "published"
    assert policies[0].created_by == DEMO_SEED_ACTOR
    assert all(SYNTHETIC_MARKER.lower() in vendor.vendor_name.lower() for vendor in vendors)

    # Trend lines need distinct, chronologically spread points; the newest is the live capture.
    captured = [point.captured_at for point in points]
    assert len(set(captured)) == len(captured)
    current = build_current_posture(lake)["posture"]
    assert points[-1].posture_score == pytest.approx(float(current["score"]))
    assert points[-1].open_violations == int(current["open_violation_count"])
    assert points[-1].remediation_open == counts["remediation_tasks"]


def test_golden_seed_is_idempotent_across_reloads(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    assert main(["fixtures", "load", "--company", "golden", "--out", str(lake), "--rebase-times"]) == 0
    first = _counts(lake)

    assert main(["fixtures", "load", "--company", "golden", "--out", str(lake), "--rebase-times"]) == 0
    assert _counts(lake) == first

    result = seed_golden_demo(lake)
    assert result["created"] == {
        "remediation_tasks": 0,
        "risks": 0,
        "policy_documents": 0,
        "vendor_assessments": 0,
        "posture_metric_points": 0,
    }
    assert _counts(lake) == first


def test_seed_only_writes_app_state_and_leaves_pipeline_outputs_untouched(tmp_path: Path) -> None:
    fixture = find_fixture("golden")
    assert fixture is not None
    lake = tmp_path / "lake"
    run_pipeline(fixture.raw_path, lake, tenant_id="default")
    moment = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
    before = _lake_digest(lake)
    hash_before = build_current_posture(lake, now=moment)["assessment_hash"]

    seed_golden_demo(lake, now=moment)

    assert _lake_digest(lake) == before
    assert (lake / "server" / "app.db").is_file()
    assert build_current_posture(lake, now=moment)["assessment_hash"] == hash_before


@pytest.mark.parametrize("company", ["saas", "fintech"])
def test_non_golden_fixtures_seed_nothing(tmp_path: Path, company: str) -> None:
    lake = tmp_path / "lake"
    assert main(["fixtures", "load", "--company", company, "--out", str(lake)]) == 0
    assert not (lake / "server" / "app.db").exists()


def test_skip_flag_and_external_database_disable_seeding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lake = tmp_path / "skip"
    assert main(["fixtures", "load", "--company", "golden", "--out", str(lake), "--no-demo-records"]) == 0
    assert not (lake / "server" / "app.db").exists()

    # A configured external database is never a demo target: seeding refuses it.
    external = tmp_path / "external.db"
    monkeypatch.setenv(ENV_DATABASE_URL, f"sqlite:///{external}")
    lake = tmp_path / "external"
    assert main(["fixtures", "load", "--company", "golden", "--out", str(lake)]) == 0
    assert not external.exists()
    assert not (lake / "server" / "app.db").exists()
