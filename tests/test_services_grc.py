"""Direct tests for the transport-agnostic GRC service layer.

These exercise ``services.grc`` against a migrated app-state DB without any
HTTP layer — proving the same logic that backs the FastAPI routes can be reused
by the MCP server, SDK, or CLI for DB-backed writes. The HTTP behavior itself is
covered (unchanged) by ``test_risks.py`` and ``test_remediation.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.server_app import create_app
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import grc as grc_services
from test_api_v1 import _seed_lake


def _app(tmp_path: Path):
    _seed_lake(tmp_path)
    return create_app(tmp_path)


# --- risks -------------------------------------------------------------------


def test_risk_service_round_trip(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")

        created = grc_services.create_risk(
            session, tenant.id, title="Vendor data exfiltration", severity="high", owner="alice"
        )
        assert created["status"] == "open"
        assert created["severity"] == "high"
        risk_id = created["id"]

        fetched = grc_services.get_risk(session, tenant.id, risk_id)
        assert fetched["id"] == risk_id

        listed = grc_services.list_risks(session, tenant.id)
        assert [r["id"] for r in listed] == [risk_id]

        updated = grc_services.update_risk(
            session, tenant.id, risk_id, changes={"status": "mitigating", "owner": "bob"}
        )
        assert updated["status"] == "mitigating"
        assert updated["owner"] == "bob"

        deleted = grc_services.delete_risk(session, tenant.id, risk_id)
        assert deleted == {"id": risk_id, "deleted": True}

        assert grc_services.list_risks(session, tenant.id) == []


def test_risk_service_filters(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        grc_services.create_risk(session, tenant.id, title="high one", severity="high", owner="alice")
        grc_services.create_risk(session, tenant.id, title="low one", severity="low", owner="bob")

        high = grc_services.list_risks(session, tenant.id, severity="high")
        assert [r["title"] for r in high] == ["high one"]
        by_owner = grc_services.list_risks(session, tenant.id, owner="bob")
        assert [r["title"] for r in by_owner] == ["low one"]


def test_risk_service_validation_errors(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValidationError, match="severity"):
            grc_services.create_risk(session, tenant.id, title="x", severity="catastrophic")
        with pytest.raises(ValidationError, match="status"):
            grc_services.create_risk(session, tenant.id, title="x", status="bogus")
        risk = grc_services.create_risk(session, tenant.id, title="ok")
        with pytest.raises(ValidationError, match="status"):
            grc_services.update_risk(session, tenant.id, risk["id"], changes={"status": "nope"})


def test_risk_service_not_found(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(NotFound):
            grc_services.get_risk(session, tenant.id, "missing")
        with pytest.raises(NotFound):
            grc_services.update_risk(session, tenant.id, "missing", changes={"status": "closed"})
        with pytest.raises(NotFound):
            grc_services.delete_risk(session, tenant.id, "missing")


def test_risk_service_tenant_isolation(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant_a = create_tenant(session, slug="acme", name="Acme")
        tenant_b = create_tenant(session, slug="globex", name="Globex")

        a_risk = grc_services.create_risk(session, tenant_a.id, title="tenant-a only")
        risk_id = a_risk["id"]

        # Tenant B never sees tenant A's risk in the collection...
        assert grc_services.list_risks(session, tenant_b.id) == []
        # ...and cannot fetch / update / delete it by id.
        with pytest.raises(NotFound):
            grc_services.get_risk(session, tenant_b.id, risk_id)
        with pytest.raises(NotFound):
            grc_services.update_risk(session, tenant_b.id, risk_id, changes={"status": "closed"})
        with pytest.raises(NotFound):
            grc_services.delete_risk(session, tenant_b.id, risk_id)

        # Tenant A still owns it.
        assert [r["title"] for r in grc_services.list_risks(session, tenant_a.id)] == ["tenant-a only"]


# --- remediation tasks -------------------------------------------------------


def test_task_service_round_trip(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")

        created = grc_services.create_task(session, tenant.id, title="Rotate keys", owner="alice", priority="high")
        assert created["status"] == "open"
        assert created["priority"] == "high"
        task_id = created["id"]

        listed = grc_services.list_tasks(session, tenant.id)
        assert [t["id"] for t in listed] == [task_id]

        updated = grc_services.update_task(session, tenant.id, task_id, changes={"status": "resolved"})
        assert updated["status"] == "resolved"
        assert updated["resolved_at"] is not None


def test_task_service_validation_and_not_found(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValidationError, match="title"):
            grc_services.create_task(session, tenant.id, title="   ")
        with pytest.raises(ValidationError, match="priority"):
            grc_services.create_task(session, tenant.id, title="ok", priority="urgent")
        with pytest.raises(NotFound):
            grc_services.update_task(session, tenant.id, "missing", changes={"status": "resolved"})


def test_task_service_tenant_isolation(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant_a = create_tenant(session, slug="acme", name="Acme")
        tenant_b = create_tenant(session, slug="globex", name="Globex")

        a_task = grc_services.create_task(session, tenant_a.id, title="tenant-a task")
        assert grc_services.list_tasks(session, tenant_b.id) == []
        with pytest.raises(NotFound):
            grc_services.update_task(session, tenant_b.id, a_task["id"], changes={"status": "resolved"})
