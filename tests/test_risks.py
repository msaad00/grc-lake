"""GRC risk register tests: data model + migration + API (RBAC, tenant isolation)."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient
from sqlalchemy import inspect

from security_lakehouse.db import migrate, risks
from security_lakehouse.db.base import create_engine_for, session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _provision(app, slug: str, role: str = "contributor") -> tuple[str, str]:
    """Create a tenant + user + API key; return (tenant_id, token)."""
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        return tenant.id, token


@pytest.fixture
def env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "contributor"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return app, client, tokens


# --- migration ---------------------------------------------------------------


def test_migration_creates_risks_table(tmp_path: Path) -> None:
    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    inspector = inspect(engine)
    assert "risks" in inspector.get_table_names()
    columns = {col["name"] for col in inspector.get_columns("risks")}
    assert {"id", "tenant_id", "title", "severity", "status", "control_id", "asset_id"} <= columns
    index_names = {ix["name"] for ix in inspector.get_indexes("risks")}
    assert "ix_risks_tenant_status" in index_names


# --- data-model + repository -------------------------------------------------


def test_risk_crud_round_trip(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        risk = risks.create_risk(
            session, tenant_id=tenant.id, title="Vendor data exfiltration", severity="high", owner="alice"
        )
        assert risk.status == "open"
        assert risks.get_risk(session, tenant_id=tenant.id, risk_id=risk.id) is not None
        assert len(risks.list_risks(session, tenant_id=tenant.id)) == 1
        updated = risks.update_risk(
            session, tenant_id=tenant.id, risk_id=risk.id, changes={"status": "mitigating", "owner": "bob"}
        )
        assert updated is not None
        assert updated.status == "mitigating"
        assert updated.owner == "bob"
        assert risks.delete_risk(session, tenant_id=tenant.id, risk_id=risk.id) is True
        assert risks.get_risk(session, tenant_id=tenant.id, risk_id=risk.id) is None


def test_invalid_level_and_status_rejected(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValueError, match="severity"):
            risks.create_risk(session, tenant_id=tenant.id, title="x", severity="catastrophic")
        with pytest.raises(ValueError, match="status"):
            risks.create_risk(session, tenant_id=tenant.id, title="x", status="bogus")
        risk = risks.create_risk(session, tenant_id=tenant.id, title="x")
        with pytest.raises(ValueError, match="status"):
            risks.update_risk(session, tenant_id=tenant.id, risk_id=risk.id, changes={"status": "nope"})


# --- API ---------------------------------------------------------------------


def test_risks_require_auth(env) -> None:
    _app, client, _tokens = env
    assert client.get("/api/v1/risks").status_code == HTTPStatus.UNAUTHORIZED


def test_risk_api_crud_and_rbac(env) -> None:
    _app, client, tokens = env
    # read_only can list but not create
    assert client.get("/api/v1/risks", headers=_bearer(tokens["read_only"])).status_code == HTTPStatus.OK
    denied = client.post("/api/v1/risks", json={"title": "x"}, headers=_bearer(tokens["read_only"]))
    assert denied.status_code == HTTPStatus.FORBIDDEN

    created = client.post(
        "/api/v1/risks",
        json={"title": "Key sprawl", "severity": "high", "control_id": "SOC2-CC6.1"},
        headers=_bearer(tokens["contributor"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    risk = created.json()["data"]
    assert risk["status"] == "open"
    assert risk["severity"] == "high"

    patched = client.patch(
        f"/api/v1/risks/{risk['id']}",
        json={"status": "accepted", "treatment": "risk accepted by CISO"},
        headers=_bearer(tokens["contributor"]),
    )
    assert patched.status_code == HTTPStatus.OK
    assert patched.json()["data"]["status"] == "accepted"

    deleted = client.delete(f"/api/v1/risks/{risk['id']}", headers=_bearer(tokens["contributor"]))
    assert deleted.status_code == HTTPStatus.OK
    assert client.get("/api/v1/risks", headers=_bearer(tokens["contributor"])).json()["data"] == []


def test_risk_bad_status_is_400(env) -> None:
    _app, client, tokens = env
    created = client.post("/api/v1/risks", json={"title": "x"}, headers=_bearer(tokens["contributor"]))
    risk_id = created.json()["data"]["id"]
    resp = client.patch(f"/api/v1/risks/{risk_id}", json={"status": "nope"}, headers=_bearer(tokens["contributor"]))
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_risk_unknown_field_rejected(env) -> None:
    _app, client, tokens = env
    resp = client.post(
        "/api/v1/risks",
        json={"title": "probe", "assignee": "bogus"},
        headers=_bearer(tokens["contributor"]),
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["data"] is None
    assert body["errors"][0]["code"] == "unprocessable_entity"
    assert "assignee" in body["errors"][0]["detail"]


# --- tenant isolation --------------------------------------------------------


def test_risk_tenant_isolation(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    _a_id, token_a = _provision(app, "acme")
    _b_id, token_b = _provision(app, "globex")

    created = client.post("/api/v1/risks", json={"title": "tenant-a only"}, headers=_bearer(token_a))
    assert created.status_code == HTTPStatus.CREATED
    risk_id = created.json()["data"]["id"]

    # Tenant B never sees tenant A's risk in the collection...
    b_list = client.get("/api/v1/risks", headers=_bearer(token_b)).json()["data"]
    assert b_list == []
    # ...and cannot fetch/patch/delete it by id.
    patch_response = client.patch(f"/api/v1/risks/{risk_id}", json={"status": "closed"}, headers=_bearer(token_b))
    delete_response = client.delete(f"/api/v1/risks/{risk_id}", headers=_bearer(token_b))
    assert patch_response.status_code == HTTPStatus.NOT_FOUND
    assert delete_response.status_code == HTTPStatus.NOT_FOUND

    # Tenant A still has it.
    a_list = client.get("/api/v1/risks", headers=_bearer(token_a)).json()["data"]
    assert [r["title"] for r in a_list] == ["tenant-a only"]
