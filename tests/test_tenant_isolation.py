"""Server-mode tenant isolation: one tenant must never read another's lake."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse import tenancy
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _provision_tenant(app, slug: str) -> tuple[str, str]:
    """Create a tenant + read-only user + API key; return (tenant_id, token)."""
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"u@{slug}.test", role="read_only")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        return tenant.id, token


def test_tenant_cannot_read_another_tenants_lake(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    a_id, token_a = _provision_tenant(app, "acme")
    _b_id, token_b = _provision_tenant(app, "globex")

    # Only tenant A's scoped lake holds evidence; tenant B is unprovisioned.
    a_lake = tmp_path / tenancy.TENANTS_DIRNAME / a_id
    a_lake.mkdir(parents=True)
    _seed_lake(a_lake)

    client = TestClient(app)
    a_controls = client.get("/api/v1/controls", headers=_bearer(token_a)).json()["data"]
    b_controls = client.get("/api/v1/controls", headers=_bearer(token_b)).json()["data"]

    assert {row["control_id"] for row in a_controls} == {"SOC2-CC6.1", "NIST-AI-RMF-MAP-1.5"}
    assert b_controls == []  # B sees its own empty lake, never A's evidence


def test_single_tenant_serves_flat_root_lake(tmp_path: Path) -> None:
    # A flat lake at the root (CLI pipeline / fixtures layout) stays readable
    # for a single-tenant deployment.
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    # Tenant provisioned after the app boots still binds (resolution is per-request).
    _id, token = _provision_tenant(app, "solo")
    controls = TestClient(app).get("/api/v1/controls", headers=_bearer(token)).json()["data"]
    assert {row["control_id"] for row in controls} == {"SOC2-CC6.1", "NIST-AI-RMF-MAP-1.5"}


def test_insecure_mode_serves_flat_root_lake(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path, require_auth=False)
    controls = TestClient(app).get("/api/v1/controls").json()["data"]
    assert {row["control_id"] for row in controls} == {"SOC2-CC6.1", "NIST-AI-RMF-MAP-1.5"}
