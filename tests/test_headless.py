"""Headless surface tests: self-describing v1 index + OpenAPI contract."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse import api_v1
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _token_for_role(app, tmp_path: Path, role: str) -> str:
    _seed_lake(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=f"tenant-{role}", name=f"Tenant {role}")
        user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    return token


def test_resource_catalog_lists_core_resources() -> None:
    catalog = api_v1.resource_catalog()
    paths = {row["path"] for row in catalog}
    assert {
        "/api/v1/posture/current",
        "/api/v1/controls",
        "/api/v1/evidence/freshness",
        "/api/v1/snapshots",
        "/api/v1/frameworks/{framework_id}/detail",
    } <= paths
    snapshots = next(row for row in catalog if row["path"] == "/api/v1/snapshots")
    assert "POST" in snapshots["methods"]
    detail = next(row for row in catalog if row["resource"] == "framework.detail")
    assert detail["path_params"] == ["framework_id"]


def test_v1_index_requires_auth(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    assert client.get("/api/v1").status_code == HTTPStatus.UNAUTHORIZED


def test_v1_index_describes_contract(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="a@acme.test", role="read_only")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    body = client.get("/api/v1", headers={"Authorization": f"Bearer {token}"}).json()
    data = body["data"]
    assert data["api_version"] == "v1"
    assert any(row["resource"] == "posture.current" for row in data["resources"])
    assert data["openapi"] == "/openapi.json"
    assert data["streams"] == ["/api/v1/stream"]


def test_v1_connector_actions_require_connector_manage_scope(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    client = TestClient(app)
    read_token = _token_for_role(app, tmp_path, "read_only")
    admin_token = _token_for_role(app, tmp_path, "security_admin")

    denied = client.post(
        "/api/v1/connectors/aws-posture/discover",
        json={"credentials": {"account_id": "123456789012"}, "options": {"region": "us-west-2"}},
        headers=_bearer(read_token),
    )
    assert denied.status_code == HTTPStatus.FORBIDDEN
    assert denied.json()["errors"][0] == {
        "code": "forbidden",
        "detail": "requires scope: connector_manage",
    }

    allowed = client.post(
        "/api/v1/connectors/aws-posture/discover",
        json={"credentials": {"account_id": "123456789012"}, "options": {"region": "us-west-2"}},
        headers=_bearer(admin_token),
    )
    assert allowed.status_code == HTTPStatus.CREATED
    assert allowed.json()["meta"]["resource"] == "connector.discover"

    contributor_token = _token_for_role(app, tmp_path, "contributor")
    sync_denied = client.post(
        "/api/v1/connectors/aws-posture/sync",
        headers=_bearer(contributor_token),
    )
    assert sync_denied.status_code == HTTPStatus.FORBIDDEN
    assert sync_denied.json()["errors"][0]["detail"] == "requires scope: connector_manage"


def test_v1_headless_github_security_probe_enable_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Headless path: probe before enable, same contract as console (#475)."""
    # Hosted server mode resolves only allowlisted or tenant-prefixed refs.
    monkeypatch.setenv("TRUSTOPS_CONNECTOR_SECRET_REFS", "ACME_GITHUB_APP_TOKEN")
    app = create_app(tmp_path)
    client = TestClient(app)
    admin_token = _token_for_role(app, tmp_path, "security_admin")
    headers = _bearer(admin_token)
    payload = {
        "actor": "headless-test",
        "credentials": {"credential_ref": "ACME_GITHUB_APP_TOKEN"},
        "options": {"repo": "acme/platform"},
    }

    blocked = client.post(
        "/api/v1/connectors/github-security/configure",
        json={"state": "enabled", **payload},
        headers=headers,
    )
    assert blocked.status_code == HTTPStatus.BAD_REQUEST
    assert "Test connection" in blocked.json()["errors"][0]["detail"]

    probe = client.post(
        "/api/v1/connectors/github-security/probe",
        json=payload,
        headers=headers,
    )
    assert probe.status_code == HTTPStatus.CREATED
    assert probe.json()["data"]["result"] == "ok"

    enabled = client.post(
        "/api/v1/connectors/github-security/configure",
        json={"state": "enabled", **payload},
        headers=headers,
    )
    assert enabled.status_code == HTTPStatus.CREATED
    assert enabled.json()["data"]["state"] == "enabled"


def test_openapi_schema_documents_surface(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    spec = create_app(tmp_path, require_auth=False).openapi()
    assert spec["info"]["title"] == "TrustOps API"
    paths = spec["paths"]
    for documented in (
        "/api/v1",
        "/api/v1/auth/methods",
        "/api/v1/frameworks/{framework_id}/detail",
        "/api/v1/remediation/tasks",
    ):
        assert documented in paths, documented
