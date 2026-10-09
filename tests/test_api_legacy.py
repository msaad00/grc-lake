"""Legacy console surface: server mode must match local mode, and be auth-gated.

The console (Next.js) talks to the unversioned ``/api/*`` routes. These tests
prove the FastAPI server returns the same bodies as the stdlib server and that
the surface is authenticated + RBAC-enforced in server mode.
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse import api_legacy
from security_lakehouse.audit_log import build_audit_log
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _request, _seed_lake, _spin

# Legacy GETs whose bodies are pure functions of seeded files (no timestamps).
LEGACY_DETERMINISTIC = [
    "/api/controls",
    "/api/control-tests",
    "/api/evidence",
    "/api/assets",
    "/api/frameworks",
    "/api/connectors",
    "/api/readiness",
    "/api/crosswalk",
    "/api/crosswalk/reviewed",
    "/api/mappings/equivalence",
    "/api/mappings",
    "/api/workflows",
    "/api/workflows/actions",
    "/api/trust-shares",
]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _normalize_legacy_body(path: str, body: Any) -> Any:
    """Drop the only wall-clock-derived field so the parity check stays stable.

    ``/api/connectors`` carries a ``next_run_at`` freshness signal. For a
    never-synced connector that value anchors to "now", which legitimately
    differs by a few milliseconds between the two independently spun servers.
    Every other field (including ``freshness_state``) is file-derived, so we
    strip only ``next_run_at`` for never-synced rows and still assert the rest
    of the surface matches byte-for-byte.
    """
    if path == "/api/connectors" and isinstance(body, dict):
        for connector in body.get("connectors", []):
            if isinstance(connector, dict) and connector.get("freshness_state") == "never_synced":
                connector.pop("next_run_at", None)
    return body


def test_legacy_surface_matches_stdlib(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    stdlib = _spin(tmp_path)
    try:
        for path in LEGACY_DETERMINISTIC:
            stdlib_status, stdlib_body = _request(stdlib, "GET", path)
            resp = client.get(path)
            assert resp.status_code == stdlib_status, path
            assert _normalize_legacy_body(path, resp.json()) == _normalize_legacy_body(path, stdlib_body), path
    finally:
        stdlib.shutdown()


def test_legacy_requires_auth_in_server_mode(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))  # auth required
    assert client.get("/api/controls").status_code == HTTPStatus.UNAUTHORIZED
    entries = build_audit_log(tmp_path / "server/security_audit", category="request")
    assert entries[0]["payload"]["route"] == "/api/{rest:path}"
    assert entries[0]["result"] == "deny"


def test_legacy_bad_request_sanitizes_internal_exception_text(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    resp = client.post("/api/connectors/does-not-exist/configure", json={"state": "enabled"})
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json() == {"error": "bad_request", "reason": "invalid request"}


def test_legacy_post_hides_unexpected_exception_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))

    def boom(*_args: Any, **_kwargs: Any) -> tuple[HTTPStatus, dict[str, str]]:
        raise RuntimeError("stack trace: secret-token-123")

    monkeypatch.setattr(api_legacy, "handle_post", boom)

    resp = client.post("/api/snapshots", json={"reason": "audit"})
    assert resp.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert resp.json() == {"error": "internal_error", "reason": "internal server error"}
    assert "secret-token-123" not in resp.text


def test_legacy_post_enforces_route_specific_scopes(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "contributor", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token

    # read_only may read but not write
    assert client.get("/api/controls", headers=_bearer(tokens["read_only"])).status_code == HTTPStatus.OK
    assert (
        client.post(
            "/api/violations/v1/triage",
            json={"state": "triaged"},
            headers=_bearer(tokens["read_only"]),
        ).status_code
        == HTTPStatus.FORBIDDEN
    )

    # contributor can triage but cannot manage connector credentials or snapshots.
    assert (
        client.post(
            "/api/violations/v1/triage",
            json={"state": "triaged"},
            headers=_bearer(tokens["contributor"]),
        ).status_code
        == HTTPStatus.CREATED
    )
    assert (
        client.post(
            "/api/connectors/github-security/configure",
            json={"state": "enabled"},
            headers=_bearer(tokens["contributor"]),
        ).status_code
        == HTTPStatus.FORBIDDEN
    )
    assert (
        client.post("/api/snapshots", json={"reason": "audit"}, headers=_bearer(tokens["contributor"])).status_code
        == HTTPStatus.FORBIDDEN
    )

    # security_admin owns connector/workflow/snapshot operations.
    assert (
        client.post(
            "/api/connectors/github-security/probe",
            json={
                "credentials": {"token": "source_connector_secret"},
                "options": {"repo": "acme/model-service"},
            },
            headers=_bearer(tokens["security_admin"]),
        ).status_code
        == HTTPStatus.CREATED
    )
    assert (
        client.post(
            "/api/connectors/github-security/configure",
            json={
                "state": "enabled",
                "credentials": {"token": "source_connector_secret"},
                "options": {"repo": "acme/model-service"},
            },
            headers=_bearer(tokens["security_admin"]),
        ).status_code
        == HTTPStatus.CREATED
    )
    assert (
        client.post("/api/snapshots", json={"reason": "audit"}, headers=_bearer(tokens["security_admin"])).status_code
        == HTTPStatus.CREATED
    )
