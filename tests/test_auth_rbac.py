"""Authentication + RBAC tests for server mode."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.audit_log import build_audit_log  # noqa: E402
from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)  # auth required
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme Inc")
        for role in ("admin", "security_admin", "contributor", "auditor", "read_only"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id, name=f"{role}-key")
            tokens[role] = token
    return client, tokens


def test_healthz_is_open(env) -> None:
    client, _tokens = env
    assert client.get("/api/healthz").status_code == HTTPStatus.OK
    assert client.get("/api/v1/healthz").status_code == HTTPStatus.OK


def test_missing_token_is_unauthorized(env) -> None:
    client, _tokens = env
    resp = client.get("/api/v1/controls")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    body = resp.json()
    assert body["data"] is None
    assert body["errors"][0]["code"] == "unauthorized"


def test_invalid_token_is_unauthorized(env) -> None:
    client, _tokens = env
    resp = client.get("/api/v1/controls", headers=_bearer("tops_deadbeef"))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_read_only_can_read_but_not_snapshot(env) -> None:
    client, tokens = env
    assert client.get("/api/v1/controls", headers=_bearer(tokens["read_only"])).status_code == HTTPStatus.OK
    resp = client.post("/api/v1/snapshots", json={"reason": "x"}, headers=_bearer(tokens["read_only"]))
    assert resp.status_code == HTTPStatus.FORBIDDEN
    assert resp.json()["errors"][0]["code"] == "forbidden"


def test_contributor_cannot_snapshot(env) -> None:
    client, tokens = env
    resp = client.post("/api/v1/snapshots", json={"reason": "x"}, headers=_bearer(tokens["contributor"]))
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_security_admin_can_snapshot(env) -> None:
    client, tokens = env
    resp = client.post("/api/v1/snapshots", json={"reason": "audit"}, headers=_bearer(tokens["security_admin"]))
    assert resp.status_code == HTTPStatus.CREATED
    assert resp.json()["data"]["reason"] == "audit"


def test_whoami_reports_role_and_scopes(env) -> None:
    client, tokens = env
    body = client.get("/api/v1/auth/whoami", headers=_bearer(tokens["read_only"])).json()
    assert body["data"]["role"] == "read_only"
    assert body["data"]["scopes"] == ["read"]
    assert body["data"]["email"] == "read_only@acme.test"


def test_key_management_requires_admin(env) -> None:
    client, tokens = env
    assert client.get("/api/v1/auth/keys", headers=_bearer(tokens["read_only"])).status_code == HTTPStatus.FORBIDDEN
    listed = client.get("/api/v1/auth/keys", headers=_bearer(tokens["admin"]))
    assert listed.status_code == HTTPStatus.OK
    assert listed.json()["meta"]["count"] == 5


def test_admin_can_issue_and_revoke_keys(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["admin"])

    created = client.post(
        "/api/v1/auth/keys",
        json={"user_email": "read_only@acme.test", "name": "ci", "expires_in_days": 30},
        headers=admin,
    )
    assert created.status_code == HTTPStatus.CREATED
    created_data = created.json()["data"]
    new_token = created_data["token"]
    key_id = created_data["id"]
    assert created_data["role"] == "read_only"
    assert created_data["expires_at"]

    # the freshly minted key works as a read_only user
    assert client.get("/api/v1/controls", headers=_bearer(new_token)).status_code == HTTPStatus.OK
    whoami = client.get("/api/v1/auth/whoami", headers=_bearer(new_token))
    assert whoami.status_code == HTTPStatus.OK
    assert whoami.json()["data"]["email"] == "read_only@acme.test"

    # revoke it, and it stops working
    revoked = client.delete(f"/api/v1/auth/keys/{key_id}", headers=admin)
    assert revoked.status_code == HTTPStatus.OK
    assert client.get("/api/v1/controls", headers=_bearer(new_token)).status_code == HTTPStatus.UNAUTHORIZED
    assert client.get("/api/v1/auth/whoami", headers=_bearer(new_token)).status_code == HTTPStatus.UNAUTHORIZED


def test_issue_key_for_unknown_user_is_404(env) -> None:
    client, tokens = env
    resp = client.post("/api/v1/auth/keys", json={"user_email": "ghost@acme.test"}, headers=_bearer(tokens["admin"]))
    assert resp.status_code == HTTPStatus.NOT_FOUND
    assert "ghost@acme.test" not in json.dumps(resp.json())


def test_issue_key_rejects_invalid_expiry(env) -> None:
    client, tokens = env
    resp = client.post(
        "/api/v1/auth/keys",
        json={"user_email": "read_only@acme.test", "expires_in_days": 0},
        headers=_bearer(tokens["admin"]),
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_auditor_reads_redacted_owner_fields(env) -> None:
    client, tokens = env
    body = client.get("/api/v1/evidence", headers=_bearer(tokens["auditor"])).json()
    assert body["data"][0]["asset_owner"] == "[redacted]"


def test_auditor_audit_log_redacts_the_fields_policy_reserves(env) -> None:
    """The audit log replays other surfaces' payloads, so it must redact like them.

    ``actor`` is in ``AUDITOR_REDACTED_FIELDS`` alongside ``credentials``. This
    route returned entries verbatim, so an auditor read here what every other
    route withholds -- including connector ``credentials`` objects.
    """
    client, tokens = env
    client.get("/api/v1/controls", headers=_bearer(tokens["admin"]))

    auditor = client.get("/api/v1/audit-log?category=request", headers=_bearer(tokens["auditor"])).json()
    admin = client.get("/api/v1/audit-log?category=request", headers=_bearer(tokens["admin"])).json()

    assert auditor["data"], "expected audit entries to assert against"
    assert {entry["actor"] for entry in auditor["data"]} == {"[redacted]"}
    # The same route must still answer fully for an operator.
    assert any(entry["actor"] != "[redacted]" for entry in admin["data"])


def test_request_audit_records_decisions(tmp_path: Path, env) -> None:
    client, tokens = env  # the env fixture seeds the lake at tmp_path
    client.get("/api/v1/controls")  # denied (no token)
    client.get("/api/v1/controls", headers=_bearer(tokens["admin"]))  # allowed
    entries = build_audit_log(tmp_path, category="request")
    decisions = {entry["result"] for entry in entries}
    assert {"allow", "deny"} <= decisions


def test_request_audit_is_explicit_not_default_activity(tmp_path: Path, env) -> None:
    client, tokens = env
    client.get("/api/v1/controls", headers=_bearer(tokens["admin"]))

    assert all(entry["category"] != "request" for entry in build_audit_log(tmp_path))
    assert build_audit_log(tmp_path, category="request")


def _request_rows(lake: Path) -> list[dict]:
    path = lake / "gold" / "request_audit.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_anonymous_request_floods_do_not_grow_the_audit_log_unbounded(tmp_path: Path, env) -> None:
    client, _tokens = env
    for _ in range(40):
        client.get("/api/v1/controls")
        client.get("/api/v1/platform/pricing")
        client.post("/api/v1/snapshots", json={})
    anonymous = [row for row in _request_rows(tmp_path) if row["actor"] == "anonymous"]
    # Still visible: the first denial and the first anonymous read from this client.
    assert {row["decision"] for row in anonymous} == {"allow", "deny"}
    assert len(anonymous) <= 4


def test_authenticated_requests_are_always_audited(tmp_path: Path, env) -> None:
    client, tokens = env
    for _ in range(5):
        client.get("/api/v1/controls", headers=_bearer(tokens["admin"]))
    authenticated = [row for row in _request_rows(tmp_path) if row["actor"] != "anonymous"]
    assert len(authenticated) == 5


def test_anonymous_request_sampler_windows_per_client() -> None:
    from security_lakehouse.auth.request_audit import AnonymousAuditSampler

    sampler = AnonymousAuditSampler(window_seconds=60, max_keys=2)
    assert sampler.should_record("h1|deny", now=0.0) is True
    assert sampler.should_record("h1|deny", now=30.0) is False
    assert sampler.should_record("h2|deny", now=31.0) is True
    assert sampler.should_record("h1|deny", now=61.0) is True
    assert sampler.should_record("h3|deny", now=62.0) is True
    assert len(sampler) <= 2
