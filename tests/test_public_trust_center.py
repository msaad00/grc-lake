"""Public trust-center consumption view (BR-8).

The issuer side (``trust_share.create_share``) mints scoped, expiring,
revocable tokens. These tests prove the consumption side: an external reviewer
holding a token reaches a redacted, read-only posture at an UNAUTHENTICATED
route, while a miss/expired/revoked token returns a generic 404 with no detail
leak — and no owner/note/evidence internals ever cross the wire.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from security_lakehouse import tenancy, trust_share
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake

# Owner-grade fields that the auditor lens redacts and the public summary must
# never surface, recursively, anywhere in the payload.
_FORBIDDEN_KEYS = {"owner", "asset_owner", "actor", "assignee", "note", "credentials"}


def _issue(lake: Path) -> str:
    share = trust_share.create_share(lake, role="auditor", expires_in_hours=24)
    return share["token"]


def _walk_keys(payload: object) -> set[str]:
    found: set[str] = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            found.add(key)
            found |= _walk_keys(value)
    elif isinstance(payload, list):
        for item in payload:
            found |= _walk_keys(item)
    return found


def test_public_trust_resolves_tenant_scoped_share(tmp_path: Path) -> None:
    """Multi-tenant shares live under tenants/<id>; the public route must find them."""
    app = create_app(tmp_path, require_auth=True)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="u@acme.test", role="admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)

    tenant_lake = tmp_path / tenancy.TENANTS_DIRNAME / tenant.id
    tenant_lake.mkdir(parents=True)
    _seed_lake(tenant_lake)
    share = trust_share.create_share(tenant_lake, role="auditor", expires_in_hours=24)
    client = TestClient(app)

    assert client.get(f"/api/public/trust/{share['token']}").status_code == 200
    assert (
        client.get("/api/public/trust/trust_does_not_exist", headers={"Authorization": f"Bearer {token}"}).status_code
        == 404
    )


def test_public_trust_returns_redacted_posture(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    token = _issue(tmp_path)
    # Auth is ON: the public route must answer without any bearer token.
    client = TestClient(create_app(tmp_path, require_auth=True))

    res = client.get(f"/api/public/trust/{token}")
    assert res.status_code == 200, res.text
    body = res.json()

    # Residency promise is present and explicit.
    assert body["data_residency"] == "evidence never leaves this lake; only this summary is shared"
    assert body["schema_version"] == "trustops.public_trust.v1"
    assert body["sensitivity"] == "public"
    assert body["sensitivity_ceiling"] == "public"
    assert body["visibility"] == "external_reviewer"
    assert body["redaction_policy"] == "trustops.public_summary.v1"

    # Trimmed public posture: score/state + per-framework readiness.
    assert isinstance(body["posture"]["score"], (int, float))
    assert body["posture"]["state"]
    assert body["frameworks"], "seeded lake produces framework readiness rows"
    for row in body["frameworks"]:
        assert {"framework", "score", "state", "control_count"} <= set(row)

    # Issuing-org context (created_by) is carried for the reviewer.
    assert body["issued_by"] == "console"

    # No owner/evidence internals anywhere in the payload.
    leaked = _FORBIDDEN_KEYS & _walk_keys(body)
    assert not leaked, f"public summary leaked redacted fields: {leaked}"
    # Raw violations / asset internals are dropped entirely, not just redacted.
    assert "violations" not in body
    assert "top_risk_assets" not in body
    assert "evidence_freshness" not in body


def test_public_trust_requires_no_auth(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    token = _issue(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=True))

    # A protected route refuses without a bearer; the public route does not.
    assert client.get("/api/v1/posture/current").status_code in {401, 403}
    assert client.get(f"/api/public/trust/{token}").status_code == 200


def test_public_trust_unknown_token_is_404(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=True))
    res = client.get("/api/public/trust/trust_does_not_exist")
    assert res.status_code == 404
    # Generic: no detail about why (unknown vs revoked vs expired).
    assert "owner" not in res.text


def test_public_trust_revoked_token_is_404(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    share = trust_share.create_share(tmp_path, role="auditor", expires_in_hours=24)
    token = share["token"]
    client = TestClient(create_app(tmp_path, require_auth=True))
    assert client.get(f"/api/public/trust/{token}").status_code == 200

    trust_share.revoke_share(tmp_path, share["share_id"])
    assert client.get(f"/api/public/trust/{token}").status_code == 404


def test_public_trust_expired_token_is_404(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    share = trust_share.create_share(tmp_path, role="auditor", expires_in_hours=1)
    token = share["token"]

    # Rewrite the share record with an expiry in the past.
    path = tmp_path / "gold" / trust_share.SHARES_FILE
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows[-1]["expires_at"] = "2000-01-01T00:00:00Z"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    client = TestClient(create_app(tmp_path, require_auth=True))
    assert client.get(f"/api/public/trust/{token}").status_code == 404


def test_resolve_share_validates_hash_and_lifecycle(tmp_path: Path) -> None:
    share = trust_share.create_share(tmp_path, role="auditor", expires_in_hours=24)
    token = share["token"]

    resolved = trust_share.resolve_share(tmp_path, token)
    assert resolved is not None
    assert resolved["share_id"] == share["share_id"]

    assert trust_share.resolve_share(tmp_path, "wrong-token") is None
    assert trust_share.resolve_share(tmp_path, "") is None


def test_share_records_default_public_sensitivity_ceiling(tmp_path: Path) -> None:
    share = trust_share.create_share(tmp_path, role="auditor", expires_in_hours=24)
    assert share["sensitivity_ceiling"] == "public"


def test_share_rejects_unknown_sensitivity_ceiling(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="sensitivity_ceiling"):
        trust_share.create_share(
            tmp_path,
            role="auditor",
            expires_in_hours=24,
            sensitivity_ceiling="customer_secret",
        )


def test_create_share_idempotency_key_does_not_mint_duplicate(tmp_path: Path) -> None:
    first = trust_share.create_share(
        tmp_path,
        role="auditor",
        expires_in_hours=24,
        idempotency_key="review-123",
    )
    replay = trust_share.create_share(
        tmp_path,
        role="auditor",
        expires_in_hours=24,
        idempotency_key="review-123",
    )

    assert replay["share_id"] == first["share_id"]
    assert replay["idempotent_replay"] is True
    assert "token" not in replay
    assert len(trust_share.list_shares(tmp_path)) == 1


def test_trust_share_api_honors_idempotency_header(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    headers = {"Idempotency-Key": "customer-review-42"}

    first = client.post(
        "/api/trust-shares",
        headers=headers,
        json={"role": "auditor", "expires_in_hours": 24},
    )
    replay = client.post(
        "/api/trust-shares",
        headers=headers,
        json={"role": "auditor", "expires_in_hours": 24},
    )

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["share"]["share_id"] == first.json()["share"]["share_id"]
    assert replay.json()["share"]["idempotent_replay"] is True
    assert "token" not in replay.json()["share"]


_DETAIL_POSTURE_KEYS = {
    "open_violation_count",
    "critical_violation_count",
    "high_violation_count",
    "stale_control_count",
}
_DETAIL_FRAMEWORK_KEYS = {"failing_control_count", "stale_control_count"}


def test_public_summary_share_hides_violation_and_stale_counts(tmp_path: Path) -> None:
    """A customer-facing (public ceiling) share carries readiness, not defect counts."""
    _seed_lake(tmp_path)
    share = trust_share.create_share(tmp_path, role="auditor", expires_in_hours=24, sensitivity_ceiling="public")
    client = TestClient(create_app(tmp_path, require_auth=True))

    body = client.get(f"/api/public/trust/{share['token']}").json()

    assert body["detail_level"] == "summary"
    assert not _DETAIL_POSTURE_KEYS & set(body["posture"])
    assert body["posture"]["framework_count"] is not None
    assert body["frameworks"]
    for row in body["frameworks"]:
        assert not _DETAIL_FRAMEWORK_KEYS & set(row)
        assert "control_count" in row


def test_auditor_share_above_public_ceiling_includes_counts(tmp_path: Path) -> None:
    """An auditor share issued at an internal ceiling keeps the defect counts."""
    _seed_lake(tmp_path)
    share = trust_share.create_share(tmp_path, role="auditor", expires_in_hours=24, sensitivity_ceiling="internal")
    client = TestClient(create_app(tmp_path, require_auth=True))

    body = client.get(f"/api/public/trust/{share['token']}").json()

    assert body["detail_level"] == "detailed"
    assert body["sensitivity_ceiling"] == "internal"
    assert set(body["posture"]) >= _DETAIL_POSTURE_KEYS
    for row in body["frameworks"]:
        assert set(row) >= _DETAIL_FRAMEWORK_KEYS
    leaked = _FORBIDDEN_KEYS & _walk_keys(body)
    assert not leaked


@pytest.mark.parametrize("path", ["/console/trust/tok-abc", "/console/trust/tok-abc/"])
def test_public_trust_page_serves_with_and_without_trailing_slash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    from security_lakehouse import server_app

    lake = tmp_path / "lake"
    lake.mkdir()
    _seed_lake(lake)
    dist = tmp_path / "dist"
    (dist / "trust" / "share").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>root</title>", encoding="utf-8")
    (dist / "trust" / "share" / "index.html").write_text("<!doctype html><title>public-trust</title>", encoding="utf-8")
    monkeypatch.setattr(server_app, "web_dist_dir", lambda: dist)
    monkeypatch.setattr(server_app, "web_dist_index", lambda: dist / "index.html")

    resp = TestClient(create_app(lake)).get(path, follow_redirects=False)

    assert resp.status_code == 200
    assert "public-trust" in resp.text
