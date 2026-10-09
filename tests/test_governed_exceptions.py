from datetime import UTC, datetime, timedelta

import pytest

from test_agent_decision_authority import human
from test_remediation import _bearer
from test_remediation import env as remediation_env

env = remediation_env


@pytest.fixture(autouse=True)
def signing_key(monkeypatch):
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "test-governed-exceptions-signing-key")


def request_body():
    return {
        "control_id": "SOC2-CC6.1",
        "reason": "Temporary migration; restricted network compensates",
        "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
    }


def test_exception_requires_independent_authenticated_approval(env):
    app, client, tokens = env
    owner = human(app, tokens["security_admin"])
    reviewer = human(app, tokens["admin"])
    created = client.post("/api/v1/remediation/exceptions", json=request_body(), headers=owner)
    assert created.status_code == 201
    row = created.json()["data"]
    assert row["status"] == "pending"
    assert row["active"] is False
    assert row["approved_by"] == ""
    url = f"/api/v1/remediation/exceptions/{row['id']}/approve"
    assert client.post(url, headers=owner).status_code == 400
    assert client.post(url, headers=_bearer(tokens["contributor"])).status_code == 403
    approved = client.post(url, headers=reviewer)
    assert approved.status_code == 200
    assert approved.json()["data"]["approved_by"] == "admin@acme.test"
    assert approved.json()["data"]["active"] is True
    assert client.post(url, headers=reviewer).status_code == 400
    revoked = client.delete(url.removesuffix("/approve"), headers=owner)
    assert revoked.status_code == 200
    assert client.post(url, headers=reviewer).status_code == 400


@pytest.mark.parametrize(
    "patch",
    [
        {"approved_by": "other@example.test"},
        {"expires_at": None},
        {"expires_at": "2000-01-01T00:00:00Z"},
        {"reason": ""},
    ],
)
def test_exception_cannot_spoof_approval_or_omit_required_limits(env, patch):
    _, client, tokens = env
    response = client.post(
        "/api/v1/remediation/exceptions", json={**request_body(), **patch}, headers=_bearer(tokens["security_admin"])
    )
    assert response.status_code in (400, 422)


def test_control_linked_task_cannot_be_resolved_by_status_patch(env):
    _, client, tokens = env
    headers = _bearer(tokens["contributor"])
    task = client.post(
        "/api/v1/remediation/tasks", json={"title": "Fix control", "control_id": "SOC2-CC6.1"}, headers=headers
    ).json()["data"]
    response = client.patch(
        f"/api/v1/remediation/tasks/{task['id']}",
        json={"status": "resolved", "resolution_note": "claim only"},
        headers=headers,
    )
    assert response.status_code == 400
    assert client.get(f"/api/v1/remediation/tasks/{task['id']}", headers=headers).json()["data"]["status"] == "open"


def test_expired_pending_request_and_other_tenant_cannot_be_approved(env):
    from security_lakehouse.db.base import session_scope
    from security_lakehouse.db.models import ControlException
    from security_lakehouse.db.repository import create_api_key, create_tenant, create_user

    app, client, tokens = env
    request = client.post(
        "/api/v1/remediation/exceptions", json=request_body(), headers=_bearer(tokens["security_admin"])
    ).json()["data"]
    with session_scope(app.state.sessionmaker) as session:
        other = create_tenant(session, slug="other", name="Other")
        user = create_user(session, tenant_id=other.id, email="other@example.test", role="admin")
        _, token = create_api_key(session, tenant_id=other.id, user_id=user.id)
    url = f"/api/v1/remediation/exceptions/{request['id']}/approve"
    assert client.post(url, headers=human(app, token)).status_code == 400
    with session_scope(app.state.sessionmaker) as session:
        session.get(ControlException, request["id"]).expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert client.post(url, headers=human(app, tokens["admin"])).status_code == 400


def test_pending_rows_do_not_consume_active_page(env):
    app, client, tokens = env
    owner = human(app, tokens["security_admin"])
    reviewer = human(app, tokens["admin"])
    first = client.post("/api/v1/remediation/exceptions", json=request_body(), headers=owner).json()["data"]
    assert client.post(f"/api/v1/remediation/exceptions/{first['id']}/approve", headers=reviewer).status_code == 200
    client.post("/api/v1/remediation/exceptions", json=request_body(), headers=owner)
    rows = client.get("/api/v1/remediation/exceptions?active=true&limit=1", headers=owner).json()["data"]
    assert [row["id"] for row in rows] == [first["id"]]


def test_upgrade_preserves_legacy_claim_without_trusting_it(tmp_path):
    from sqlalchemy import text

    from security_lakehouse.db import migrate
    from security_lakehouse.db.base import create_engine_for

    migrate.upgrade(tmp_path, revision="0020_saml_assertion_replays")
    engine = create_engine_for(tmp_path)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO tenants (id, slug, name) VALUES ('t', 'legacy', 'Legacy')"))
        connection.execute(
            text(
                "INSERT INTO control_exceptions (id, tenant_id, control_id, reason, approved_by, created_by, status) VALUES ('e', 't', 'C', 'legacy', 'claimed@example.test', 'requester', 'active')"
            )
        )
    migrate.upgrade(tmp_path)
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT status, approved_by, approved_by_id, requested_by_id FROM control_exceptions WHERE id='e'")
        ).one()
        assert tuple(row) == ("pending", "claimed@example.test", None, None)


@pytest.mark.parametrize("offset_hours", [5.5, -4])
def test_exception_expiry_preserves_the_instant_across_database_roundtrip(env, offset_hours):
    from datetime import timezone

    from security_lakehouse.db import remediation
    from security_lakehouse.db.base import session_scope

    app, client, tokens = env
    deadline = datetime.now(UTC) + timedelta(minutes=1)
    request = request_body()
    request["expires_at"] = deadline.astimezone(timezone(timedelta(hours=offset_hours))).isoformat()
    headers = _bearer(tokens["security_admin"])
    created = client.post("/api/v1/remediation/exceptions", json=request, headers=headers).json()["data"]
    listed = client.get("/api/v1/remediation/exceptions", headers=headers).json()["data"]
    row = next(item for item in listed if item["id"] == created["id"])
    stored = datetime.fromisoformat(row["expires_at"])
    assert stored.tzinfo is not None
    assert stored == deadline
    with session_scope(app.state.sessionmaker) as session:
        from security_lakehouse.db.models import ControlException

        exception = session.get(ControlException, created["id"])
        with pytest.raises(ValueError):
            remediation.approve_exception(
                session,
                tenant_id=exception.tenant_id,
                exception_id=exception.id,
                reviewer_id="independent-reviewer",
                reviewer="reviewer@example.test",
                now=deadline + timedelta(seconds=1),
            )
