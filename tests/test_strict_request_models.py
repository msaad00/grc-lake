"""Request bodies reject unknown fields with a v1-envelope 422."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _client_and_token(tmp_path: Path) -> tuple[TestClient, str]:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="c@acme.test", role="contributor")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    return TestClient(app), token


def test_unknown_field_is_rejected_with_v1_envelope(tmp_path: Path) -> None:
    client, token = _client_and_token(tmp_path)
    resp = client.post(
        "/api/v1/remediation/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "probe", "assignee": "bogus", "totally_fake_field": 123},
    )
    assert resp.status_code == 422
    body = resp.json()
    # Same v1 error envelope as the rest of the surface, naming the bad fields.
    assert body["data"] is None
    assert body["errors"] and body["errors"][0]["code"] == "unprocessable_entity"
    detail = body["errors"][0]["detail"]
    assert "assignee" in detail and "totally_fake_field" in detail


def test_valid_body_still_succeeds(tmp_path: Path) -> None:
    client, token = _client_and_token(tmp_path)
    resp = client.post(
        "/api/v1/remediation/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "real task", "owner": "alice", "priority": "high"},
    )
    assert resp.status_code == 201
    assert resp.json()["data"]["title"] == "real task"
