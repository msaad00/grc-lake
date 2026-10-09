"""Server mode attributes writes to the authenticated principal, never to a
client-supplied ``actor`` field."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app
from test_headless import _token_for_role


def test_triage_actor_is_the_session_identity_not_the_body(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token_for_role(app, tmp_path, 'security_admin')}"}

    violations = client.get("/api/v1/violations?limit=1", headers=headers).json()["data"]
    assert violations, "seeded lake should have a finding"
    violation_id = violations[0]["violation_id"]

    response = client.post(
        f"/api/v1/violations/{violation_id}/triage",
        json={"state": "triaged", "actor": "someone-else@spoofed.test"},
        headers=headers,
    )
    assert response.status_code == HTTPStatus.CREATED
    assert response.json()["data"]["actor"] == "security_admin@acme.test"

    history = client.get(f"/api/v1/violations/{violation_id}/tracking", headers=headers).json()["data"]
    actors = {event["actor"] for event in history["events"]}
    assert "someone-else@spoofed.test" not in actors
    assert "security_admin@acme.test" in actors
