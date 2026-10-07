"""Shared job feeds do not grant every reader a writer's result or cancellation."""

from fastapi.testclient import TestClient

from security_lakehouse import api_v1
from security_lakehouse.db.models import ApiKey
from security_lakehouse.db.repository import create_api_key, create_user
from test_operation_jobs import _authenticated


def test_read_only_peer_cannot_read_another_users_result_or_cancel(tmp_path):
    app, key_id, headers, _ = _authenticated(tmp_path)
    with app.state.sessionmaker.begin() as session:
        tenant = session.get(ApiKey, key_id).tenant_id
        reader = create_user(session, tenant_id=tenant, email="reader@example.test", role="read_only")
        _, token = create_api_key(session, tenant_id=tenant, user_id=reader.id)
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    row = app.state.operation_queue.claim()
    app.state.operation_queue.finish(row, 200, api_v1.envelope("fixture", {"receipt": "private-result"}))
    peer = {"Authorization": "Bearer " + token}
    result = client.get(job["status_url"], headers=peer)
    assert result.status_code == 200
    assert "private-result" not in result.text
    assert "private-result" in client.get(job["status_url"], headers=headers).text
    assert client.post(job["status_url"] + "/cancel", headers=peer).status_code == 403


def test_owner_can_cancel_queued_job_idempotently(tmp_path):
    app, _, headers, _ = _authenticated(tmp_path)
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    response = client.post(job["status_url"] + "/cancel", headers=headers)
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "cancelled"
    assert app.state.operation_queue.claim() is None
    assert client.post(job["status_url"] + "/cancel", headers=headers).status_code == 200


def test_cancellation_racing_completion_cannot_strand_running_state(tmp_path):
    app, _, headers, _ = _authenticated(tmp_path)
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    row = app.state.operation_queue.claim()
    assert client.post(job["status_url"] + "/cancel", headers=headers).json()["data"]["status"] == "cancelling"
    app.state.operation_queue.finish(row, 200, api_v1.envelope("fixture", {"done": True}))
    assert client.get(job["status_url"], headers=headers).json()["data"]["status"] == "interrupted"


def test_cancel_follows_a_claim_that_wins_before_its_update(tmp_path):
    from sqlalchemy import event

    app, _, headers, _ = _authenticated(tmp_path)
    queue = app.state.operation_queue
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    engine = queue.factory.kw["bind"]
    claimed = []

    def claim_before_update(conn, cursor, statement, parameters, context, executemany):
        if not claimed and statement.startswith("UPDATE operation_jobs"):
            claimed.append(None)
            claimed[0] = queue.claim()
            assert claimed[0].id == job["id"]

    event.listen(engine, "before_cursor_execute", claim_before_update)
    try:
        response = client.post(job["status_url"] + "/cancel", headers=headers)
    finally:
        event.remove(engine, "before_cursor_execute", claim_before_update)

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "cancelling"
    assert response.json()["data"]["finished_at"] is None
    queue.finish(claimed[0], 200, api_v1.envelope("fixture", {"done": True}))
    assert client.get(job["status_url"], headers=headers).json()["data"]["status"] == "interrupted"


def test_cancel_does_not_acknowledge_when_completion_wins_before_its_update(tmp_path):
    from sqlalchemy import event

    app, _, headers, _ = _authenticated(tmp_path)
    queue = app.state.operation_queue
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    engine = queue.factory.kw["bind"]
    raced = False

    def complete_before_update(conn, cursor, statement, parameters, context, executemany):
        nonlocal raced
        if not raced and statement.startswith("UPDATE operation_jobs"):
            raced = True
            row = queue.claim()
            assert row.id == job["id"]
            queue.finish(row, 200, api_v1.envelope("fixture", {"done": True}))

    event.listen(engine, "before_cursor_execute", complete_before_update)
    try:
        response = client.post(job["status_url"] + "/cancel", headers=headers)
    finally:
        event.remove(engine, "before_cursor_execute", complete_before_update)

    assert raced
    assert response.status_code == 409
    result = client.get(job["status_url"], headers=headers).json()["data"]
    assert result["status"] == "succeeded"
    assert result["response"]["data"] == {"done": True}
