"""Durable operations: acceptance, authority, recovery, and duplicate delivery."""

from fastapi.testclient import TestClient

from security_lakehouse import api_v1
from security_lakehouse.server_app import create_app


def test_revoked_browser_session_cannot_execute_queued_work(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
    from security_lakehouse.db.models import ApiKey, OperationJob
    from security_lakehouse.db.repository import create_user_session

    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "local-test-operation-signing")
    app, key_id, _, _ = _authenticated(tmp_path)
    with app.state.sessionmaker.begin() as session:
        key = session.get(ApiKey, key_id)
        login, token = create_user_session(session, tenant_id=key.tenant_id, user_id=key.user_id, idp="oidc")
        login_id = login.id
    client = TestClient(app)
    headers = {"Cookie": f"{SESSION_COOKIE}={encode_session_cookie(token)}", "Prefer": "respond-async"}
    response = client.post("/api/v1/ingestion/eval", json={}, headers=headers)
    assert response.status_code == 202
    job = response.json()["data"]
    with app.state.sessionmaker.begin() as session:
        from security_lakehouse.db.models import UserSession

        session.get(UserSession, login_id).revoked_at = datetime.now(UTC)
    calls = []
    monkeypatch.setattr(
        api_v1, "handle_post", lambda *args, **kwargs: (calls.append(1), (200, api_v1.envelope("eval", {})))[1]
    )
    app.state.operation_worker.run_once()
    assert calls == []
    with app.state.sessionmaker() as session:
        stored = session.get(OperationJob, job["id"])
        assert stored.status == "failed"
        assert stored.http_status == 403


def test_async_eval_is_persisted_before_execution(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_v1, "handle_post", lambda *a, **kw: (calls.append(a), (201, api_v1.envelope("ingestion.eval", {})))[1]
    )
    app = create_app(tmp_path, require_auth=False)
    client = TestClient(app)
    response = client.post(
        "/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async", "Idempotency-Key": "first"}
    )
    assert response.status_code == 202
    assert calls == []
    job = response.json()["data"]
    assert job["status"] == "queued"
    assert client.get(response.headers["Location"]).json()["data"]["id"] == job["id"]
    replay = client.post(
        "/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async", "Idempotency-Key": "first"}
    )
    assert replay.json()["data"]["id"] == job["id"]


def _authenticated(tmp_path):
    from security_lakehouse.db.repository import create_api_key, create_tenant, create_user

    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="a", name="A")
        user = create_user(session, tenant_id=tenant.id, email="a@example.test", role="security_admin")
        key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        other = create_tenant(session, slug="b", name="B")
        reader = create_user(session, tenant_id=other.id, email="b@example.test", role="read_only")
        _, other_token = create_api_key(session, tenant_id=other.id, user_id=reader.id)
        session.commit()
        key_id = key.id
    return (
        app,
        key_id,
        {"Authorization": "Bearer " + token, "Prefer": "respond-async"},
        {"Authorization": "Bearer " + other_token},
    )


def test_job_status_and_feed_are_tenant_scoped(tmp_path):
    app, _, headers, other = _authenticated(tmp_path)
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    assert client.get(job["status_url"], headers=other).status_code == 404
    assert client.get("/api/v1/operations", headers=other).json()["data"] == []
    assert client.get("/api/v1/platform/jobs", headers=headers).json()["data"]["running_count"] == 1
    assert (
        client.post("/api/v1/ingestion/eval", json={}, headers={**other, "Prefer": "respond-async"}).status_code == 403
    )
    assert (
        client.post("/api/v1/ingestion/eval", json={}, headers={**headers, "X-Trust-Role": "auditor"}).status_code
        == 403
    )


def test_idempotency_conflict_and_sensitive_input_rejected(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    client = TestClient(app)
    headers = {"Prefer": "respond-async", "Idempotency-Key": "same"}
    assert client.post("/api/v1/ingestion/eval", json={}, headers=headers).status_code == 202
    assert client.post("/api/v1/scheduler/tick", json={}, headers=headers).status_code == 409
    assert (
        client.post("/api/v1/ingestion/eval", json={"credentials": {"password": "secret"}}, headers=headers).status_code
        == 400
    )
    assert (
        client.post("/api/v1/connectors/aws-posture/sync", json={"materialize": "false"}, headers=headers).status_code
        == 400
    )


def test_queued_authority_is_rechecked_before_execution(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from security_lakehouse.db.models import ApiKey

    app, key_id, headers, _ = _authenticated(tmp_path)
    client = TestClient(app)
    job = client.post("/api/v1/ingestion/eval", json={}, headers=headers).json()["data"]
    with app.state.sessionmaker.begin() as session:
        session.get(ApiKey, key_id).revoked_at = datetime.now(UTC)
    monkeypatch.setattr(
        api_v1, "handle_post", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not execute"))
    )
    assert app.state.operation_worker.run_once()
    with app.state.sessionmaker() as session:
        from security_lakehouse.db.models import OperationJob

        row = session.get(OperationJob, job["id"])
        assert row.status == "failed"
        assert row.http_status == 403


def test_queue_survives_restart_and_claim_is_atomic(tmp_path, monkeypatch):
    import concurrent.futures
    import threading

    from security_lakehouse.operation_jobs import JobQueue

    app = create_app(tmp_path, require_auth=False)
    response = TestClient(app).post("/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async"})
    app2 = create_app(tmp_path, require_auth=False)
    assert TestClient(app2).get(response.headers["Location"]).json()["data"]["status"] == "queued"
    barrier = threading.Barrier(2)

    def claim():
        barrier.wait()
        return JobQueue(app2.state.sessionmaker, tmp_path).claim()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _: claim(), range(2)))
    assert sum(row is not None for row in claims) == 1


def test_expired_claim_is_interrupted_without_replay_and_fenced(tmp_path):
    import time

    from sqlalchemy import update

    from security_lakehouse.db.models import OperationJob
    from security_lakehouse.operation_jobs import LEASE_SECONDS

    app = create_app(tmp_path, require_auth=False)
    TestClient(app).post("/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async"})
    queue = app.state.operation_queue
    row = queue.claim()
    queue.recover()
    assert queue.get("insecure", row.id)["status"] == "running"
    with app.state.sessionmaker.begin() as session:
        session.execute(
            update(OperationJob).where(OperationJob.id == row.id).values(heartbeat_at=time.time() - LEASE_SECONDS - 1)
        )
    queue.recover()
    queue.finish(row, 201, api_v1.envelope("ingestion.eval", {}))
    assert queue.get("insecure", row.id)["status"] == "interrupted"
    assert queue.claim() is None


def test_worker_failure_does_not_expose_exception(tmp_path, monkeypatch, caplog):
    app = create_app(tmp_path, require_auth=False)
    client = TestClient(app)
    response = client.post("/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async"})
    monkeypatch.setattr(
        api_v1, "handle_post", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("private-path-detail"))
    )
    app.state.operation_worker.run_once()
    result = client.get(response.headers["Location"])
    assert result.json()["data"]["status"] == "failed"
    assert "private-path-detail" not in result.text
    assert "private-path-detail" in caplog.text


def test_lifespan_worker_completes_without_holding_request(tmp_path, monkeypatch):
    import threading
    import time

    gate = threading.Event()
    entered = threading.Event()

    def run(*args, **kwargs):
        entered.set()
        assert gate.wait(4)
        return 201, api_v1.envelope("ingestion.eval", {"result": "ok"})

    monkeypatch.setattr(api_v1, "handle_post", run)
    app = create_app(tmp_path, require_auth=False)
    # This unit test exercises mocked in-process dispatch; process isolation has real smoke coverage.
    app.state.operation_worker.subprocess_execute = None
    with TestClient(app) as client:
        response = client.post("/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async"})
        assert response.status_code == 202
        try:
            assert entered.wait(3)
            assert client.get(response.headers["Location"]).json()["data"]["status"] == "running"
        finally:
            gate.set()
        for _ in range(100):
            data = client.get(response.headers["Location"]).json()["data"]
            if data["status"] == "succeeded":
                break
            time.sleep(0.02)
        assert data["response"]["data"] == {"result": "ok"}


def test_reentered_lifespan_can_process_new_jobs(tmp_path, monkeypatch):
    import time

    monkeypatch.setattr(api_v1, "handle_post", lambda *a, **kw: (201, api_v1.envelope("ingestion.eval", {})))
    app = create_app(tmp_path, require_auth=False)
    # This unit test exercises mocked in-process dispatch; process isolation has real smoke coverage.
    app.state.operation_worker.subprocess_execute = None
    for _ in range(2):
        with TestClient(app) as client:
            response = client.post("/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async"})
            for _ in range(100):
                data = client.get(response.headers["Location"]).json()["data"]
                if data["status"] == "succeeded":
                    break
                time.sleep(0.02)
            assert data["status"] == "succeeded"


def test_async_acceptance_is_documented(tmp_path):
    spec = api_v1.merge_openapi(create_app(tmp_path, require_auth=False).openapi())
    post = spec["paths"]["/api/v1/ingestion/eval"]["post"]
    assert "202" in post["responses"]
    assert {p["name"] for p in post["parameters"]} >= {"Prefer", "Idempotency-Key"}


def test_retries_use_stable_principal_not_mutable_actor_label(tmp_path):
    from security_lakehouse.auth.dependencies import _INSECURE_IDENTITY

    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    first = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {"actor": "old@example.test"}, "stable")
    replay = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {"actor": "new@example.test"}, "stable")
    assert first["id"] == replay["id"]
