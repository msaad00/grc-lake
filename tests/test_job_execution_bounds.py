"""A timed-out process cannot continue its side effects after worker recovery."""

import time
from pathlib import Path

from security_lakehouse.auth.dependencies import _INSECURE_IDENTITY
from security_lakehouse.operation_jobs import JobWorker
from security_lakehouse.server_app import create_app


def delayed_write(root, row):
    Path(root, "started").write_text(row.id)
    time.sleep(30)
    Path(root, "finished").write_text(row.id)
    return 200, {"data": {"done": True}}


def test_worker_terminates_overdue_process_before_reporting_interruption(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "timeout")
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=delayed_write, timeout_seconds=5)
    assert worker.run_once(isolated=True)
    assert (tmp_path / "started").is_file()
    assert not (tmp_path / "finished").exists()
    result = queue.get("insecure", job["id"])
    assert result["status"] == "interrupted"
    assert result["response"]["errors"][0]["code"] == "execution_timeout"
    assert queue.claim() is None


def test_server_background_worker_uses_process_isolation(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    assert app.state.operation_worker.subprocess_execute is not None


def test_spawned_server_worker_creates_a_real_snapshot(tmp_path):
    from fastapi.testclient import TestClient

    from test_api_v1 import _seed_lake

    _seed_lake(tmp_path)
    app = create_app(tmp_path, require_auth=False)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/snapshots", json={}, headers={"Prefer": "respond-async", "Idempotency-Key": "spawn-snapshot"}
        )
        assert response.status_code == 202
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            job = client.get(response.headers["Location"]).json()["data"]
            if job["status"] not in {"queued", "running"}:
                break
            time.sleep(0.1)
        assert job["status"] == "succeeded", job
        assert client.get("/api/v1/snapshots/integrity").json()["data"]["ok"] is True


def test_recovery_does_not_interrupt_a_live_execution_lock(tmp_path):
    from sqlalchemy import update

    from security_lakehouse.db.models import OperationJob

    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "live")
    row = queue.claim()
    with queue.factory.begin() as session:
        session.execute(update(OperationJob).where(OperationJob.id == row.id).values(heartbeat_at=0))
    with queue.execution_lock(row):
        queue.recover()
        assert queue.get("insecure", job["id"])["status"] == "running"
    queue.recover()
    assert queue.get("insecure", job["id"])["status"] == "interrupted"


def test_running_cancellation_stops_process_before_reporting_interruption(tmp_path):
    import threading

    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "cancel-running")
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=delayed_write, timeout_seconds=15)
    thread = threading.Thread(target=lambda: worker.run_once(isolated=True))
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / "started").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert (tmp_path / "started").exists()
        assert queue.cancel(_INSECURE_IDENTITY, job["id"])["status"] == "cancelling"
    finally:
        thread.join(10)
        if thread.is_alive():
            worker.stop_event.set()
            thread.join(10)
    assert not thread.is_alive()
    assert queue.get("insecure", job["id"])["status"] == "interrupted"
    assert not (tmp_path / "finished").exists()
