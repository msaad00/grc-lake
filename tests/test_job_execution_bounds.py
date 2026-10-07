"""A timed-out process cannot continue its side effects after worker recovery."""

import time
from pathlib import Path

import pytest

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


def native_digest(root, row):
    import hashlib

    Path(root, "native-started").write_text(row.id)
    # This native loop does not return to Python to dispatch Python signal handlers.
    hashlib.pbkdf2_hmac("sha256", b"bounded-deadline-fixture", b"salt", 100_000_000)
    Path(root, "native-finished").write_text(row.id)
    return 200, {"data": {"done": True}}


def test_independent_child_deadline_terminates_native_work_without_parent_watchdog(tmp_path):
    import multiprocessing
    import signal

    from security_lakehouse.operation_jobs import _subprocess_entry

    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "native-timeout")
    row = queue.claim()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_subprocess_entry, args=(tmp_path, row, native_digest, sender, 2.0))
    process.start()
    sender.close()
    try:
        startup_deadline = time.monotonic() + 20
        while not (tmp_path / "native-started").exists() and process.is_alive() and time.monotonic() < startup_deadline:
            time.sleep(0.05)
        assert (tmp_path / "native-started").exists()
        # The observer never invokes the worker's parent watchdog or sends a signal.
        process.join(4)
        assert not process.is_alive()
        assert process.exitcode == -signal.SIGALRM
        assert not (tmp_path / "native-finished").exists()
    finally:
        if process.is_alive():
            process.kill()
        process.join(5)
        receiver.close()


def abrupt_exit(root, row):
    import json
    import os
    import signal

    Path(root, "exit-started").write_text(row.id)
    reason = json.loads(row.payload_json)["reason"]
    if reason == "status":
        os._exit(124)
    os.kill(os.getpid(), signal.SIGALRM if reason == "alarm" else signal.SIGTERM)


@pytest.mark.parametrize(
    "reason, expected", [("alarm", "execution_timeout"), ("term", "outcome_unknown"), ("status", "outcome_unknown")]
)
def test_worker_distinguishes_alarm_timeout_from_other_abrupt_exits(tmp_path, reason, expected):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/snapshots", {"reason": reason}, "exit-classification")
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=abrupt_exit, timeout_seconds=20)
    assert worker.run_once(isolated=True)
    assert (tmp_path / "exit-started").exists()
    result = queue.get("insecure", job["id"])
    assert result["status"] == "interrupted"
    assert result["response"]["errors"][0]["code"] == expected
