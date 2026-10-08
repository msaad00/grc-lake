"""Lease renewal survives transient database lock errors without outliving the lease."""

import sqlite3
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError

from security_lakehouse import operation_jobs
from security_lakehouse.auth.dependencies import _INSECURE_IDENTITY
from security_lakehouse.db.models import OperationJob
from security_lakehouse.operation_jobs import JobWorker
from security_lakehouse.server_app import create_app


def short_job(root, row):
    time.sleep(2.5)
    Path(root, "finished").write_text(row.id)
    return 200, {"data": {"done": True}}


def long_job(root, row):
    Path(root, "started").write_text(row.id)
    time.sleep(30)
    Path(root, "finished").write_text(row.id)
    return 200, {"data": {"done": True}}


def _locked() -> OperationalError:
    return OperationalError("UPDATE operation_jobs", {}, sqlite3.OperationalError("database is locked"))


def _flaky_renew(queue, monkeypatch, failures: int | None, *, before_real=None):
    """Raise a lock error on the first ``failures`` renewals (all, when None)."""
    real = queue.renew
    calls = {"failed": 0, "renewed": [], "lost": 0}

    def renew(row):
        if failures is None or calls["failed"] < failures:
            calls["failed"] += 1
            raise _locked()
        if before_real is not None:
            before_real(row)
        if real(row):
            calls["renewed"].append(time.monotonic())
            return True
        calls["lost"] += 1
        return False

    monkeypatch.setattr(queue, "renew", renew)
    return calls


def _job_row(queue, job_id):
    with queue.factory() as session:
        return session.scalar(select(OperationJob).where(OperationJob.id == job_id))


def test_isolated_renewal_retries_lock_errors_and_the_job_completes(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "flaky-renew")
    calls = _flaky_renew(queue, monkeypatch, failures=3)
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=short_job, timeout_seconds=30)

    assert worker.run_once(isolated=True)

    assert calls["failed"] == 3
    assert calls["renewed"], "no renewal succeeded after the lock cleared"
    assert (tmp_path / "finished").is_file()
    assert queue.get("insecure", job["id"])["status"] == "succeeded"


def test_isolated_renewal_gives_up_before_the_lease_can_expire(tmp_path, monkeypatch):
    monkeypatch.setattr(operation_jobs, "LEASE_SECONDS", 3)
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "locked-renew")
    calls = _flaky_renew(queue, monkeypatch, failures=None)
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=long_job, timeout_seconds=60)

    started = time.monotonic()
    assert worker.run_once(isolated=True)
    elapsed = time.monotonic() - started

    assert calls["failed"] > 3, "renewal was not retried"
    assert elapsed < 3 + 5, elapsed
    assert (tmp_path / "started").is_file()
    assert not (tmp_path / "finished").exists()
    result = queue.get("insecure", job["id"])
    assert result["status"] == "interrupted"
    assert result["response"]["errors"][0]["code"] == "lease_renewal_failed"


def test_retry_never_extends_a_lease_taken_by_another_worker(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "stolen-lease")

    def steal(row):
        with queue.factory.begin() as session:
            session.execute(
                update(OperationJob).where(OperationJob.id == row.id).values(worker_token="other", heartbeat_at=1.0)
            )

    calls = _flaky_renew(queue, monkeypatch, failures=1, before_real=steal)
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=long_job, timeout_seconds=60)

    assert worker.run_once(isolated=True)

    assert calls["failed"] == 1 and calls["lost"] == 1 and not calls["renewed"]
    stolen = _job_row(queue, job["id"])
    assert stolen.worker_token == "other"
    assert stolen.heartbeat_at == 1.0
    assert stolen.status == "running"
    assert not (tmp_path / "finished").exists()


def test_in_process_heartbeat_retries_lock_errors_within_one_lease(tmp_path, monkeypatch):
    monkeypatch.setattr(operation_jobs, "LEASE_SECONDS", 3)
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "inline-flaky")
    calls = _flaky_renew(queue, monkeypatch, failures=3)
    release = threading.Event()

    def execute(row):
        release.wait(2.5)
        return 200, {"data": {"done": True}}

    worker = JobWorker(queue, execute)
    claimed_at = time.monotonic()

    assert worker.run_once(isolated=False)

    assert calls["failed"] == 3
    assert calls["renewed"], "no renewal succeeded before the job finished"
    assert calls["renewed"][0] - claimed_at < 3
    assert queue.get("insecure", job["id"])["status"] == "succeeded"


def _flaky_begin(queue, monkeypatch, failures: int | None):
    """Raise a lock error from the first ``failures`` write transactions (all, when None)."""
    real = queue.factory.begin
    calls = {"failed": 0}

    def begin(*args, **kwargs):
        if failures is None or calls["failed"] < failures:
            calls["failed"] += 1
            raise _locked()
        return real(*args, **kwargs)

    monkeypatch.setattr(queue.factory, "begin", begin)
    return calls


def test_finish_retries_lock_errors_and_records_the_result(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "flaky-finish")
    row = queue.claim()
    calls = _flaky_begin(queue, monkeypatch, failures=2)

    queue.finish(row, 200, {"data": {"done": True}, "meta": {}, "errors": []})

    assert calls["failed"] == 2
    result = queue.get("insecure", job["id"])
    assert result["status"] == "succeeded"
    assert result["response"]["data"] == {"done": True}


def test_finish_still_raises_after_the_retry_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(operation_jobs, "_WRITE_RETRY_SECONDS", 0.5)
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "locked-finish")
    row = queue.claim()
    calls = _flaky_begin(queue, monkeypatch, failures=None)

    started = time.monotonic()
    with pytest.raises(OperationalError):
        queue.finish(row, 200, {"data": {"done": True}, "meta": {}, "errors": []})

    assert calls["failed"] > 1
    assert time.monotonic() - started < 3
    assert queue.get("insecure", job["id"])["status"] == "running"


def test_finish_retry_never_overwrites_a_job_another_worker_holds(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "stolen-finish")
    row = queue.claim()
    real = queue.factory.begin
    calls = {"failed": 0}

    def begin(*args, **kwargs):
        if not calls["failed"]:
            calls["failed"] += 1
            with real() as session:
                session.execute(update(OperationJob).where(OperationJob.id == row.id).values(worker_token="other"))
            raise _locked()
        return real(*args, **kwargs)

    monkeypatch.setattr(queue.factory, "begin", begin)

    queue.finish(row, 200, {"data": {"done": True}, "meta": {}, "errors": []})

    stolen = _job_row(queue, job["id"])
    assert stolen.status == "running" and stolen.worker_token == "other"
    assert stolen.result_json is None


def test_interrupted_status_update_retries_lock_errors(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "flaky-interrupt")
    calls = _flaky_begin(queue, monkeypatch, failures=2)
    worker = JobWorker(queue, lambda row: (200, {}), subprocess_execute=long_job, timeout_seconds=0.5)

    assert worker.run_once(isolated=True)

    assert calls["failed"] == 2
    result = queue.get("insecure", job["id"])
    assert result["status"] == "interrupted"
    assert result["response"]["errors"][0]["code"] == "execution_timeout"
