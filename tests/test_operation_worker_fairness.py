"""Bounded worker concurrency, per-tenant fairness, atomic claims, and shutdown."""

from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import replace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from security_lakehouse.auth.dependencies import _INSECURE_IDENTITY
from security_lakehouse.operation_jobs import JobWorker
from security_lakehouse.server_app import create_app


def _tenant(name: str):
    return replace(_INSECURE_IDENTITY, tenant_id=name, user_id=f"user-{name}")


def _wait(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_other_tenant_runs_while_one_tenant_has_a_long_job(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    long_job = queue.enqueue(_tenant("tenant-a"), "/api/v1/ingestion/eval", {}, "a-long")
    second_a = queue.enqueue(_tenant("tenant-a"), "/api/v1/scheduler/tick", {}, "a-second")
    b_job = queue.enqueue(_tenant("tenant-b"), "/api/v1/ingestion/eval", {}, "b-short")
    release = threading.Event()
    started: list[str] = []

    def execute(row):
        started.append(row.id)
        if row.id == long_job["id"]:
            assert release.wait(20)
        return 200, {"data": {"ok": True}, "meta": {}, "errors": []}

    worker = JobWorker(queue, execute, concurrency=2)
    worker.start()
    try:
        assert _wait(lambda: queue.get("tenant-b", b_job["id"])["status"] == "succeeded")
        assert queue.get("tenant-a", long_job["id"])["status"] == "running"
        # One in-flight job per tenant per replica: tenant A's backlog cannot
        # take the slot that keeps other tenants moving.
        time.sleep(1.5)
        assert second_a["id"] not in started
        assert queue.get("tenant-a", second_a["id"])["status"] == "queued"
    finally:
        release.set()
    try:
        assert _wait(lambda: queue.get("tenant-a", second_a["id"])["status"] == "succeeded")
    finally:
        worker.stop()
    assert started[0] in {long_job["id"], b_job["id"]}
    assert started.index(long_job["id"]) < started.index(second_a["id"])


def test_single_worker_preserves_serial_execution(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    jobs = [queue.enqueue(_tenant(f"t{i}"), "/api/v1/ingestion/eval", {}, f"k{i}") for i in range(3)]
    active = 0
    peak = 0
    lock = threading.Lock()

    def execute(row):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return 200, {"data": {}, "meta": {}, "errors": []}

    worker = JobWorker(queue, execute, concurrency=1)
    worker.start()
    try:
        assert _wait(lambda: all(queue.get(f"t{i}", j["id"])["status"] == "succeeded" for i, j in enumerate(jobs)))
    finally:
        worker.stop()
    assert peak == 1


@pytest.mark.parametrize("value", [0, -1, 17, 1.5, True])
def test_worker_concurrency_is_bounded(tmp_path, value):
    app = create_app(tmp_path, require_auth=False)
    with pytest.raises(ValueError):
        JobWorker(app.state.operation_queue, lambda row: (200, {}), concurrency=value)


def test_server_reads_worker_count_from_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("GRC_LAKE_OPERATION_WORKERS", raising=False)
    assert create_app(tmp_path, require_auth=False).state.operation_worker.concurrency == 2
    monkeypatch.setenv("GRC_LAKE_OPERATION_WORKERS", "4")
    assert create_app(tmp_path, require_auth=False).state.operation_worker.concurrency == 4
    monkeypatch.setenv("GRC_LAKE_OPERATION_WORKERS", "lots")
    with pytest.raises(ValueError, match="GRC_LAKE_OPERATION_WORKERS"):
        create_app(tmp_path, require_auth=False)


def test_lifespan_starts_configured_workers_and_joins_them_on_shutdown(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("GRC_LAKE_OPERATION_WORKERS", "3")
    app = create_app(tmp_path, require_auth=False)
    with TestClient(app):
        worker = app.state.operation_worker
        assert worker.concurrency == 3
        assert len(worker.threads) == 3
        assert all(thread.is_alive() for thread in worker.threads)
    assert not any(thread.is_alive() for thread in worker.threads)


def test_stop_waits_for_in_flight_work_and_joins_every_thread(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    job = queue.enqueue(_tenant("tenant-a"), "/api/v1/ingestion/eval", {}, "drain")
    entered = threading.Event()

    def execute(row):
        entered.set()
        time.sleep(0.5)
        return 200, {"data": {}, "meta": {}, "errors": []}

    worker = JobWorker(queue, execute, concurrency=2)
    worker.start()
    assert entered.wait(10)
    worker.stop()
    assert not any(thread.is_alive() for thread in worker.threads)
    assert queue.get("tenant-a", job["id"])["status"] == "succeeded"


@pytest.fixture(params=["sqlite", "postgresql"])
def database(request, tmp_path, monkeypatch):
    if request.param == "sqlite":
        monkeypatch.delenv("GRC_LAKE_DATABASE_URL", raising=False)
        yield
        return
    configured = os.environ.get("TEST_POSTGRES_URL")
    if not configured:
        pytest.skip("TEST_POSTGRES_URL is required for the PostgreSQL claim gate")
    name = "trustops_test_" + uuid.uuid4().hex
    admin = create_engine(configured, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    monkeypatch.setenv(
        "GRC_LAKE_DATABASE_URL", make_url(configured).set(database=name).render_as_string(hide_password=False)
    )
    try:
        yield
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def test_concurrent_workers_across_replicas_never_claim_the_same_job(tmp_path, database):
    replicas = [create_app(tmp_path, require_auth=False) for _ in range(2)]
    queue = replicas[0].state.operation_queue
    expected = {
        queue.enqueue(_tenant(f"tenant-{i % 5}"), "/api/v1/ingestion/eval", {}, f"job-{i}")["id"] for i in range(30)
    }
    lock = threading.Lock()
    executed: list[str] = []

    def execute(row):
        with lock:
            executed.append(row.id)
        time.sleep(0.01)
        return 200, {"data": {}, "meta": {}, "errors": []}

    workers = [JobWorker(app.state.operation_queue, execute, concurrency=3) for app in replicas]
    for worker in workers:
        worker.start()
    try:
        assert _wait(lambda: len(executed) >= len(expected), timeout=60)
        time.sleep(0.3)
    finally:
        for worker in workers:
            worker.stop()
    assert sorted(executed) == sorted(expected)
    assert len(set(executed)) == len(executed)
    for app in replicas:
        app.state.sessionmaker.kw["bind"].dispose()


def test_simultaneous_claims_for_one_job_have_exactly_one_winner(tmp_path, database):
    import concurrent.futures

    from sqlalchemy import event

    from security_lakehouse.operation_jobs import JobQueue

    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    queue.enqueue(_tenant("tenant-a"), "/api/v1/ingestion/eval", {}, "only")
    contenders = 8
    # Every contender selects the same queued row before any claim UPDATE runs,
    # so only the database's conditional update can pick the winner.
    selected = threading.Barrier(contenders, timeout=30)
    engine = app.state.sessionmaker.kw["bind"]

    def hold_claim_update(conn, cursor, statement, parameters, context, executemany):
        compact = " ".join(statement.split()).lower()
        if compact.startswith("update operation_jobs set status") and "started_at" in compact:
            selected.wait()

    event.listen(engine, "before_cursor_execute", hold_claim_update)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=contenders) as pool:
            claims = list(pool.map(lambda _: JobQueue(app.state.sessionmaker, tmp_path).claim(), range(contenders)))
    finally:
        event.remove(engine, "before_cursor_execute", hold_claim_update)
    winners = [row for row in claims if row is not None]
    assert len(winners) == 1
    assert queue.get("tenant-a", winners[0].id)["status"] == "running"
    engine.dispose()
