"""A tenant backlog cannot monopolize the durable worker."""

from contextlib import suppress
from dataclasses import replace

from security_lakehouse.auth.dependencies import _INSECURE_IDENTITY
from security_lakehouse.server_app import create_app


def test_claims_rotate_between_tenants_before_draining_a_backlog(tmp_path):
    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    a = replace(_INSECURE_IDENTITY, tenant_id="a", user_id="a")
    b = replace(_INSECURE_IDENTITY, tenant_id="b", user_id="b")
    a_jobs = [queue.enqueue(a, "/api/v1/ingestion/eval", {}, f"a-{i}") for i in range(3)]
    b_job = queue.enqueue(b, "/api/v1/ingestion/eval", {}, "b-0")
    first = queue.claim()
    assert first.id == a_jobs[0]["id"]
    queue.finish(first, 200, {"data": {}})
    second = queue.claim()
    assert second.id == b_job["id"]
    queue.finish(second, 200, {"data": {}})
    assert queue.claim().id == a_jobs[1]["id"]


def test_concurrent_admission_never_exceeds_tenant_pending_limit(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from security_lakehouse.operation_jobs import JobConflict

    app = create_app(tmp_path, require_auth=False)
    queue = app.state.operation_queue
    for i in range(98):
        queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, str(i))
    # Force concurrent callers to observe the same pre-admission count.
    import threading

    from sqlalchemy import event

    barrier = threading.Barrier(8)
    engine = queue.factory.kw["bind"]

    def after_count(conn, cursor, statement, parameters, context, executemany):
        if "count(" in statement.lower() and "operation_jobs" in statement.lower():
            with suppress(threading.BrokenBarrierError):
                barrier.wait(timeout=1)

    event.listen(engine, "after_cursor_execute", after_count)

    def submit(i):
        try:
            queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, f"concurrent-{i}")
            return True
        except JobConflict:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = sum(pool.map(submit, range(8)))
    assert accepted == 2
    assert len(queue.list("insecure", 500)) == 100
