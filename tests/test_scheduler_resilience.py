"""Failures before execution do not kill the daemon or disclose provider details."""

import pytest

from security_lakehouse import connector_state, scheduler
from security_lakehouse.validation import validate_raw_event


def test_daemon_continues_after_tick_error(tmp_path, monkeypatch, caplog):
    calls = []

    def tick(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("private-provider-value")

    monkeypatch.setattr(scheduler, "tick", tick)
    sleeps = []
    assert scheduler.run_forever(tmp_path, iterations=2, sleeper=sleeps.append) == 2
    assert len(calls) == len(sleeps) == 2
    assert "scheduler tick failed" in caplog.text
    assert "private-provider-value" not in caplog.text


def test_connector_append_is_durable(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(connector_state.os, "fsync", calls.append)
    connector_state._append_jsonl(tmp_path / "runs.jsonl", {"result": "started"})
    assert calls


@pytest.mark.parametrize(
    "timestamp",
    [
        "0001-01-01T00:00:00+23:59",
        "9999-12-31T23:59:59-23:59",
        "9999-12-31T23:59:59Z",
    ],
)
@pytest.mark.parametrize("field", ["event_time", "collected_at"])
def test_unrepresentable_timestamp_fails_validation(timestamp, field):
    row = {
        "event_id": "x",
        "tenant_id": "a",
        "event_time": "2026-01-01T00:00:00Z",
        "source": "test",
        "event_type": "cloud.config",
        "entity": {},
    }
    if field == "event_time":
        row[field] = timestamp
    else:
        row["evidence"] = {field: timestamp}
    assert validate_raw_event(row)


def test_explicit_tail_repair_preserves_original_and_defers_replay(tmp_path):
    from datetime import UTC, datetime, timedelta

    from security_lakehouse.io import read_jsonl
    from security_lakehouse.workflows import save_workflow

    save_workflow(
        tmp_path,
        workflow_id="wf",
        name="test",
        description="",
        nodes=[{"id": "cron", "node_type": "trigger.cron", "params": {"schedule": "@hourly"}}],
        edges=[],
    )
    state = tmp_path / "gold" / scheduler.STATE_FILE
    state.write_bytes(b'{"target_kind":"workflow","target_id":"wf","last_fired_at":"2026-01-01T00:00:00Z"}\n{"target')
    before = state.read_bytes()
    now = datetime(2026, 10, 6, tzinfo=UTC)
    result = scheduler.repair_history(tmp_path, now=now)
    assert result["repaired"] == [scheduler.STATE_FILE]
    assert any(path.read_bytes() == before for path in (tmp_path / "gold/recovery").iterdir())
    assert read_jsonl(state)[-1]["result"] == "recovery_deferred"
    assert (
        scheduler.tick(tmp_path, now=now + timedelta(minutes=30), runner=lambda *a, **k: pytest.fail("replayed")) == []
    )
    saved = state.read_bytes()
    assert scheduler.repair_history(tmp_path, now=now)["repaired"] == []
    assert state.read_bytes() == saved


def test_tail_repair_refuses_interior_or_terminated_corruption(tmp_path):
    state = tmp_path / "gold" / scheduler.STATE_FILE
    state.parent.mkdir()
    for data in (b"{bad}\n", b'{bad}\n{"tail'):
        state.write_bytes(data)
        with pytest.raises(ValueError):
            scheduler.repair_history(tmp_path)
        assert state.read_bytes() == data


def test_interrupted_repair_blocks_scheduling(tmp_path, monkeypatch):
    marker = tmp_path / "gold/scheduler_recovery_pending.json"
    marker.parent.mkdir()
    marker.write_text("{}")
    with pytest.raises(ValueError, match="recovery"):
        scheduler.tick(tmp_path)


def test_repair_waiting_for_scheduler_does_not_hold_connector_writer_lock(tmp_path, monkeypatch):
    import fcntl
    import os
    import threading
    from concurrent.futures import ThreadPoolExecutor

    gold = tmp_path / "gold"
    gold.mkdir()
    real_flock = fcntl.flock
    waiting = threading.Event()
    with (gold / scheduler.LOCK_FILE).open("a") as held:
        real_flock(held.fileno(), fcntl.LOCK_EX)

        def observe(fd, operation):
            if operation == fcntl.LOCK_EX and os.fstat(fd).st_ino == os.fstat(held.fileno()).st_ino:
                waiting.set()
            return real_flock(fd, operation)

        monkeypatch.setattr(fcntl, "flock", observe)
        with (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="repair") as repair_pool,
            ThreadPoolExecutor(max_workers=1) as writers,
        ):
            repair = repair_pool.submit(scheduler.repair_history, tmp_path)
            try:
                assert waiting.wait(2)
                write = writers.submit(connector_state._append_jsonl, gold / "connector_runs.jsonl", {"result": "ok"})
                write.result(timeout=2)
            finally:
                real_flock(held.fileno(), fcntl.LOCK_UN)
            repair.result(timeout=2)
