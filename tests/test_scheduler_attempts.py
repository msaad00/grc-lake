"""Failed and interrupted attempts retain their schedule interval."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_lakehouse import scheduler
from security_lakehouse.io import read_jsonl


@pytest.mark.parametrize("kind", ["workflow", "connector", "lake_eval"])
@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_failed_attempt_is_durable_and_bounded(tmp_path, monkeypatch, kind, failure):
    period = timedelta(hours=23)
    monkeypatch.setattr(scheduler, "list_workflows", lambda lake: [])
    monkeypatch.setattr(
        scheduler,
        "_scheduled_from_workflows",
        lambda rows: [SimpleNamespace(workflow_id="target", period=period, schedule="every 23h")]
        if kind == "workflow"
        else [],
    )
    monkeypatch.setattr(
        scheduler,
        "_scheduled_from_connectors",
        lambda lake: [
            SimpleNamespace(
                connector_id="target",
                period=period,
                schedule="every 23h",
                repo=None,
                fixture_dir=None,
                token_env="TEST",
                materialize=False,
            )
        ]
        if kind == "connector"
        else [],
    )
    monkeypatch.setattr(
        scheduler,
        "_scheduled_lake_eval",
        lambda lake: SimpleNamespace(period=period, schedule="every 23h") if kind == "lake_eval" else None,
    )
    calls = []

    def fail(lake, **kwargs):
        calls.append(lake)
        raise failure("private provider error")

    monkeypatch.setattr(scheduler, "run_lake_eval", fail)
    base = datetime(2026, 10, 5, tzinfo=UTC)

    def fire(now):
        return scheduler.tick(tmp_path, now=now, runner=fail, connector_runner=fail)

    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            fire(base)
    else:
        assert fire(base)[0]["result"] == "error"
    assert fire(base + timedelta(minutes=15)) == []
    assert len(calls) == 1
    rows = read_jsonl(tmp_path / "gold" / scheduler.STATE_FILE)
    assert rows[0]["result"] == "started"
    assert rows[-1]["result"] == ("started" if failure is KeyboardInterrupt else "error")
    assert "private provider error" not in (tmp_path / "gold" / scheduler.STATE_FILE).read_text()
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            fire(base + period)
    else:
        fire(base + period)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "payload",
    [
        "{bad json",
        "{}",
        "null",
        '{"target_id":"x","last_fired_at":"not-a-date"}',
        '{"target_id":"x","last_fired_at":"2026-01-01","target_id":"y"}',
    ],
)
def test_corrupt_state_fails_closed_without_rewrite(tmp_path: Path, payload):
    state = tmp_path / "gold" / scheduler.STATE_FILE
    state.parent.mkdir()
    state.write_text(payload + "\n")
    before = state.read_bytes()
    with pytest.raises(ValueError, match="invalid scheduler state"):
        scheduler.tick(tmp_path)
    assert state.read_bytes() == before


def test_process_exit_preserves_attempt_before_side_effects(tmp_path):
    import subprocess
    import sys

    from security_lakehouse.workflows import save_workflow

    save_workflow(
        tmp_path,
        workflow_id=None,
        name="crash",
        description="",
        nodes=[{"id": "cron", "node_type": "trigger.cron", "params": {"schedule": "every 23h"}}],
        edges=[],
    )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
from datetime import UTC, datetime
from security_lakehouse.scheduler import tick
def exit_process(*args, **kwargs):
    os._exit(31)
tick(sys.argv[1], now=datetime(2026, 10, 5, tzinfo=UTC), runner=exit_process)
""",
            str(tmp_path),
        ],
        check=False,
    )
    assert child.returncode == 31
    assert read_jsonl(tmp_path / "gold" / scheduler.STATE_FILE)[-1]["result"] == "started"
    assert (
        scheduler.tick(
            tmp_path,
            now=datetime(2026, 10, 5, 0, 15, tzinfo=UTC),
            runner=lambda *a, **kw: pytest.fail("attempt repeated"),
        )
        == []
    )


def test_failed_state_write_prevents_execution(tmp_path, monkeypatch):
    from security_lakehouse.workflows import save_workflow

    save_workflow(
        tmp_path,
        workflow_id=None,
        name="disk-full",
        description="",
        nodes=[{"id": "cron", "node_type": "trigger.cron", "params": {"schedule": "every 23h"}}],
        edges=[],
    )

    def cannot_persist(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(scheduler, "append_jsonl", cannot_persist)
    with pytest.raises(OSError, match="disk full"):
        scheduler.tick(tmp_path, runner=lambda *a, **kw: pytest.fail("ran without durable attempt"))


def test_corrupt_scheduler_state_http_error_is_sanitized(tmp_path):
    from fastapi.testclient import TestClient

    from security_lakehouse.server_app import create_app

    (tmp_path / "silver").mkdir()
    state = tmp_path / "gold" / scheduler.STATE_FILE
    state.parent.mkdir()
    state.write_text('{"secret-provider-detail":true}\n')
    before = state.read_bytes()
    with TestClient(create_app(tmp_path, require_auth=False), raise_server_exceptions=False) as client:
        response = client.post("/api/v1/scheduler/tick", json={})
    assert response.status_code == 503
    assert response.json()["errors"][0] == {"code": "invalid_stored_data", "detail": "stored data failed validation"}
    assert state.read_bytes() == before


def test_corrupt_scheduler_state_direct_api_returns_error(tmp_path):
    from security_lakehouse import api_v1

    path = tmp_path / "gold" / scheduler.STATE_FILE
    path.parent.mkdir()
    path.write_text("{}\n")
    status, body = api_v1.handle_post("/api/v1/scheduler/tick", {}, tmp_path)
    assert status == 503
    assert body["errors"][0]["code"] == "invalid_stored_data"
    assert path.read_text() == "{}\n"
