"""Failure contracts for the real-container CI smoke harness."""

from __future__ import annotations

import http.client
import runpy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools/compose_smoke.py"


def test_readiness_retries_a_connection_closed_during_startup(monkeypatch) -> None:
    wait = runpy.run_path(str(SCRIPT))["wait_ready"]
    calls = []

    def get(base, path):
        calls.append(path)
        if len(calls) == 1:
            raise http.client.RemoteDisconnected("starting")
        return b'{"ok":true}'

    monkeypatch.setitem(wait.__globals__, "get", get)
    monkeypatch.setattr(wait.__globals__["time"], "sleep", lambda _: None)
    wait("http://127.0.0.1:1234")
    assert calls == ["/api/readyz", "/api/readyz"]


def test_readiness_fails_when_deadline_expires(monkeypatch) -> None:
    wait = runpy.run_path(str(SCRIPT))["wait_ready"]
    ticks = iter([0, 0, 2])
    monkeypatch.setattr(wait.__globals__["time"], "monotonic", lambda: next(ticks))
    monkeypatch.setattr(wait.__globals__["time"], "sleep", lambda _: None)
    monkeypatch.setitem(wait.__globals__, "get", lambda *_: b'{"ok":false}')
    with pytest.raises(RuntimeError, match="did not become ready"):
        wait("http://127.0.0.1:1234", timeout=1)


def test_failed_startup_still_collects_logs_removes_volume_and_deletes_secret(tmp_path, monkeypatch) -> None:
    qualify = runpy.run_path(str(SCRIPT))["qualify"]
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        if "up" in args:
            raise RuntimeError("injected startup failure")
        return "synthetic diagnostic"

    monkeypatch.setitem(qualify.__globals__, "run", run)
    output = tmp_path / "receipt"
    with pytest.raises(RuntimeError, match="injected startup failure"):
        qualify("trustops:ci", output)
    assert any("logs" in call for call in calls)
    assert any(call[-2:] == ("down", "--volumes") for call in calls)
    assert not (output / "trustops.env").exists()
    assert '"ok": false' in (output / "result.json").read_text()
    assert (output / "container.log").read_text().strip() == "synthetic diagnostic"
