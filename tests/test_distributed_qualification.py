"""Qualification waits for data-plane recovery without hiding lost evidence."""

import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from tools import distributed_qualification_probe as probe


@pytest.fixture
def recovery(monkeypatch):
    rows = [{"evidence": "committed"}]
    saved = []
    clock = [0.0]
    catalog = SimpleNamespace(
        head=lambda tenant: SimpleNamespace(version=7), engine=SimpleNamespace(dispose=lambda: None)
    )
    monkeypatch.setattr(probe, "ready", lambda: None)
    monkeypatch.setattr(probe, "runtime", lambda: (SimpleNamespace(catalog=catalog), None))
    data = {
        "credentials": [{"tenant": "tenant-a"}],
        "baseline": {
            "versions": {"tenant-a": 7},
            "evidence_sha256": {"tenant-a": hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()},
        },
    }
    monkeypatch.setattr(probe, "load", data.__getitem__)
    monkeypatch.setattr(probe, "save", lambda *args: saved.append(args))
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    return rows, saved, clock


def test_recovery_waits_for_objects_after_bucket_is_ready(recovery, monkeypatch):
    rows, saved, _ = recovery
    responses = iter([httpx.Response(503), httpx.Response(200, json={"data": rows})])
    monkeypatch.setattr(probe, "request", lambda *args, **kwargs: next(responses))
    probe.stable("objects-recovered")
    assert saved and saved[0][1]["evidence_sha256_preserved"]


def test_recovery_failure_is_bounded(recovery, monkeypatch):
    _, saved, clock = recovery
    monkeypatch.setattr(probe, "request", lambda *args, **kwargs: httpx.Response(503))
    with pytest.raises(AssertionError, match="recovery deadline"):
        probe.stable("objects-recovered")
    assert clock[0] <= 90
    assert not saved


def test_recovery_never_retries_a_successful_but_changed_evidence_response(recovery, monkeypatch):
    _, saved, clock = recovery
    monkeypatch.setattr(probe, "request", lambda *args, **kwargs: httpx.Response(200, json={"data": []}))
    with pytest.raises(AssertionError):
        probe.stable("objects-recovered")
    assert clock[0] == 0
    assert not saved
