"""A slow tenant stream must not hold the cache lock for other tenants."""

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from security_lakehouse import server_app


def test_stream_builds_for_different_lakes_do_not_serialize(tmp_path, monkeypatch):
    from security_lakehouse import ai_governance, evidence_freshness, evidence_freshness_workflows, generations

    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(generations, "generation_identity", lambda lake: {"generation_id": "one"})
    monkeypatch.setattr(ai_governance, "build_ai_governance_status", lambda **kw: {})
    monkeypatch.setattr(evidence_freshness_workflows, "load_freshness_records", lambda lake: [])
    monkeypatch.setattr(evidence_freshness, "build_freshness_summary", lambda rows: {})

    def posture(path, params, lake):
        if Path(lake).name == "slow":
            entered.set()
            assert release.wait(5)
        return 200, {"data": {"lake": Path(lake).name}}

    monkeypatch.setattr(server_app.api_v1, "handle_get", posture)
    with ThreadPoolExecutor(max_workers=2) as pool:
        slow = pool.submit(server_app._stream_payloads, tmp_path / "slow", "a", None, 10)
        try:
            assert entered.wait(2)
            fast = pool.submit(server_app._stream_payloads, tmp_path / "fast", "b", None, 10)
            assert fast.result(timeout=1)["posture"]["lake"] == "fast"
        finally:
            release.set()
        assert slow.result()["posture"]["lake"] == "slow"


def test_stream_cache_expires_and_generation_changes_bypass_it(tmp_path, monkeypatch):
    from security_lakehouse import ai_governance, evidence_freshness, evidence_freshness_workflows, generations

    clock = [100.0]
    generation = ["first"]
    calls = []
    monkeypatch.setattr(server_app.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(generations, "generation_identity", lambda lake: {"generation_id": generation[0]})
    monkeypatch.setattr(ai_governance, "build_ai_governance_status", lambda **kw: {})
    monkeypatch.setattr(evidence_freshness_workflows, "load_freshness_records", lambda lake: [])
    monkeypatch.setattr(evidence_freshness, "build_freshness_summary", lambda rows: {})

    def posture(*args):
        calls.append(generation[0])
        return 200, {"data": {"build": len(calls)}}

    monkeypatch.setattr(server_app.api_v1, "handle_get", posture)
    assert server_app._stream_payloads(tmp_path, "a", None, 10)["posture"]["build"] == 1
    clock[0] = 159.9
    assert server_app._stream_payloads(tmp_path, "a", None, 10)["posture"]["build"] == 1
    clock[0] = 160.0
    assert server_app._stream_payloads(tmp_path, "a", None, 10)["posture"]["build"] == 2
    generation[0] = "next"
    assert server_app._stream_payloads(tmp_path, "a", None, 10)["posture"]["build"] == 3
    assert server_app._stream_payloads(tmp_path, "other", None, 10)["posture"]["build"] == 4


def test_concurrent_subscribers_share_one_build(tmp_path, monkeypatch):
    from security_lakehouse import ai_governance, evidence_freshness, evidence_freshness_workflows, generations

    entered, release = threading.Event(), threading.Event()
    calls = []
    monkeypatch.setattr(generations, "generation_identity", lambda lake: {"generation_id": "one"})
    monkeypatch.setattr(ai_governance, "build_ai_governance_status", lambda **kw: {})
    monkeypatch.setattr(evidence_freshness_workflows, "load_freshness_records", lambda lake: [])
    monkeypatch.setattr(evidence_freshness, "build_freshness_summary", lambda rows: {})

    def posture(*args):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return 200, {"data": {"build": len(calls)}}

    monkeypatch.setattr(server_app.api_v1, "handle_get", posture)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(server_app._stream_payloads, tmp_path, "a", None, 10) for _ in range(4)]
        try:
            assert entered.wait(2)
        finally:
            release.set()
        assert [future.result()["posture"]["build"] for future in futures] == [1] * 4
    assert len(calls) == 1
