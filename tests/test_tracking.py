"""Triage persistence + verification + auditor-mode role gating tests."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from security_lakehouse import api_v1
from security_lakehouse.server import _Handler
from security_lakehouse.tracking import append_event, latest_state, list_events, tracking_path, verify_tracking_chain
from security_lakehouse.verification import verify_event

# --- pure-Python tracking module ------------------------------------------------


def test_append_and_list_round_trip(tmp_path: Path) -> None:
    rec = append_event(
        tmp_path,
        violation_id="SOC2-CC6.1:evt-001",
        actor="alice",
        state="triaged",
        assignee="bob",
        due_at="2026-06-01T00:00:00Z",
        note="initial review",
    )
    assert rec["violation_id"] == "SOC2-CC6.1:evt-001"
    assert rec["state"] == "triaged"
    assert rec["prev_hash"] is None
    assert len(rec["record_hash"]) == 64
    assert tracking_path(tmp_path).is_file()

    events = list_events(tmp_path)
    assert len(events) == 1
    assert events[0]["assignee"] == "bob"

    filtered = list_events(tmp_path, violation_id="SOC2-CC6.1:evt-001")
    assert len(filtered) == 1
    assert list_events(tmp_path, violation_id="missing") == []


def test_latest_state_returns_most_recent(tmp_path: Path) -> None:
    append_event(tmp_path, violation_id="v1", actor="a", state="triaged")
    append_event(tmp_path, violation_id="v1", actor="a", state="in_progress")
    append_event(tmp_path, violation_id="v1", actor="a", state="resolved")
    latest = latest_state(tmp_path, violation_id="v1")
    assert latest is not None
    assert latest["state"] == "resolved"


def test_append_rejects_unknown_state(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        append_event(tmp_path, violation_id="v1", actor="a", state="bogus")


def test_append_requires_violation_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        append_event(tmp_path, violation_id="", actor="a", state="triaged")


def test_tracking_events_are_hash_chained(tmp_path: Path) -> None:
    first = append_event(tmp_path, violation_id="v1", actor="a", state="triaged")
    second = append_event(tmp_path, violation_id="v1", actor="a", state="resolved")

    assert first["prev_hash"] is None
    assert second["prev_hash"] == first["record_hash"]
    assert verify_tracking_chain(tmp_path) == {
        "ok": True,
        "length": 2,
        "tip_hash": second["record_hash"],
        "issues": [],
    }


def test_tracking_idempotency_key_returns_existing_event(tmp_path: Path) -> None:
    first = append_event(
        tmp_path,
        violation_id="v1",
        actor="a",
        state="triaged",
        note="first attempt",
        idempotency_key="triage-v1",
    )
    replay = append_event(
        tmp_path,
        violation_id="v1",
        actor="a",
        state="resolved",
        note="retry with different body",
        idempotency_key="triage-v1",
    )

    assert replay["idempotent_replay"] is True
    assert replay["tracking_id"] == first["tracking_id"]
    assert replay["state"] == "triaged"
    assert len(list_events(tmp_path)) == 1


def test_tracking_chain_detects_tamper(tmp_path: Path) -> None:
    append_event(tmp_path, violation_id="v1", actor="a", state="triaged")
    path = tracking_path(tmp_path)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["state"] = "resolved"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")

    result = verify_tracking_chain(tmp_path)
    assert result["ok"] is False
    assert any("record_hash" in issue for issue in result["issues"])


def test_concurrent_triage_events_do_not_fork_the_chain(tmp_path: Path) -> None:
    """Two writers reading the same tip must not both claim it as prev_hash."""
    workers = 8
    barrier = threading.Barrier(workers)

    def submit(index: int) -> None:
        barrier.wait()
        append_event(tmp_path, violation_id=f"v{index}", actor="agent", state="triaged")

    threads = [threading.Thread(target=submit, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    result = verify_tracking_chain(tmp_path)
    assert result["ok"] is True, result["issues"]
    assert result["length"] == workers


def test_tracking_integrity_route_and_catalog(tmp_path: Path) -> None:
    append_event(tmp_path, violation_id="v1", actor="a", state="triaged")

    status, body = api_v1.handle_get("/api/v1/tracking/integrity", {}, tmp_path)
    assert status == HTTPStatus.OK
    assert body["meta"]["resource"] == "tracking.integrity"
    assert body["errors"] == []
    assert body["data"]["ok"] is True

    catalog = api_v1.resource_catalog()
    row = next((r for r in catalog if r["path"] == "/api/v1/tracking/integrity"), None)
    assert row is not None
    assert row["resource"] == "tracking.integrity"
    assert row["methods"] == ["GET"]


# --- verification module --------------------------------------------------------


def _write_bronze_silver(tmp_path: Path) -> str:
    bronze_dir = tmp_path / "bronze"
    silver_dir = tmp_path / "silver"
    bronze_dir.mkdir(parents=True)
    silver_dir.mkdir(parents=True)
    raw = {"event_id": "evt-001", "kind": "cloud.config", "payload": {"finding": "x"}}
    import hashlib

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    bronze_record = {"ingested_at": "2026-05-23T00:00:00Z", "raw_sha256": expected, "raw": raw}
    (bronze_dir / "raw_events.jsonl").write_text(json.dumps(bronze_record) + "\n", encoding="utf-8")
    silver_record = {"event_id": "evt-001", "raw_sha256": expected, "source": "cspm"}
    (silver_dir / "normalized_events.jsonl").write_text(json.dumps(silver_record) + "\n", encoding="utf-8")
    # A matching event hash only qualifies as verified when its legacy lake's
    # complete integrity manifest also verifies.
    from security_lakehouse.io import write_json
    from security_lakehouse.pipeline import build_evidence_integrity

    artifacts = {
        "bronze_raw_events": bronze_dir / "raw_events.jsonl",
        "silver_normalized_events": silver_dir / "normalized_events.jsonl",
    }
    for name in ("control_posture", "control_tests", "evidence_freshness", "asset_risk", "metrics", "dashboard_data"):
        path = tmp_path / "gold" / (name + (".json" if name in {"metrics", "dashboard_data"} else ".jsonl"))
        path.parent.mkdir(exist_ok=True)
        path.write_text("{}" if path.suffix == ".json" else "")
        artifacts["gold_" + name] = path
    write_json(
        tmp_path / "gold/evidence_integrity.json",
        build_evidence_integrity(
            raw_rows=[raw], bronze_rows=[bronze_record], silver_rows=[silver_record], artifact_paths=artifacts
        ),
    )
    return expected


def test_verify_event_matches(tmp_path: Path) -> None:
    expected = _write_bronze_silver(tmp_path)
    result = verify_event(tmp_path, "evt-001")
    assert result["verified"] is True
    assert result["verification_scope"] == "lake_and_bronze_hash"
    assert result["expected_sha256"] == expected
    assert result["computed_sha256"] == expected


def test_verify_event_detects_drift(tmp_path: Path) -> None:
    _write_bronze_silver(tmp_path)
    silver_path = tmp_path / "silver" / "normalized_events.jsonl"
    rows = [json.loads(line) for line in silver_path.read_text(encoding="utf-8").splitlines() if line]
    rows[0]["raw_sha256"] = "0" * 64
    silver_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    result = verify_event(tmp_path, "evt-001")
    assert result["verified"] is False
    assert result["reason"]


def test_verify_event_missing_silver(tmp_path: Path) -> None:
    result = verify_event(tmp_path, "evt-missing")
    assert result["verified"] is False
    assert result["source_layer"] == "missing"


# --- HTTP server integration ----------------------------------------------------


def _spin_handler(lake: Path) -> ThreadingHTTPServer:
    (lake / "gold").mkdir(parents=True, exist_ok=True)
    (lake / "silver").mkdir(parents=True, exist_ok=True)
    (lake / "console.html").write_bytes(b"<!doctype html>")

    class Handler(_Handler):
        lake_dir = lake
        dashboard_path = lake / "console.html"
        web_dist = None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _request(
    server: ThreadingHTTPServer,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    role: str | None = None,
) -> tuple[int, dict]:
    host, port = server.server_address
    url = f"http://{host}:{port}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(  # noqa: S310 (local test url)
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    if role:
        req.add_header("X-Trust-Role", role)
    try:
        with urllib.request.urlopen(req) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read().decode("utf-8"))


def test_triage_round_trip_via_http(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/violations/SOC2-CC6.1:evt-001/triage",
            body={"state": "triaged", "actor": "carol", "assignee": "dan"},
        )
        assert status == HTTPStatus.CREATED
        assert body["event"]["state"] == "triaged"

        status, body = _request(server, "GET", "/api/violations/SOC2-CC6.1:evt-001/tracking")
        assert status == HTTPStatus.OK
        assert body["current_state"] == "triaged"
        assert len(body["events"]) == 1
    finally:
        server.shutdown()


def test_triage_idempotency_key_via_http(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        host, port = server.server_address
        url = f"http://{host}:{port}/api/violations/v1/triage"
        payload = {"state": "triaged", "actor": "carol"}
        headers = {"Content-Type": "application/json", "Idempotency-Key": "triage-v1"}
        for _ in range(2):
            req = urllib.request.Request(  # noqa: S310 (local test url)
                url,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers=headers,
            )
            with urllib.request.urlopen(req) as resp:
                assert int(resp.status) == HTTPStatus.CREATED

        assert len(list_events(tmp_path)) == 1
        assert verify_tracking_chain(tmp_path)["ok"] is True
    finally:
        server.shutdown()


def test_triage_rejects_unknown_state(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/violations/v1/triage",
            body={"state": "made-up"},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "state must be" in body["reason"]
    finally:
        server.shutdown()


def test_auditor_role_blocks_post(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "POST", "/api/snapshots", body={"reason": "audit"}, role="auditor")
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "forbidden"

        status, body = _request(
            server,
            "POST",
            "/api/violations/v1/triage",
            body={"state": "triaged"},
            role="auditor",
        )
        assert status == HTTPStatus.FORBIDDEN
    finally:
        server.shutdown()


def test_auditor_role_redacts_pii_in_responses(tmp_path: Path) -> None:
    append_event(
        tmp_path,
        violation_id="v1",
        actor="alice",
        state="triaged",
        assignee="bob",
        note="sensitive remediation context",
    )
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/violations/v1/tracking", role="auditor")
        assert status == HTTPStatus.OK
        event = body["events"][0]
        assert event["actor"] == "[redacted]"
        assert event["assignee"] == "[redacted]"
        assert event["note"] == "[redacted]"
        assert event["state"] == "triaged"
    finally:
        server.shutdown()


def test_snapshot_list_endpoint(tmp_path: Path) -> None:
    snapshots_dir = tmp_path / "gold" / "snapshots"
    snapshots_dir.mkdir(parents=True)
    (snapshots_dir / "assessment-20260520T000000.json").write_text(
        json.dumps(
            {
                "assessment_type": "point_in_time_snapshot",
                "evaluated_at": "2026-05-20T00:00:00Z",
                "snapshot_reason": "monthly_review",
                "assessment_hash": "abc",
                "posture": {
                    "score": 88.0,
                    "open_violation_count": 4,
                    "critical_violation_count": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/snapshots")
        assert status == HTTPStatus.OK
        assert body["count"] == 1
        assert body["snapshots"][0]["reason"] == "monthly_review"
        assert body["snapshots"][0]["posture_score"] == 88.0
    finally:
        server.shutdown()


def test_verify_endpoint_returns_match_status(tmp_path: Path) -> None:
    _write_bronze_silver(tmp_path)
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "POST", "/api/evidence/evt-001/verify")
        assert status == HTTPStatus.OK
        assert body["verified"] is True
        assert body["source_layer"] == "bronze"
    finally:
        server.shutdown()
