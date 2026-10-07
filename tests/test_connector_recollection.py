"""Mutable source records can advance without changing their event timestamp."""

import copy
from datetime import UTC, datetime, timedelta

import pytest

from security_lakehouse import connector_runner, connector_state
from security_lakehouse.connectors_siem import SiemFixtureClient, collect_siem_evidence
from security_lakehouse.generations import active_generation
from security_lakehouse.ingestion.watermark import read_watermark
from security_lakehouse.io import read_jsonl
from security_lakehouse.verification import verify_event
from test_connector_event_identity import event
from test_siem_connector import FIXTURE_DIR


@pytest.mark.parametrize("mode", ["append", "snapshot"])
@pytest.mark.parametrize("newest_first", [False, True])
@pytest.mark.parametrize("collection_key", ["collected_at", "evidence_collected_at"])
def test_equal_event_time_uses_newest_collection(tmp_path, mode, newest_first, collection_key):
    original = event(status="open")
    original["evidence"] = {"ref": "fixture://alert", collection_key: "2026-01-01T01:00:00Z"}
    updated = copy.deepcopy(original)
    updated["status"] = "closed"
    updated["evidence"][collection_key] = "2026-01-01T04:00:00+02:00"
    rows = [original, updated]
    if newest_first:
        rows.reverse()
    path = tmp_path / "raw.jsonl"
    for row in rows:
        connector_runner._upsert_raw_events(path, [row], connector_id="one", write_mode=mode)
    stored = read_jsonl(path)
    assert len(stored) == 1
    assert stored[0]["status"] == "closed"
    assert stored[0]["event_time"] == original["event_time"]
    before = path.read_bytes()
    connector_runner._upsert_raw_events(path, rows, connector_id="one", write_mode=mode)
    assert path.read_bytes() == before


def test_source_time_takes_precedence_over_recollection_time(tmp_path):
    current = event(at="2026-01-02T00:00:00Z", status="closed")
    old = event(status="open")
    old["evidence"]["collected_at"] = "2026-01-03T00:00:00Z"
    path = tmp_path / "raw.jsonl"
    connector_runner._upsert_raw_events(path, [current, old], connector_id="one", write_mode="append")
    assert read_jsonl(path)[0]["status"] == "closed"


@pytest.mark.parametrize("mode", ["append", "snapshot"])
def test_equal_collection_instants_still_reject_conflicts(tmp_path, mode):
    path = tmp_path / "raw.jsonl"
    connector_runner._upsert_raw_events(path, [event()], connector_id="one", write_mode=mode)
    conflict = event(status="failed")
    conflict["evidence"]["collected_at"] = "2026-01-01T02:00:00+01:00"
    before = path.read_bytes()
    with pytest.raises(ValueError, match="conflict"):
        connector_runner._upsert_raw_events(path, [conflict], connector_id="one", write_mode=mode)
    assert path.read_bytes() == before


def test_siem_recollection_updates_posture_and_preserves_generation(tmp_path, monkeypatch):
    # Simulate an export redelivering an updated alert despite its cursor. Use
    # the real SIEM conversion, sync, publication, and lineage implementation.
    alert = copy.deepcopy(SiemFixtureClient(FIXTURE_DIR).alerts()[1])
    moment = datetime.now(UTC) - timedelta(minutes=1)
    observations = []
    for index, status in enumerate(("open", "closed", "closed")):
        alert["status"] = status
        alert["alert_state"] = status
        client = SiemFixtureClient(FIXTURE_DIR)
        monkeypatch.setattr(client, "alerts", lambda *, since=None: [copy.deepcopy(alert)])
        observations.append(collect_siem_evidence(client, collected_at=moment + timedelta(seconds=index)))
    pulls = iter(observations)
    monkeypatch.setattr(connector_runner, "collect_siem_evidence", lambda client, *, since=None: next(pulls))
    connector_state.append_config_event(tmp_path, connector_id="siem-alerts", state="enabled", actor="test")

    def sync():
        return connector_runner.run_connector_sync(tmp_path, connector_id="siem-alerts", fixture_dir=FIXTURE_DIR)

    assert sync().result == "ok"
    previous = active_generation(tmp_path)
    previous_bytes = (previous / "silver/normalized_events.jsonl").read_bytes()
    assert all(row["status"] == "fail" for row in read_jsonl(tmp_path / "gold/control_posture.jsonl"))
    cursor = read_watermark(tmp_path, "siem-alerts")
    assert sync().result == "ok"
    assert sync().result == "ok"
    current = read_jsonl(tmp_path / "silver/normalized_events.jsonl")
    assert len(current) == 1
    assert current[0]["status"] == "closed"
    # Closing the alert clears the finding; the SOC 2 program still needs its
    # other required evidence types before it can pass.
    assert {row["control_id"]: row["status"] for row in read_jsonl(tmp_path / "gold/control_posture.jsonl")} == {
        "SOC2-CC7.2": "stale",
        "ISO27001-A.8.16": "pass",
    }
    assert verify_event(tmp_path, current[0]["event_id"])["verified"]
    assert read_watermark(tmp_path, "siem-alerts") == cursor
    assert (previous / "silver/normalized_events.jsonl").read_bytes() == previous_bytes
    assert read_jsonl(previous / "silver/normalized_events.jsonl")[0]["status"] == "open"
