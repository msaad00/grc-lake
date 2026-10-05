"""Okta System Log connector adapter tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE, run_connector_sync
from security_lakehouse.connector_state import append_config_event, has_adapter
from security_lakehouse.connectors_okta import OktaFixtureClient, collect_okta_system_log_evidence
from security_lakehouse.ingestion.watermark import read_watermark
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "okta-system-log"


def test_has_adapter_registered() -> None:
    assert has_adapter("okta-system-log") is True


def test_collect_okta_system_log_evidence_maps_auth_events() -> None:
    client = OktaFixtureClient(FIXTURE)
    rows = collect_okta_system_log_evidence(client, collected_at=datetime(2026, 5, 28, tzinfo=UTC))
    assert validate_raw_events(rows) == []
    assert len(rows) == 2
    assert {row["source"] for row in rows} == {"okta-system-log"}
    failed = [row for row in rows if row["attributes"]["outcome_result"] == "FAILURE"]
    assert len(failed) == 1
    assert all(row["status"] == "observed" for row in rows)
    assert "FEDRAMP-AC-7" in failed[0]["controls"]


def test_okta_system_log_sync_advances_watermark(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="okta-system-log", state="enabled", actor="test")
    result = run_connector_sync(tmp_path, connector_id="okta-system-log", fixture_dir=FIXTURE, actor="test")
    assert result.result == "ok"
    assert result.evidence_count == 2
    assert result.watermark_cursor == "2026-05-20T13:05:00Z"
    assert read_watermark(tmp_path, "okta-system-log") == "2026-05-20T13:05:00Z"
    raw = read_jsonl(tmp_path / CONNECTOR_RAW_FILE)
    assert len(raw) == 2
