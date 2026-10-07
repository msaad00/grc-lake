"""Jira ticketing/workflow-evidence connector runner tests (fixture-backed)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE, ConnectorSyncError, run_connector_sync
from security_lakehouse.connector_state import (
    append_config_event,
    has_adapter,
    latest_run,
    run_probe,
)
from security_lakehouse.connectors_jira import JiraFixtureClient, collect_jira_evidence
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "jira"
COLLECTED_AT = datetime(2026, 5, 28, tzinfo=UTC)


def _by_asset(rows: list[dict], event_type: str) -> dict[str, dict]:
    return {r["entity"]["asset_id"]: r for r in rows if r["event_type"] == event_type}


def test_collect_jira_evidence_is_schema_valid_and_mapped() -> None:
    client = JiraFixtureClient(FIXTURE)
    rows = collect_jira_evidence(client, collected_at=COLLECTED_AT)

    assert validate_raw_events(rows) == []
    # 3 issues -> 3 ticket + 3 transition events; 2 projects -> 2 project events.
    assert len(rows) == 8

    tickets = _by_asset(rows, "jira.workflow.ticket")
    transitions = _by_asset(rows, "jira.workflow.transition")
    projects = [r for r in rows if r["event_type"] == "jira.workflow.project"]
    assert len(tickets) == 3
    assert len(transitions) == 3
    assert len(projects) == 2

    # Every emitted event is Jira-scoped and maps to workflow controls that
    # exist in the control catalog.
    for row in rows:
        assert row["source"] == "jira"
        assert "SOC2-CC7.2" in row["controls"]

    # A resolved remediation ticket is observed evidence (pass); an overdue open
    # ticket is a medium open finding; an unassigned open ticket is also open.
    done = tickets["jira:issue:SEC-101"]
    assert done["status"] == "pass"
    assert done["attributes"]["is_done"] is True
    assert done["attributes"]["is_assigned"] is True

    overdue = tickets["jira:issue:SEC-102"]
    assert overdue["status"] == "open"
    assert overdue["severity"] == "medium"
    assert overdue["attributes"]["is_overdue"] is True

    unassigned = tickets["jira:issue:GOV-7"]
    assert unassigned["status"] == "open"
    assert unassigned["attributes"]["is_assigned"] is False
    assert unassigned["attributes"]["is_overdue"] is False

    # Transition events track lifecycle position for ageing in-progress work.
    in_progress = transitions["jira:issue:GOV-7"]
    assert in_progress["status"] == "observed"
    assert in_progress["attributes"]["in_progress"] is True

    # Asset + evidence shapes are Jira-scoped and point at the read-only API.
    sample = tickets["jira:issue:SEC-101"]
    assert sample["entity"]["asset_type"] == "workflow_ticket"
    assert sample["evidence"]["evidence_ref"].endswith("/rest/api/3/issue/SEC-101")

    archived = [p for p in projects if p["entity"]["asset_id"] == "jira:project:GOV"][0]
    assert archived["status"] == "open"
    assert archived["attributes"]["is_archived"] is True
    assert "/rest/api/3/project/" in archived["evidence"]["evidence_ref"]


def test_jira_connector_sync_writes_raw_and_materializes_lake(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="jira-ticketing", state="enabled", actor="alice")
    result = run_connector_sync(
        tmp_path,
        connector_id="jira-ticketing",
        fixture_dir=FIXTURE,
    )
    assert result.result == "ok"
    assert result.evidence_count == 8
    assert result.materialized is True

    raw_rows = read_jsonl(tmp_path / CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert len(raw_rows) == 8
    assert all(r["source"] == "jira" for r in raw_rows)
    assert (tmp_path / "bronze" / "raw_events.jsonl").is_file()
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    assert (tmp_path / "gold" / "current_posture.json").is_file()

    run = latest_run(tmp_path, "jira-ticketing", kind="sync")
    assert run["result"] == "ok"
    assert run["evidence_count"] == 8


def test_jira_connector_sync_upserts_stable_event_ids(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="jira-ticketing", state="enabled", actor="a")
    first = run_connector_sync(tmp_path, connector_id="jira-ticketing", fixture_dir=FIXTURE)
    second = run_connector_sync(
        tmp_path,
        connector_id="jira-ticketing",
        fixture_dir=FIXTURE,
        materialize=False,
    )
    assert first.evidence_count == second.evidence_count == 8
    assert len(read_jsonl(tmp_path / CONNECTOR_RAW_FILE)) == 8


def test_jira_connector_sync_requires_enabled_connector(tmp_path: Path) -> None:
    with pytest.raises(ConnectorSyncError, match="not enabled") as exc:
        run_connector_sync(tmp_path, connector_id="jira-ticketing", fixture_dir=FIXTURE)
    assert exc.value.run["result"] == "error"


def test_jira_connector_sync_without_fixture_or_creds_errors(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("JIRA_BASE_URL", raising=False)
    monkeypatch.delenv("JIRA_EMAIL", raising=False)
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    monkeypatch.delenv("__provider_default__", raising=False)
    append_config_event(tmp_path, connector_id="jira-ticketing", state="enabled", actor="a")
    with pytest.raises(ConnectorSyncError, match="requires --fixture-dir"):
        run_connector_sync(tmp_path, connector_id="jira-ticketing")


def test_jira_adapter_is_registered_and_probe_reports_ok(tmp_path: Path) -> None:
    assert has_adapter("jira-ticketing") is True
    # Before enablement the probe is skipped (no synthetic collection signal).
    skipped = run_probe(tmp_path, connector_id="jira-ticketing")
    assert skipped["result"] == "skipped"
    assert "not enabled" in skipped["error"]

    append_config_event(tmp_path, connector_id="jira-ticketing", state="enabled", actor="a")
    ok = run_probe(tmp_path, connector_id="jira-ticketing")
    # Adapter-available -> probe is "ok", not "skipped", and reports no count.
    assert ok["result"] == "ok"
    assert ok["evidence_count"] is None
