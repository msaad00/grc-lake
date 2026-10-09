"""Rippling and Workday HRIS connectors (fixture-backed + fake HTTP)."""

from __future__ import annotations

import base64
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import netguard
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.connectors_rippling import RipplingClient, RipplingFixtureClient, collect_rippling_evidence
from security_lakehouse.connectors_workday import (
    WORKDAY_COLUMNS,
    WorkdayReportClient,
    WorkdayReportFixtureClient,
    collect_workday_evidence,
    validate_report_url,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURES = Path(__file__).parent / "fixtures"
COLLECTED = datetime(2026, 6, 3, tzinfo=UTC)
REPORT_URL = (
    "https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/isu_trustops/GrcLake_Employment?format=json"
)
PERSONNEL_ATTRIBUTES = {
    "employee_id",
    "employee_number",
    "work_email",
    "employment_status",
    "hire_date",
    "termination_date",
    "is_terminated",
    "department",
    "manager_id",
    "data_sensitivity",
}


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r["attributes"]["employee_id"]: r for r in rows}


# --- Rippling ---------------------------------------------------------------


def test_rippling_emits_minimal_employment_records() -> None:
    rows = collect_rippling_evidence(RipplingFixtureClient(FIXTURES / "rippling"), collected_at=COLLECTED)

    assert validate_raw_events(rows) == []
    workers = _by_id(rows)
    assert sorted(workers) == ["w-201", "w-202", "w-203"]
    assert workers["w-202"]["attributes"]["is_terminated"] is True
    assert workers["w-203"]["attributes"]["is_terminated"] is False
    assert workers["w-201"]["attributes"]["employee_number"] == "201"
    for row in rows:
        assert row["source"] == "rippling"
        assert row["event_type"] == "hris.personnel.employment"
        assert set(row["attributes"]) <= PERSONNEL_ATTRIBUTES
    assert "1990-01-01" not in json.dumps(rows)
    assert "ada.home@example.net" not in json.dumps(rows)


def test_rippling_client_pages_with_bearer_and_pins_next_link_host(monkeypatch: pytest.MonkeyPatch) -> None:
    workers = json.loads((FIXTURES / "rippling" / "workers.json").read_text())
    first = "https://rest.ripplingapis.com/workers/?limit=100"
    second = "https://rest.ripplingapis.com/workers/?limit=100&cursor=abc"
    pages = {first: {"results": workers[:2], "next_link": second}, second: {"results": workers[2:], "next_link": None}}
    seen: list[Any] = []

    def fake_open_public(request: Any, *, timeout: float, label: str) -> _FakeResponse:
        seen.append(request)
        return _FakeResponse(json.dumps(pages[request.full_url]).encode())

    monkeypatch.setattr(netguard, "open_public", fake_open_public)
    assert len(RipplingClient(token="tok").workers()) == 4
    assert [r.full_url for r in seen] == [first, second]
    assert seen[0].get_header("Authorization") == "Bearer tok"

    pages[first] = {"results": [], "next_link": "https://attacker.example/steal"}
    with pytest.raises(ValueError, match="rest.ripplingapis.com"):
        RipplingClient(token="tok").workers()


# --- Workday ----------------------------------------------------------------


def test_workday_emits_minimal_employment_records() -> None:
    rows = collect_workday_evidence(
        WorkdayReportFixtureClient(FIXTURES / "workday", report_url=REPORT_URL), collected_at=COLLECTED
    )

    assert validate_raw_events(rows) == []
    workers = _by_id(rows)
    assert sorted(workers) == ["301", "302"]
    assert workers["302"]["attributes"]["is_terminated"] is True
    assert workers["301"]["attributes"]["termination_date"] is None
    assert workers["301"]["attributes"]["department"] == "Engineering"
    for row in rows:
        assert row["source"] == "workday"
        assert set(row["attributes"]) <= PERSONNEL_ATTRIBUTES
    assert "Ada L" not in json.dumps(rows)
    assert set(WORKDAY_COLUMNS) == {
        "Employee_ID",
        "Work_Email",
        "Worker_Status",
        "Hire_Date",
        "Termination_Date",
        "Department",
        "Manager_ID",
    }


def test_workday_client_uses_basic_auth_against_the_report_url(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.loads((FIXTURES / "workday" / "report.json").read_text())
    seen: list[Any] = []

    def fake_open_public(request: Any, *, timeout: float, label: str) -> _FakeResponse:
        seen.append(request)
        return _FakeResponse(json.dumps(payload).encode())

    monkeypatch.setattr(netguard, "open_public", fake_open_public)
    rows = WorkdayReportClient(REPORT_URL, username="isu_trustops", password="pw").rows()

    assert len(rows) == 3
    assert seen[0].full_url == REPORT_URL
    assert seen[0].get_header("Authorization") == "Basic " + base64.b64encode(b"isu_trustops:pw").decode()


@pytest.mark.parametrize(
    "url",
    [
        "http://wd5-services1.myworkday.com/ccx/service/customreport2/acme/u/r?format=json",
        "https://attacker.example/ccx/service/customreport2/acme/u/r?format=json",
        "https://myworkday.com.attacker.example/r?format=json",
        "https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/u/r",
        "https://user:pw@wd5-services1.myworkday.com/r?format=json",
    ],
)
def test_workday_report_url_must_be_https_workday_json(url: str) -> None:
    with pytest.raises(ValueError, match="report_url"):
        validate_report_url(url)


# --- Runner wiring ----------------------------------------------------------


@pytest.mark.parametrize(
    ("connector_id", "fixture", "credentials", "expected"),
    [
        ("rippling-personnel", "rippling", {"credential_ref": "RIPPLING_API_TOKEN"}, 3),
        (
            "workday-personnel",
            "workday",
            {"report_url": REPORT_URL, "username": "isu_trustops", "credential_ref": "WORKDAY_ISU_PASSWORD"},
            2,
        ),
    ],
)
def test_fixture_sync_materializes(
    tmp_path: Path, connector_id: str, fixture: str, credentials: dict[str, str], expected: int
) -> None:
    append_config_event(tmp_path, connector_id=connector_id, state="enabled", actor="a", credentials=credentials)

    result = connector_runner.run_connector_sync(tmp_path, connector_id=connector_id, fixture_dir=FIXTURES / fixture)

    assert result.result == "ok"
    assert result.evidence_count == expected
    assert validate_raw_events(read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)) == []


@pytest.mark.parametrize("connector_id", ["rippling-personnel", "workday-personnel"])
def test_live_sync_without_config_fails_closed(tmp_path: Path, connector_id: str) -> None:
    append_config_event(tmp_path, connector_id=connector_id, state="enabled", actor="a")
    with pytest.raises(connector_runner.ConnectorSyncError):
        connector_runner.run_connector_sync(tmp_path, connector_id=connector_id)
