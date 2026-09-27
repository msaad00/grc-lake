"""KnowBe4 security-awareness connector tests (fixture-backed + fake Reporting API).

Fixture shapes follow the User, Enrollment, and PST schemas of the KnowBe4
Reporting API OpenAPI 3.0.1 spec (https://developer.knowbe4.com/elvis-swagger.yml,
retrieved 2026-09-27): enrollment ``status`` values ``Not Started``,
``In Progress``, ``Completed``, ``Passed``, ``Past Due``; PST
``phish_prone_percentage`` as a decimal; ``page``/``per_page`` (max 500) paging.
"""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import connectors_knowbe4, netguard
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connector_state import append_config_event, latest_run
from security_lakehouse.connectors_knowbe4 import (
    KNOWBE4_REGIONS,
    PER_PAGE,
    KnowBe4Client,
    KnowBe4FixtureClient,
    collect_knowbe4_evidence,
)
from security_lakehouse.ingestion.oauth import CredentialRejectedError
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "knowbe4"
COLLECTED = datetime(2026, 6, 3, tzinfo=UTC)
TOKEN = "kb4-reporting-key-do-not-log"


def _rows(fixture: Path = FIXTURE, collected_at: datetime = COLLECTED) -> list[dict[str, Any]]:
    return collect_knowbe4_evidence(KnowBe4FixtureClient(fixture, region="us"), collected_at=collected_at)


def _user_event(rows: list[dict[str, Any]], user_id: int) -> dict[str, Any]:
    matches = [r for r in rows if r["entity"]["asset_id"] == f"knowbe4:user:{user_id}"]
    assert len(matches) == 1
    return matches[0]


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [r for r in rows if r["event_type"] == "knowbe4.phishing.summary"]
    assert len(matches) == 1
    return matches[0]


def test_collect_emits_one_training_event_per_active_user_and_one_summary() -> None:
    rows = _rows()

    assert validate_raw_events(rows) == []
    # 4 active users (the archived one is excluded) + 1 phishing summary.
    assert len(rows) == 5
    assert "knowbe4:user:555001" not in {r["entity"]["asset_id"] for r in rows}
    catalog = load_control_catalog()
    for row in rows:
        assert row["source"] == "knowbe4"
        assert row["event_id"].startswith("knowbe4-")
        assert row["controls"]
        assert all(control in catalog for control in row["controls"]), row["controls"]
        assert row["evidence"]["evidence_ref"].startswith("https://us.api.knowbe4.com/v1/")
    assert {r["entity"]["asset_type"] for r in rows} == {"workforce_user", "security_awareness_program"}


def test_every_mapped_control_exists_in_the_control_catalog() -> None:
    catalog = load_control_catalog()
    for control in connectors_knowbe4.TRAINING_CONTROLS + connectors_knowbe4.PHISHING_CONTROLS:
        assert control in catalog, control


@pytest.mark.parametrize(
    ("user_id", "status", "severity", "reason"),
    [
        (667542, "pass", "info", None),  # Passed + Completed
        (796742, "open", "medium", "training_overdue"),  # one Past Due beats one Passed
        (802220, "open", "low", "training_incomplete"),  # In Progress + Not Started
        (801113, "open", "medium", "not_enrolled"),  # active user, no enrollment
    ],
)
def test_training_status(user_id: int, status: str, severity: str, reason: str | None) -> None:
    event = _user_event(_rows(), user_id)
    assert event["event_type"] == "knowbe4.user.training"
    assert (event["status"], event["severity"]) == (status, severity)
    assert event["attributes"]["finding_reason"] == reason
    assert event["controls"] == connectors_knowbe4.TRAINING_CONTROLS


def test_training_counts_and_last_completion() -> None:
    event = _user_event(_rows(), 796742)
    attrs = event["attributes"]
    assert (attrs["enrollment_count"], attrs["completed_count"], attrs["past_due_count"]) == (2, 1, 1)
    assert attrs["last_completion_date"] == "2026-01-06T09:00:00.000Z"
    assert attrs["email"] == "s_thomas@kb4-demo.com"


def test_phishing_summary_is_delivery_weighted_within_lookback() -> None:
    event = _summary(_rows())
    attrs = event["attributes"]
    # April 25% x 40 + May 10% x 60 -> 16%; the 2025 test is outside 90 days.
    assert attrs["test_count"] == 2
    assert attrs["phish_prone_percentage"] == 16.0
    assert (attrs["delivered_count"], attrs["clicked_count"]) == (100, 16)
    assert (event["status"], event["severity"]) == ("pass", "info")
    assert event["entity"]["asset_id"] == "knowbe4:account:us"
    assert event["controls"] == connectors_knowbe4.PHISHING_CONTROLS


def test_phishing_summary_opens_at_threshold(tmp_path: Path) -> None:
    tests = json.loads((FIXTURE / "phishing_security_tests.json").read_text())
    tests[1]["phish_prone_percentage"] = 0.3  # April 25% x 40 + May 30% x 60 -> 28%
    (tmp_path / "phishing_security_tests.json").write_text(json.dumps(tests))
    event = _summary(_rows(tmp_path))
    assert event["attributes"]["phish_prone_percentage"] == 28.0
    assert (event["status"], event["severity"]) == ("open", "low")
    assert event["attributes"]["finding_reason"] == "phish_prone_above_threshold"


def test_no_recent_phishing_test_is_observed_not_pass() -> None:
    event = _summary(_rows(collected_at=datetime(2027, 6, 3, tzinfo=UTC)))
    assert event["status"] == "observed"
    assert event["attributes"]["finding_reason"] == "no_recent_phishing_test"
    assert event["attributes"]["test_count"] == 0


def test_empty_fixture_emits_only_an_observed_summary(tmp_path: Path) -> None:
    rows = _rows(tmp_path)
    assert [r["event_type"] for r in rows] == ["knowbe4.phishing.summary"]
    assert rows[0]["status"] == "observed"


def test_attributes_are_minimized() -> None:
    user_allowed = {
        "user_id",
        "email",
        "employee_number",
        "enrollment_count",
        "completed_count",
        "past_due_count",
        "in_progress_count",
        "not_started_count",
        "last_completion_date",
        "phish_prone_percentage",
        "finding_reason",
    }
    summary_allowed = {
        "region",
        "lookback_days",
        "test_count",
        "delivered_count",
        "clicked_count",
        "phish_prone_percentage",
        "phish_prone_threshold",
        "latest_test_started_at",
        "finding_reason",
    }
    rows = _rows()
    for row in rows:
        allowed = summary_allowed if row["event_type"] == "knowbe4.phishing.summary" else user_allowed
        assert set(row["attributes"]) <= allowed
    serialized = json.dumps(rows)
    for leaked in ("Marcoux", "555-554-2222", "Office A", "Michael Scott", "Building 7", "Corporate Test"):
        assert leaked not in serialized


def test_event_ids_are_stable_and_unique() -> None:
    first, second = _rows(), _rows()
    assert [r["event_id"] for r in first] == [r["event_id"] for r in second]
    assert len({r["event_id"] for r in first}) == len(first)


def test_unknown_region_is_rejected() -> None:
    with pytest.raises(ValueError, match="us"):
        KnowBe4Client("ap", token=TOKEN)
    with pytest.raises(ValueError, match="expected one of"):
        KnowBe4FixtureClient(FIXTURE, region="mars")
    assert set(KNOWBE4_REGIONS) == {"us", "eu", "ca", "uk", "de"}


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _http_error(url: str, code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    message = email.message.Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return urllib.error.HTTPError(url, code, "error", message, io.BytesIO(b"{}"))


def _fake_api(monkeypatch: pytest.MonkeyPatch, responder: Any) -> list[Any]:
    seen: list[Any] = []

    def fake_open_public(request: Any, *, timeout: float, label: str) -> _FakeResponse:
        seen.append(request)
        result = responder(request)
        if isinstance(result, Exception):
            raise result
        return _FakeResponse(json.dumps(result).encode())

    monkeypatch.setattr(netguard, "open_public", fake_open_public)
    return seen


def _client(region: str = "eu") -> KnowBe4Client:
    return KnowBe4Client(region, token=TOKEN, min_interval=0)


def _query(request: Any) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)


def test_live_client_pages_until_a_short_page(monkeypatch: pytest.MonkeyPatch) -> None:
    users = [{"id": i, "email": f"u{i}@example.com", "status": "active"} for i in range(PER_PAGE * 2 + 3)]

    def responder(request: Any) -> list[dict[str, Any]]:
        page = int(_query(request)["page"][0])
        return users[(page - 1) * PER_PAGE : page * PER_PAGE]

    seen = _fake_api(monkeypatch, responder)

    assert [u["id"] for u in _client().users()] == [u["id"] for u in users]
    assert len(seen) == 3
    for index, request in enumerate(seen, start=1):
        parsed = urllib.parse.urlparse(request.full_url)
        assert (parsed.scheme, parsed.hostname, parsed.path) == ("https", "eu.api.knowbe4.com", "/v1/users")
        assert _query(request) == {"status": ["active"], "page": [str(index)], "per_page": [str(PER_PAGE)]}
        assert request.get_header("Authorization") == f"Bearer {TOKEN}"


def test_live_client_stops_on_an_empty_page(monkeypatch: pytest.MonkeyPatch) -> None:
    full_page = [{"enrollment_id": i, "status": "Passed", "user": {"id": 1}} for i in range(PER_PAGE)]
    seen = _fake_api(monkeypatch, lambda request: full_page if _query(request)["page"] == ["1"] else [])

    assert len(_client().training_enrollments()) == PER_PAGE
    assert len(seen) == 2
    assert _query(seen[0])["exclude_archived_users"] == ["true"]


def test_live_client_retries_429_honoring_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    calls = {"n": 0}

    def responder(request: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return _http_error(request.full_url, 429, {"Retry-After": "3"})
        return [{"pst_id": 1, "status": "Closed"}]

    _fake_api(monkeypatch, responder)

    assert _client().phishing_tests() == [{"pst_id": 1, "status": "Closed"}]
    assert sleeps == [3.0]


def test_live_client_paces_requests_under_the_burst_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_api(monkeypatch, lambda request: [])
    now = [100.0]
    waits: list[float] = []
    client = KnowBe4Client("us", token=TOKEN, clock=lambda: now[0], sleep=waits.append)

    client.users()
    client.users()
    assert waits == [connectors_knowbe4.MIN_REQUEST_INTERVAL_SECONDS]


@pytest.mark.parametrize("code", [401, 403])
def test_rejected_key_fails_closed_without_leaking_it(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    _fake_api(monkeypatch, lambda request: _http_error(request.full_url, code))

    with pytest.raises(CredentialRejectedError) as excinfo:
        _client().users()
    assert str(code) in str(excinfo.value)
    assert TOKEN not in str(excinfo.value)


def test_non_list_payload_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_api(monkeypatch, lambda request: {"error": "unexpected"})
    with pytest.raises(ValueError, match="non-list"):
        _client().users()


def test_client_requires_a_key() -> None:
    with pytest.raises(ValueError, match="API key"):
        KnowBe4Client("us", token="")


# --- Runner wiring (depends on connector_runner registering "knowbe4-training") ---


def test_fixture_sync_materializes_training_evidence(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="knowbe4-training",
        state="enabled",
        actor="alice",
        credentials={"region": "us", "credential_ref": "KB4_TOKEN"},
    )

    result = connector_runner.run_connector_sync(tmp_path, connector_id="knowbe4-training", fixture_dir=FIXTURE)

    assert result.result == "ok"
    assert result.evidence_count == 5
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert "FEDRAMP-AT-2" in {c for r in raw_rows for c in r["controls"]}


def test_live_sync_without_a_resolvable_key_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("KB4_TOKEN", "KB4_TOKEN_FILE", "KNOWBE4_API_TOKEN", "KNOWBE4_API_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    append_config_event(
        tmp_path,
        connector_id="knowbe4-training",
        state="enabled",
        actor="alice",
        credentials={"region": "us", "credential_ref": "KB4_TOKEN"},
    )

    with pytest.raises(connector_runner.ConnectorSyncError, match="credential_ref"):
        connector_runner.run_connector_sync(tmp_path, connector_id="knowbe4-training")
    assert latest_run(tmp_path, "knowbe4-training", kind="sync")["result"] == "error"
