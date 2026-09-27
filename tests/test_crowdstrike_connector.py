"""CrowdStrike Falcon connector tests (fixture-backed + fake Falcon API).

Fixture and fake-API shapes follow the Falcon API as documented by the
CrowdStrike-maintained FalconPy SDK endpoint modules (``main``, checked
2026-09-27) and developer.crowdstrike.com/api-reference/collections/{hosts,
prevention-policies,alerts}: the ``meta``/``resources``/``errors`` envelope,
``GET /devices/queries/devices-scroll/v1`` (opaque ``meta.pagination.offset``),
``POST /devices/entities/devices/v2`` (``{"ids": [...]}``),
``GET /policy/combined/prevention/v1`` (integer offset/total), and
``POST /alerts/combined/alerts/v1`` (``meta.pagination.after`` cursor).
"""

from __future__ import annotations

import email.message
import io
import json
import time
import urllib.error
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import connectors_crowdstrike, netguard
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connector_state import append_config_event, latest_run
from security_lakehouse.connectors_crowdstrike import (
    ALERTS_COMBINED_PATH,
    HOST_DETAILS_PATH,
    HOST_SCROLL_PATH,
    PREVENTION_POLICIES_PATH,
    CrowdStrikeClient,
    CrowdStrikeFixtureClient,
    collect_crowdstrike_evidence,
    crowdstrike_retry_after,
)
from security_lakehouse.ingestion.oauth import CredentialRejectedError
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "crowdstrike"
COLLECTED = datetime(2026, 6, 3, tzinfo=UTC)
HOST = "api.crowdstrike.com"

HEALTHY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
STALE = "b2c3d4e5f60718293a4b5c6d7e8f90a1"
RFM = "c3d4e5f60718293a4b5c6d7e8f90a1b2"
NO_TELEMETRY = "d4e5f60718293a4b5c6d7e8f90a1b2c3"
NOT_APPLIED = "e5f60718293a4b5c6d7e8f90a1b2c3d4"


def _rows() -> list[dict[str, Any]]:
    return collect_crowdstrike_evidence(CrowdStrikeFixtureClient(FIXTURE, cloud="us-1"), collected_at=COLLECTED)


def _event(rows: list[dict[str, Any]], device_id: str, signal: str) -> dict[str, Any]:
    matches = [
        r
        for r in rows
        if r["entity"]["asset_id"] == f"crowdstrike:host:{device_id}" and r["event_type"] == f"crowdstrike.{signal}"
    ]
    assert len(matches) == 1
    return matches[0]


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [r for r in rows if r["event_type"] == "crowdstrike.detections.summary"]
    assert len(matches) == 1
    return matches[0]


def test_collect_emits_sensor_and_prevention_per_host_plus_one_summary() -> None:
    rows = _rows()

    assert validate_raw_events(rows) == []
    assert len(rows) == 5 * 2 + 1
    catalog = load_control_catalog()
    for row in rows:
        assert row["source"] == "crowdstrike"
        assert row["event_id"].startswith("crowdstrike-")
        assert row["controls"]
        assert all(control in catalog for control in row["controls"])
        assert row["evidence"]["evidence_ref"].startswith(f"https://{HOST}/")
    assert _rows() == rows  # stable event ids and content


def test_every_mapped_control_exists_in_the_control_catalog() -> None:
    catalog = load_control_catalog()
    for controls in (
        connectors_crowdstrike.SENSOR_CONTROLS,
        connectors_crowdstrike.PREVENTION_CONTROLS,
        connectors_crowdstrike.DETECTION_CONTROLS,
    ):
        assert set(controls) <= set(catalog)


@pytest.mark.parametrize(
    ("device_id", "status", "severity", "reason"),
    [
        (HEALTHY, "pass", "info", None),
        (STALE, "open", "medium", "sensor_not_reporting"),
        (RFM, "open", "high", "reduced_functionality_mode"),
        (NO_TELEMETRY, "open", "medium", "last_seen_not_reported"),
        (NOT_APPLIED, "pass", "info", None),
    ],
)
def test_sensor_status(device_id: str, status: str, severity: str, reason: str | None) -> None:
    event = _event(_rows(), device_id, "host.sensor")
    assert (event["status"], event["severity"], event["attributes"]["finding_reason"]) == (status, severity, reason)
    assert event["entity"]["asset_type"] == "endpoint_host"


@pytest.mark.parametrize(
    ("device_id", "status", "reason"),
    [
        (HEALTHY, "pass", None),
        (STALE, "pass", None),
        (RFM, "open", "policy_disabled"),
        (NO_TELEMETRY, "open", "no_prevention_policy"),
        (NOT_APPLIED, "open", "policy_not_applied"),
    ],
)
def test_prevention_policy_status(device_id: str, status: str, reason: str | None) -> None:
    event = _event(_rows(), device_id, "host.prevention_policy")
    assert event["status"] == status
    assert event["severity"] == ("info" if status == "pass" else "high")
    assert event["attributes"]["finding_reason"] == reason


def test_prevention_policy_missing_from_policy_list_is_open(tmp_path: Path) -> None:
    hosts = json.loads((FIXTURE / "hosts.json").read_text())
    (tmp_path / "hosts.json").write_text(json.dumps(hosts))
    (tmp_path / "prevention_policies.json").write_text("[]")
    rows = collect_crowdstrike_evidence(CrowdStrikeFixtureClient(tmp_path, cloud="us-1"), collected_at=COLLECTED)
    assert _event(rows, HEALTHY, "host.prevention_policy")["attributes"]["finding_reason"] == "policy_not_found"


def test_detection_summary_counts_only_unresolved_alerts() -> None:
    event = _summary(_rows())
    counts = event["attributes"]["unresolved_alert_counts"]
    assert counts == {"critical": 0, "high": 1, "medium": 0, "low": 1, "informational": 0}
    assert (event["status"], event["severity"]) == ("open", "high")
    assert event["attributes"]["host_count"] == 5
    assert event["entity"]["asset_id"] == "crowdstrike:tenant:us-1"


@pytest.mark.parametrize(
    ("alerts", "status", "severity"),
    [
        ([], "pass", "info"),
        ([{"status": "new", "severity": 55}], "open", "medium"),
        ([{"status": "reopened", "severity": 92}], "open", "high"),
        ([{"status": "in_progress", "severity_name": "Low"}], "pass", "info"),
        ([{"status": "closed", "severity_name": "Critical"}], "pass", "info"),
    ],
)
def test_detection_summary_thresholds(tmp_path: Path, alerts: list[dict[str, Any]], status: str, severity: str) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps(alerts))
    event = _summary(
        collect_crowdstrike_evidence(CrowdStrikeFixtureClient(tmp_path, cloud="eu-1"), collected_at=COLLECTED)
    )
    assert (event["status"], event["severity"]) == (status, severity)


def test_empty_tenant_still_reports_a_summary(tmp_path: Path) -> None:
    rows = collect_crowdstrike_evidence(CrowdStrikeFixtureClient(tmp_path, cloud="us-2"), collected_at=COLLECTED)
    assert len(rows) == 1
    assert rows[0]["attributes"]["host_count"] == 0
    assert rows[0]["evidence"]["evidence_ref"].startswith("https://api.us-2.crowdstrike.com/")


def test_attributes_are_minimized() -> None:
    allowed = {
        "device_id",
        "hostname",
        "platform",
        "os_version",
        "product_type",
        "agent_version",
        "first_seen",
        "last_seen",
        "containment_status",
        "reduced_functionality_mode",
        "prevention_policy_id",
        "prevention_policy_name",
        "prevention_policy_applied",
        "prevention_policy_enabled",
        "cloud",
        "lookback_days",
        "unresolved_alert_counts",
        "unresolved_alert_total",
        "host_count",
        "finding_reason",
    }
    rows = _rows()
    for row in rows:
        assert set(row["attributes"]) <= allowed
    blob = json.dumps(rows)
    for leaked in ("10.20.4.17", "203.0.113.40", "3c-22-fb-10-aa-01", "5CG1234XYZ", "jdoe"):
        assert leaked not in blob


def test_unknown_cloud_is_rejected() -> None:
    with pytest.raises(ValueError, match="us-1"):
        CrowdStrikeClient("mars-1", client_id="c", client_secret="s")
    with pytest.raises(ValueError, match="eu-1"):
        CrowdStrikeFixtureClient(FIXTURE, cloud="")


# --- live client over a fake Falcon API -------------------------------------------------


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


class _FakeFalcon:
    """Routes requests by (method, path) to queued responses and records them."""

    def __init__(self, routes: dict[tuple[str, str], list[Any]]) -> None:
        self.routes = routes
        self.seen: list[Any] = []

    def __call__(self, request: Any, *, timeout: float, label: str) -> _FakeResponse:
        self.seen.append(request)
        parsed = urllib.parse.urlparse(request.full_url)
        assert parsed.scheme == "https"
        assert parsed.hostname == HOST
        queue = self.routes[(request.get_method(), parsed.path)]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return _FakeResponse(json.dumps(item).encode())

    def calls(self, path: str) -> list[Any]:
        return [r for r in self.seen if urllib.parse.urlparse(r.full_url).path == path]


def _hosts_fixture() -> list[dict[str, Any]]:
    return json.loads((FIXTURE / "hosts.json").read_text())["resources"]


def _default_routes() -> dict[tuple[str, str], list[Any]]:
    hosts = _hosts_fixture()
    ids = [h["device_id"] for h in hosts]
    return {
        ("POST", "/oauth2/token"): [{"access_token": "falcon-token", "expires_in": 1799, "token_type": "bearer"}],
        ("GET", HOST_SCROLL_PATH): [
            {"meta": {"pagination": {"offset": "scroll-1", "total": 5}}, "resources": ids[:3]},
            {"meta": {"pagination": {"offset": "scroll-2", "total": 5}}, "resources": ids[3:]},
        ],
        ("POST", HOST_DETAILS_PATH): [{"meta": {}, "resources": hosts, "errors": []}],
        ("GET", PREVENTION_POLICIES_PATH): [json.loads((FIXTURE / "prevention_policies.json").read_text())],
        ("POST", ALERTS_COMBINED_PATH): [
            {
                "meta": {"pagination": {"after": "cursor-2", "total": 3}},
                "resources": [{"status": "new", "severity": 70}],
            },
            {"meta": {"pagination": {"total": 3}}, "resources": [{"status": "new", "severity": 20}]},
        ],
    }


def _client() -> CrowdStrikeClient:
    return CrowdStrikeClient("us-1", client_id="falcon-client", client_secret="falcon-secret-value")


def test_live_client_exchanges_client_credentials_and_sends_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeFalcon(_default_routes())
    monkeypatch.setattr(netguard, "open_public", fake)

    rows = collect_crowdstrike_evidence(_client(), collected_at=COLLECTED)

    assert validate_raw_events(rows) == []
    token_calls = fake.calls("/oauth2/token")
    assert len(token_calls) == 1
    assert urllib.parse.parse_qs(token_calls[0].data.decode()) == {
        "client_id": ["falcon-client"],
        "client_secret": ["falcon-secret-value"],
    }
    api_calls = [r for r in fake.seen if urllib.parse.urlparse(r.full_url).path != "/oauth2/token"]
    assert api_calls
    assert all(r.get_header("Authorization") == "Bearer falcon-token" for r in api_calls)


def test_live_client_scrolls_hosts_and_fetches_details_in_one_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeFalcon(_default_routes())
    monkeypatch.setattr(netguard, "open_public", fake)

    hosts = _client().hosts()

    assert [h["device_id"] for h in hosts] == [h["device_id"] for h in _hosts_fixture()]
    scrolls = fake.calls(HOST_SCROLL_PATH)
    assert len(scrolls) == 2
    first_query = urllib.parse.parse_qs(urllib.parse.urlparse(scrolls[0].full_url).query)
    second_query = urllib.parse.parse_qs(urllib.parse.urlparse(scrolls[1].full_url).query)
    assert "offset" not in first_query
    assert second_query["offset"] == ["scroll-1"]
    details = fake.calls(HOST_DETAILS_PATH)
    assert len(details) == 1
    assert json.loads(details[0].data)["ids"] == [h["device_id"] for h in _hosts_fixture()]
    # MAC/IP/serial/user are dropped at the client, not only at event build.
    assert not {"mac_address", "local_ip", "external_ip", "serial_number", "last_login_user"} & set(hosts[0])


def test_live_client_batches_host_details(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(connectors_crowdstrike, "HOST_DETAILS_BATCH", 2)
    fake = _FakeFalcon(_default_routes())
    monkeypatch.setattr(netguard, "open_public", fake)

    _client().hosts()

    batches = [json.loads(r.data)["ids"] for r in fake.calls(HOST_DETAILS_PATH)]
    assert [len(b) for b in batches] == [2, 2, 1]


def test_live_client_pages_prevention_policies_by_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = _default_routes()
    routes[("GET", PREVENTION_POLICIES_PATH)] = [
        {"meta": {"pagination": {"offset": 0, "limit": 2, "total": 3}}, "resources": [{"id": "p1"}, {"id": "p2"}]},
        {"meta": {"pagination": {"offset": 2, "limit": 2, "total": 3}}, "resources": [{"id": "p3", "enabled": True}]},
    ]
    fake = _FakeFalcon(routes)
    monkeypatch.setattr(netguard, "open_public", fake)

    policies = _client().prevention_policies()

    assert [p["id"] for p in policies] == ["p1", "p2", "p3"]
    offsets = [
        urllib.parse.parse_qs(urllib.parse.urlparse(r.full_url).query)["offset"]
        for r in fake.calls(PREVENTION_POLICIES_PATH)
    ]
    assert offsets == [["0"], ["2"]]


def test_live_client_follows_alert_after_cursor_with_bounded_unresolved_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeFalcon(_default_routes())
    monkeypatch.setattr(netguard, "open_public", fake)

    alerts = _client().alerts(now=COLLECTED)

    assert len(alerts) == 2
    bodies = [json.loads(r.data) for r in fake.calls(ALERTS_COMBINED_PATH)]
    assert "after" not in bodies[0]
    assert bodies[1]["after"] == "cursor-2"
    assert bodies[0]["filter"] == "status:!'closed'+created_timestamp:>='2026-05-04T00:00:00Z'"
    assert bodies[0]["limit"] == 1000


def test_live_client_honors_x_ratelimit_retryafter(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    monkeypatch.setattr(time, "time", lambda: 1_780_000_000.0)
    routes = _default_routes()
    routes[("GET", PREVENTION_POLICIES_PATH)] = [
        _http_error(f"https://{HOST}{PREVENTION_POLICIES_PATH}", 429, {"X-RateLimit-RetryAfter": "1780000003"}),
        {"meta": {"pagination": {"offset": 0, "total": 1}}, "resources": [{"id": "p1"}]},
    ]
    monkeypatch.setattr(netguard, "open_public", _FakeFalcon(routes))

    assert [p["id"] for p in _client().prevention_policies()] == ["p1"]
    assert sleeps == [3.0]


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"X-RateLimit-RetryAfter": "1780000005"}, 5.0),
        ({"X-RateLimit-RetryAfter": "1780000002000"}, 2.0),
        ({"X-RateLimit-RetryAfter": "1779999990"}, 0.0),
        ({"Retry-After": "7"}, 7.0),
        ({}, None),
    ],
)
def test_retry_after_extractor(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str], expected: float | None
) -> None:
    monkeypatch.setattr(time, "time", lambda: 1_780_000_000.0)
    assert crowdstrike_retry_after(_http_error("https://x", 429, headers)) == expected


def test_rejected_client_credentials_fail_closed_without_leaking_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = _default_routes()
    routes[("POST", "/oauth2/token")] = [_http_error(f"https://{HOST}/oauth2/token", 401)]
    monkeypatch.setattr(netguard, "open_public", _FakeFalcon(routes))

    with pytest.raises(CredentialRejectedError) as excinfo:
        _client().prevention_policies()
    assert "CrowdStrike" in str(excinfo.value)
    assert "falcon-secret-value" not in str(excinfo.value)


def test_api_401_re_mints_the_token_once(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = _default_routes()
    routes[("POST", "/oauth2/token")] = [{"access_token": "old", "expires_in": 1799}, {"access_token": "new"}]
    routes[("GET", PREVENTION_POLICIES_PATH)] = [
        _http_error(f"https://{HOST}{PREVENTION_POLICIES_PATH}", 401),
        {"meta": {"pagination": {"offset": 0, "total": 1}}, "resources": [{"id": "p1"}]},
    ]
    fake = _FakeFalcon(routes)
    monkeypatch.setattr(netguard, "open_public", fake)

    assert [p["id"] for p in _client().prevention_policies()] == ["p1"]
    assert [r.get_header("Authorization") for r in fake.calls(PREVENTION_POLICIES_PATH)] == [
        "Bearer old",
        "Bearer new",
    ]


def test_non_retryable_api_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = _default_routes()
    routes[("GET", PREVENTION_POLICIES_PATH)] = [_http_error(f"https://{HOST}{PREVENTION_POLICIES_PATH}", 403)]
    monkeypatch.setattr(netguard, "open_public", _FakeFalcon(routes))

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _client().prevention_policies()
    assert excinfo.value.code == 403


@pytest.mark.parametrize(
    ("cloud", "host"),
    [
        ("us-2", "api.us-2.crowdstrike.com"),
        ("EU-1", "api.eu-1.crowdstrike.com"),
        ("us-gov-1", "api.laggar.gcw.crowdstrike.com"),
        ("us-gov-2", "api.us-gov-2.crowdstrike.mil"),
    ],
)
def test_cloud_selects_the_regional_api_host(cloud: str, host: str) -> None:
    client = CrowdStrikeClient(cloud, client_id="c", client_secret="s")
    assert client.host == host
    assert client._token.token_url == f"https://{host}/oauth2/token"  # noqa: SLF001


# --- runner wiring (depends on connector_runner registering "crowdstrike-falcon") -------


def test_fixture_sync_materializes_crowdstrike_evidence(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="crowdstrike-falcon",
        state="enabled",
        actor="alice",
        credentials={"cloud": "us-1", "client_id": "x", "client_secret_ref": "CS_SECRET"},
    )

    result = connector_runner.run_connector_sync(tmp_path, connector_id="crowdstrike-falcon", fixture_dir=FIXTURE)

    assert result.result == "ok"
    assert result.evidence_count == 11
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert "SOC2-CC6.8" in {c for r in raw_rows for c in r["controls"]}


def test_live_sync_without_secret_fails_naming_client_secret_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("CS_SECRET", raising=False)
    append_config_event(
        tmp_path,
        connector_id="crowdstrike-falcon",
        state="enabled",
        actor="alice",
        credentials={"cloud": "us-1", "client_id": "x", "client_secret_ref": "CS_SECRET"},
    )

    with pytest.raises(connector_runner.ConnectorSyncError, match="client_secret_ref"):
        connector_runner.run_connector_sync(tmp_path, connector_id="crowdstrike-falcon")
    assert latest_run(tmp_path, "crowdstrike-falcon", kind="sync")["result"] == "error"
