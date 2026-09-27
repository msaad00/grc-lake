"""Jamf Pro device-posture connector tests (fixture-backed + fake Jamf Pro API).

Fixtures follow the Jamf Pro API 11.32.0 OpenAPI definitions published at
developer.jamf.com (reference pages updated 2026-06-15 / 2026-07-13):
``GET /api/v4/computers-inventory`` (ComputerInventoryV4),
``GET /api/v2/mobile-devices/detail`` (MobileDeviceIosInventory),
``GET /api/v1/managed-software-updates/available-updates`` (AvailableOsUpdates),
and ``POST /api/v1/oauth/token`` (OAuthTokenRequest/Response).
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
from security_lakehouse import connectors_jamf, netguard
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connector_state import append_config_event, latest_run
from security_lakehouse.connectors_jamf import (
    JamfFixtureClient,
    JamfProClient,
    collect_jamf_evidence,
    normalize_base_url,
)
from security_lakehouse.ingestion.oauth import CredentialRejectedError
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "jamf"
BASE = "https://acme.jamfcloud.com"
COLLECTED = datetime(2026, 6, 3, tzinfo=UTC)
SCREEN_LOCK_EA = "Screen Lock Enforced"


def _rows(**kwargs: Any) -> list[dict[str, Any]]:
    return collect_jamf_evidence(JamfFixtureClient(FIXTURE, base_url=BASE), collected_at=COLLECTED, **kwargs)


def _event(rows: list[dict[str, Any]], asset_id: str, signal: str) -> dict[str, Any] | None:
    matches = [r for r in rows if r["entity"]["asset_id"] == asset_id and r["event_type"] == f"jamf.device.{signal}"]
    assert len(matches) <= 1
    return matches[0] if matches else None


def test_collect_emits_valid_events_mapped_to_existing_controls() -> None:
    rows = _rows(screen_lock_attribute=SCREEN_LOCK_EA)

    assert validate_raw_events(rows) == []
    assert len(rows) == 23
    catalog = load_control_catalog()
    for row in rows:
        assert row["source"] == "jamf"
        assert row["entity"]["asset_type"] == "managed_device"
        assert row["entity"]["org"] == "acme.jamfcloud.com"
        assert row["controls"]
        assert all(control in catalog for control in row["controls"]), row["controls"]
        assert row["evidence"]["evidence_ref"].startswith(f"{BASE}/api/")


def test_every_declared_control_exists_in_the_control_catalog() -> None:
    catalog = load_control_catalog()
    for controls in connectors_jamf.SIGNAL_CONTROLS.values():
        assert controls
        assert set(controls) <= set(catalog)


def test_screen_lock_for_macs_is_only_emitted_when_an_extension_attribute_is_configured() -> None:
    rows = _rows()
    assert len(rows) == 21
    assert _event(rows, "jamf:computer:1", "screen_lock") is None
    # iOS passcode state comes from inventory and needs no configuration.
    assert _event(rows, "jamf:mobile_device:101", "screen_lock") is not None


@pytest.mark.parametrize(
    ("asset_id", "signal", "status", "severity", "reason"),
    [
        ("jamf:computer:1", "encryption", "pass", "info", None),
        ("jamf:computer:2", "encryption", "open", "high", "not_encrypted"),
        ("jamf:computer:3", "encryption", "open", "low", "encryption_in_progress"),
        ("jamf:mobile_device:101", "encryption", "pass", "info", None),
        ("jamf:mobile_device:102", "encryption", "open", "high", "not_data_protected"),
        ("jamf:computer:1", "os_patch", "pass", "info", None),
        ("jamf:computer:2", "os_patch", "open", "medium", "os_update_available"),
        ("jamf:computer:3", "os_patch", "open", "high", "os_major_unsupported"),
        ("jamf:mobile_device:101", "os_patch", "pass", "info", None),
        ("jamf:mobile_device:102", "os_patch", "open", "medium", "os_update_available"),
        ("jamf:computer:1", "firewall", "pass", "info", None),
        ("jamf:computer:2", "firewall", "open", "medium", "firewall_disabled"),
        ("jamf:computer:3", "firewall", "pass", "info", None),
        ("jamf:computer:1", "screen_lock", "pass", "info", None),
        ("jamf:computer:2", "screen_lock", "open", "medium", "screen_lock_not_enforced"),
        ("jamf:mobile_device:101", "screen_lock", "pass", "info", None),
        ("jamf:mobile_device:102", "screen_lock", "open", "high", "no_passcode"),
        ("jamf:computer:1", "management", "pass", "info", None),
        ("jamf:computer:2", "management", "open", "medium", "not_checking_in"),
        ("jamf:computer:3", "management", "open", "high", "not_managed"),
        ("jamf:mobile_device:102", "management", "open", "high", "jailbroken"),
        ("jamf:mobile_device:201", "management", "pass", "info", None),
    ],
)
def test_signal_status(asset_id: str, signal: str, status: str, severity: str, reason: str | None) -> None:
    event = _event(_rows(screen_lock_attribute=SCREEN_LOCK_EA), asset_id, signal)
    assert event is not None
    assert (event["status"], event["severity"]) == (status, severity)
    assert event["attributes"]["finding_reason"] == reason


def test_signals_without_evidence_are_not_emitted() -> None:
    rows = _rows(screen_lock_attribute=SCREEN_LOCK_EA)
    # Computer 3 has no screen-lock extension attribute value.
    assert _event(rows, "jamf:computer:3", "screen_lock") is None
    # Apple TV: no data-protection/passcode inventory and no tvOS update feed.
    for signal in ("encryption", "screen_lock", "os_patch", "firewall"):
        assert _event(rows, "jamf:mobile_device:201", signal) is None
    # Firewall state only exists for computers.
    assert _event(rows, "jamf:mobile_device:101", "firewall") is None


def test_os_patch_records_the_latest_available_version() -> None:
    event = _event(_rows(), "jamf:computer:2", "os_patch")
    assert event is not None
    assert event["attributes"]["os_version"] == "15.4"
    assert event["attributes"]["latest_available_version"] == "15.6"


def test_no_update_feed_means_no_patch_verdict() -> None:
    class NoFeed(JamfFixtureClient):
        def available_updates(self) -> dict[str, list[str]] | None:
            return None

    rows = collect_jamf_evidence(NoFeed(FIXTURE, base_url=BASE), collected_at=COLLECTED)
    assert not [r for r in rows if r["event_type"] == "jamf.device.os_patch"]


def test_attributes_are_minimized() -> None:
    allowed = {
        "device_id",
        "device_kind",
        "device_type",
        "device_name",
        "user_email",
        "os_name",
        "os_version",
        "managed",
        "supervised",
        "last_contact",
        "finding_reason",
        "file_vault_status",
        "boot_partition_state",
        "data_protected",
        "latest_available_version",
        "firewall_enabled",
        "screen_lock_attribute",
        "screen_lock_value",
        "passcode_present",
        "passcode_compliant",
        "jailbroken",
    }
    serialized = json.dumps(_rows(screen_lock_attribute=SCREEN_LOCK_EA))
    for row in _rows(screen_lock_attribute=SCREEN_LOCK_EA):
        assert set(row["attributes"]) <= allowed
    for leaked in ("203.0.113.10", "555-0100", "Ada Lovelace", "10.0.0.1"):
        assert leaked not in serialized


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://acme.jamfcloud.com", "https://acme.jamfcloud.com"),
        ("https://acme.jamfcloud.com/", "https://acme.jamfcloud.com"),
        ("acme.jamfcloud.com", "https://acme.jamfcloud.com"),
        ("https://jamf.example.com:8443", "https://jamf.example.com:8443"),
    ],
)
def test_normalize_base_url(raw: str, expected: str) -> None:
    assert normalize_base_url(raw) == expected


@pytest.mark.parametrize(
    "raw", ["http://acme.jamfcloud.com", "https://acme.jamfcloud.com/api", "https://user@acme.jamfcloud.com", ""]
)
def test_normalize_base_url_rejects_unsafe_values(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_base_url(raw)


# --- live client over a fake Jamf Pro API -------------------------------------------------


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


class _FakeJamf:
    def __init__(self, *, page_size: int = 2) -> None:
        self.computers = json.loads((FIXTURE / "computers.json").read_text())
        self.mobiles = json.loads((FIXTURE / "mobile_devices.json").read_text())
        self.updates = json.loads((FIXTURE / "available_updates.json").read_text())
        self.page_size = page_size
        self.requests: list[Any] = []
        self.failures: dict[str, list[urllib.error.HTTPError]] = {}
        self.tokens = 0

    def __call__(self, request: Any, *, timeout: float, label: str) -> _FakeResponse:
        self.requests.append(request)
        parsed = urllib.parse.urlparse(request.full_url)
        assert f"{parsed.scheme}://{parsed.netloc}" == BASE
        queue = self.failures.get(parsed.path)
        if queue:
            raise queue.pop(0)
        if parsed.path == "/api/v1/oauth/token":
            self.tokens += 1
            return self._json({"access_token": f"jwt-{self.tokens}", "token_type": "Bearer", "expires_in": 1200})
        assert request.get_header("Authorization", "").startswith("Bearer jwt-")
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/api/v4/computers-inventory":
            return self._page(self.computers, query)
        if parsed.path == "/api/v2/mobile-devices/detail":
            return self._page(self.mobiles, query)
        if parsed.path == "/api/v1/managed-software-updates/available-updates":
            return self._json(self.updates)
        raise AssertionError(f"unexpected path {parsed.path}")

    def _page(self, records: list[dict[str, Any]], query: dict[str, list[str]]) -> _FakeResponse:
        page = int(query["page"][0])
        size = min(int(query["page-size"][0]), self.page_size)
        return self._json({"totalCount": len(records), "results": records[page * size : (page + 1) * size]})

    @staticmethod
    def _json(payload: Any) -> _FakeResponse:
        return _FakeResponse(json.dumps(payload).encode())


def _client(fake: _FakeJamf, monkeypatch: pytest.MonkeyPatch) -> JamfProClient:
    monkeypatch.setattr(netguard, "open_public", fake)
    return JamfProClient(BASE, client_id="client-1", client_secret="shh-secret")


def test_live_client_pages_every_inventory_and_requests_minimal_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeJamf(page_size=2)
    client = _client(fake, monkeypatch)

    assert [c["id"] for c in client.computers()] == ["1", "2", "3"]
    assert [m["mobileDeviceId"] for m in client.mobile_devices()] == ["101", "102", "201"]
    assert client.available_updates() == fake.updates["availableUpdates"]

    token_requests = [r for r in fake.requests if r.full_url.endswith("/api/v1/oauth/token")]
    assert len(token_requests) == 1
    form = urllib.parse.parse_qs(token_requests[0].data.decode())
    assert form == {"grant_type": ["client_credentials"], "client_id": ["client-1"], "client_secret": ["shh-secret"]}

    computer_calls = [
        urllib.parse.parse_qs(urllib.parse.urlparse(r.full_url).query)
        for r in fake.requests
        if "/computers-inventory" in r.full_url
    ]
    assert [q["page"] for q in computer_calls] == [["0"], ["1"]]
    sections = set(computer_calls[0]["section"])
    assert sections == {"GENERAL", "DISK_ENCRYPTION", "OPERATING_SYSTEM", "SECURITY", "USER_AND_LOCATION"}
    assert all(r.get_method() == "GET" for r in fake.requests if "oauth" not in r.full_url)


def test_live_client_requests_extension_attributes_only_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeJamf()
    client = _client(fake, monkeypatch)
    client.computers(include_extension_attributes=True)

    query = urllib.parse.parse_qs(urllib.parse.urlparse(fake.requests[1].full_url).query)
    assert "EXTENSION_ATTRIBUTES" in query["section"]


def test_live_client_retries_rate_limits_with_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    fake = _FakeJamf(page_size=100)
    path = "/api/v4/computers-inventory"
    fake.failures[path] = [_http_error(BASE + path, 429, {"Retry-After": "3"})]
    client = _client(fake, monkeypatch)

    assert len(client.computers()) == 3
    assert sleeps == [3.0]


def test_live_client_remints_the_token_once_on_401(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeJamf(page_size=100)
    path = "/api/v2/mobile-devices/detail"
    fake.failures[path] = [_http_error(BASE + path, 401)]
    client = _client(fake, monkeypatch)

    assert len(client.mobile_devices()) == 3
    assert fake.tokens == 2


def test_rejected_client_credentials_fail_closed_without_the_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeJamf()
    fake.failures["/api/v1/oauth/token"] = [_http_error(BASE + "/api/v1/oauth/token", 401)]
    client = _client(fake, monkeypatch)

    with pytest.raises(CredentialRejectedError) as excinfo:
        client.computers()
    assert "shh-secret" not in str(excinfo.value)


@pytest.mark.parametrize("code", [403, 404])
def test_missing_update_feed_privilege_skips_patch_verdict(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    fake = _FakeJamf()
    path = "/api/v1/managed-software-updates/available-updates"
    fake.failures[path] = [_http_error(BASE + path, code)]
    client = _client(fake, monkeypatch)

    assert client.available_updates() is None


def test_inventory_permission_errors_are_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeJamf()
    path = "/api/v4/computers-inventory"
    fake.failures[path] = [_http_error(BASE + path, 403)]
    client = _client(fake, monkeypatch)

    with pytest.raises(urllib.error.HTTPError):
        client.computers()


def test_pagination_stops_on_an_empty_page_even_if_total_count_lies(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeJamf(page_size=100)

    def lying_page(records: list[dict[str, Any]], query: dict[str, list[str]]) -> _FakeResponse:
        page = int(query["page"][0])
        return _FakeJamf._json({"totalCount": 999, "results": records if page == 0 else []})

    monkeypatch.setattr(fake, "_page", lying_page)
    client = _client(fake, monkeypatch)

    assert len(client.computers()) == 3


# --- runner wiring ----------------------------------------------------------------------------


def test_sync_requires_base_url_client_id_and_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("JAMF_TEST_SECRET", "JAMF_TEST_SECRET_FILE", "JAMF_CLIENT_SECRET", "JAMF_CLIENT_SECRET_FILE"):
        monkeypatch.delenv(name, raising=False)
    append_config_event(
        tmp_path,
        connector_id="jamf-devices",
        state="enabled",
        actor="alice",
        credentials={"base_url": BASE, "client_id": "client-1", "client_secret_ref": "JAMF_TEST_SECRET"},
    )

    with pytest.raises(connector_runner.ConnectorSyncError, match="client_secret_ref"):
        connector_runner.run_connector_sync(tmp_path, connector_id="jamf-devices")
    assert latest_run(tmp_path, "jamf-devices", kind="sync")["result"] == "error"


def test_fixture_sync_materializes_device_controls(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="jamf-devices",
        state="enabled",
        actor="alice",
        credentials={
            "base_url": BASE,
            "client_id": "client-1",
            "client_secret_ref": "JAMF_TEST_SECRET",
            "screen_lock_attribute": SCREEN_LOCK_EA,
        },
    )

    result = connector_runner.run_connector_sync(tmp_path, connector_id="jamf-devices", fixture_dir=FIXTURE)

    assert result.result == "ok"
    assert result.evidence_count == 23
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert {"jamf.device.encryption", "jamf.device.screen_lock"} <= {r["event_type"] for r in raw_rows}
