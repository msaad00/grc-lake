"""Jamf Pro device-posture evidence collector (macOS and iOS/iPadOS).

Reads managed-device posture from the Jamf Pro API and emits it in the lake's
raw evidence shape. Endpoints (Jamf Pro API 11.32.0 OpenAPI, developer.jamf.com
reference pages updated 2026-06-15 / 2026-07-13):

* ``POST /api/v1/oauth/token`` — OAuth 2.0 client credentials for a Jamf Pro
  *API client* (Settings > API roles and clients). No user password is used.
* ``GET /api/v4/computers-inventory`` — computer inventory. ``v1``–``v3`` are
  deprecated (v3 since 2026-07-14). Privilege: *Read Computers*.
* ``GET /api/v2/mobile-devices/detail`` — mobile device inventory.
  Privilege: *Read Mobile Devices*.
* ``GET /api/v1/managed-software-updates/available-updates`` — the OS versions
  Apple currently offers, used as the patch baseline. Jamf documents no
  separate privilege for it; if the API client cannot read it (403/404) no OS
  patch verdict is emitted rather than guessing one.

Both inventories page with ``page``/``page-size`` (max 100) and a
``totalCount`` envelope. Every request goes only to the configured Jamf Pro
URL through ``netguard.open_public`` + ``backoff.http_retry``; the bearer token
lives in memory and is re-minted once on 401.

Data minimization: only the GENERAL, DISK_ENCRYPTION, OPERATING_SYSTEM,
SECURITY and USER_AND_LOCATION sections are requested (EXTENSION_ATTRIBUTES
only when a screen-lock attribute is configured), and from them only posture
fields plus the user's email (the join key to identity-provider users) are
kept. IP addresses, serials, usernames, real names, phone numbers, recovery
keys, and locations are dropped before anything is stored.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connectors_intune import COMPLIANCE_CONTROLS, ENCRYPTION_CONTROLS
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.oauth import ClientCredentialsToken
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json
from security_lakehouse.models import parse_event_time, utc_iso

DEFAULT_TIMEOUT = 30
PAGE_SIZE = 100
TOKEN_PATH = "/api/v1/oauth/token"
COMPUTERS_PATH = "/api/v4/computers-inventory"
MOBILE_DEVICES_PATH = "/api/v2/mobile-devices/detail"
AVAILABLE_UPDATES_PATH = "/api/v1/managed-software-updates/available-updates"
COMPUTER_SECTIONS = ("GENERAL", "DISK_ENCRYPTION", "OPERATING_SYSTEM", "SECURITY", "USER_AND_LOCATION")
MOBILE_SECTIONS = ("GENERAL", "SECURITY", "USER_AND_LOCATION")

# A managed device that has not contacted Jamf Pro for this long is not
# receiving policy, so its inventory is no longer trustworthy posture.
CHECK_IN_STALE_AFTER = timedelta(days=30)

# Controls verified to exist in controls/catalog.json. Encryption and
# management reuse the Intune sets so both MDM sources satisfy the same device
# controls.
SIGNAL_CONTROLS: dict[str, list[str]] = {
    "encryption": ENCRYPTION_CONTROLS,
    "management": [*COMPLIANCE_CONTROLS, "FEDRAMP-CM-8"],
    "os_patch": ["FEDRAMP-SI-2", "CMMC-3.14.1", "ISO27001-A.8.8", "SOC2-CC7.1", "CIS-CONTROLS-7", "NIST-CSF-PR.PS-02"],
    "screen_lock": ["FEDRAMP-AC-11", "CMMC-3.1.10", "ISO27001-A.8.1"],
    "firewall": ["FEDRAMP-CM-6", "CMMC-3.4.2", "CIS-CONTROLS-4", "ISO27001-A.8.1"],
}

ENCRYPTED_FILEVAULT_STATUSES = {"ALL_ENCRYPTED", "BOOT_ENCRYPTED"}
IN_PROGRESS_PARTITION_STATES = {"ENCRYPTING", "OPTIMIZING", "RESTART_NEEDED", "ENCRYPTING_PAUSED"}
TRUTHY_ATTRIBUTE_VALUES = {"true", "yes", "enabled", "1", "on"}
# Jamf mobile deviceType -> key in the availableUpdates feed (iPadOS reports iOS).
MOBILE_UPDATE_FEED = {"ios": "iOS"}


def normalize_base_url(raw: str) -> str:
    """Return ``https://host[:port]`` for a Jamf Pro URL, rejecting anything else."""
    value = str(raw or "").strip()
    if not value:
        raise ValueError("Jamf Pro base_url is required, e.g. https://yourcompany.jamfcloud.com")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https":
        raise ValueError("Jamf Pro base_url must use https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Jamf Pro base_url must be a bare https host without credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Jamf Pro base_url must not include a path; use https://yourcompany.jamfcloud.com")
    return f"https://{parsed.netloc}"


class JamfProClient:
    """Read-only Jamf Pro API client authenticated as an API client."""

    def __init__(
        self,
        base_url: str,
        *,
        client_id: str,
        client_secret: str,
        timeout: int = DEFAULT_TIMEOUT,
        token_source: ClientCredentialsToken | None = None,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.timeout = timeout
        self._token = token_source or ClientCredentialsToken(
            f"{self.base_url}{TOKEN_PATH}",
            form={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret},
            label="Jamf Pro",
            timeout=timeout,
        )

    def computers(self, *, include_extension_attributes: bool = False) -> list[dict[str, Any]]:
        sections = [*COMPUTER_SECTIONS, *(["EXTENSION_ATTRIBUTES"] if include_extension_attributes else [])]
        return self._paged(COMPUTERS_PATH, sections, sort="id:asc")

    def mobile_devices(self) -> list[dict[str, Any]]:
        return self._paged(MOBILE_DEVICES_PATH, list(MOBILE_SECTIONS), sort="mobileDeviceId:asc")

    def available_updates(self) -> dict[str, list[str]] | None:
        try:
            payload = self._get(AVAILABLE_UPDATES_PATH)
        except urllib.error.HTTPError as exc:
            if exc.code in {403, 404}:
                return None
            raise
        return _update_feed(payload)

    def _paged(self, path: str, sections: list[str], *, sort: str) -> list[dict[str, Any]]:
        seen = 0

        def fetch_page(page: int | None) -> tuple[int, dict[str, Any]]:
            number = page or 0
            query = urllib.parse.urlencode(
                [("section", s) for s in sections]
                + [("page", str(number)), ("page-size", str(PAGE_SIZE)), ("sort", sort)]
            )
            payload = self._get(f"{path}?{query}")
            if not isinstance(payload, dict):
                raise ValueError(f"Jamf Pro returned non-object JSON for {path}")
            return number, payload

        def extract_items(page: tuple[int, dict[str, Any]]) -> list[dict[str, Any]]:
            nonlocal seen
            items = [item for item in page[1].get("results") or [] if isinstance(item, dict)]
            seen += len(items)
            return items

        def next_cursor(page: tuple[int, dict[str, Any]]) -> int | None:
            number, payload = page
            results = payload.get("results") or []
            total = int(payload.get("totalCount") or 0)
            if not results or seen >= total:
                return None
            return number + 1

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _get(self, path_and_query: str) -> Any:
        url = f"{self.base_url}{path_and_query}"

        def call(token: str) -> Any:
            request = urllib.request.Request(
                url,
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {token}",
                    "user-agent": "trustops-security-data-lake",
                },
            )
            return backoff.http_retry(lambda: self._open(request))

        return self._token.call_with_bearer(call)

    def _open(self, request: urllib.request.Request) -> Any:
        with netguard.open_public(request, timeout=self.timeout, label="jamf pro") as resp:
            return json.loads(resp.read().decode("utf-8"))


class JamfFixtureClient:
    """Offline Jamf Pro client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, base_url: str) -> None:
        self.fixture = Path(fixture_dir)
        self.base_url = normalize_base_url(base_url)

    def computers(self, *, include_extension_attributes: bool = False) -> list[dict[str, Any]]:
        return self._records("computers.json")

    def mobile_devices(self) -> list[dict[str, Any]]:
        return self._records("mobile_devices.json")

    def available_updates(self) -> dict[str, list[str]] | None:
        path = self.fixture / "available_updates.json"
        return _update_feed(read_json(path)) if path.exists() else None

    def _records(self, name: str) -> list[dict[str, Any]]:
        path = self.fixture / name
        payload = read_json(path) if path.exists() else []
        return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _update_feed(payload: Any) -> dict[str, list[str]] | None:
    feed = payload.get("availableUpdates") if isinstance(payload, dict) else None
    if not isinstance(feed, dict):
        return None
    return {str(k): [str(v) for v in values] for k, values in feed.items() if isinstance(values, list)}


def collect_jamf_evidence(
    client: JamfProClient | JamfFixtureClient,
    *,
    screen_lock_attribute: str | None = None,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Emit per-device encryption, management, OS patch, screen lock, and firewall events."""
    now = collected_at or datetime.now(UTC)
    attribute = (screen_lock_attribute or "").strip() or None
    updates = client.available_updates()
    ctx = _Context(client.base_url, now, tenant_id)
    rows: list[dict[str, Any]] = []
    for computer in client.computers(include_extension_attributes=attribute is not None):
        rows.extend(_computer_events(ctx, computer, updates, attribute))
    for device in client.mobile_devices():
        rows.extend(_mobile_events(ctx, device, updates))
    return rows


class _Context:
    def __init__(self, base_url: str, collected_at: datetime, tenant_id: str) -> None:
        self.base_url = base_url
        self.org = urllib.parse.urlparse(base_url).netloc
        self.collected_at = collected_at
        self.tenant_id = tenant_id


def _computer_events(
    ctx: _Context, computer: dict[str, Any], updates: dict[str, list[str]] | None, screen_lock_attribute: str | None
) -> list[dict[str, Any]]:
    device_id = str(computer.get("id") or "").strip()
    if not device_id:
        return []
    general = _obj(computer.get("general"))
    disk = _obj(computer.get("diskEncryption"))
    os_info = _obj(computer.get("operatingSystem"))
    security = _obj(computer.get("security"))
    user = _obj(computer.get("userAndLocation"))
    base = {
        "device_id": device_id,
        "device_kind": "computer",
        "device_type": general.get("platform") or "Mac",
        "device_name": general.get("name"),
        "user_email": user.get("email") or None,
        "os_name": os_info.get("name") or "macOS",
        "os_version": os_info.get("version"),
        "managed": _obj(general.get("remoteManagement")).get("managed") is True,
        "supervised": general.get("supervised"),
        "last_contact": general.get("lastContact"),
    }
    device = _Device(ctx, "computer", device_id, f"{COMPUTERS_PATH}?filter=id%3D%3D{device_id}", base)

    events = [
        _computer_encryption(device, os_info, disk),
        _management(device, jailbroken=False),
    ]
    patch = _os_patch(device, (updates or {}).get("macOS") if updates is not None else None)
    if patch:
        events.append(patch)
    if "firewallEnabled" in security:
        enabled = security.get("firewallEnabled") is True
        events.append(
            device.event(
                "firewall",
                ("pass", "info", None) if enabled else ("open", "medium", "firewall_disabled"),
                {"firewall_enabled": enabled},
            )
        )
    if screen_lock_attribute:
        value = _extension_attribute(computer, screen_lock_attribute)
        if value is not None:
            enforced = value.strip().lower() in TRUTHY_ATTRIBUTE_VALUES
            events.append(
                device.event(
                    "screen_lock",
                    ("pass", "info", None) if enforced else ("open", "medium", "screen_lock_not_enforced"),
                    {"screen_lock_attribute": screen_lock_attribute, "screen_lock_value": value},
                )
            )
    return events


def _mobile_events(ctx: _Context, mobile: dict[str, Any], updates: dict[str, list[str]] | None) -> list[dict[str, Any]]:
    device_id = str(mobile.get("mobileDeviceId") or "").strip()
    if not device_id:
        return []
    general = _obj(mobile.get("general"))
    security = _obj(mobile.get("security"))
    user = _obj(mobile.get("userAndLocation"))
    device_type = str(mobile.get("deviceType") or "")
    base = {
        "device_id": device_id,
        "device_kind": "mobile_device",
        "device_type": device_type or None,
        "device_name": general.get("displayName"),
        "user_email": user.get("emailAddress") or None,
        "os_name": device_type or None,
        "os_version": general.get("osVersion"),
        "managed": general.get("managed") is True,
        "supervised": general.get("supervised"),
        "last_contact": general.get("lastContactDate"),
    }
    device = _Device(ctx, "mobile_device", device_id, f"/api/v2/mobile-devices/{device_id}/detail", base)
    events = [_management(device, jailbroken=security.get("jailBreakDetected") is True)]

    if "dataProtected" in security:
        protected = security.get("dataProtected") is True
        events.append(
            device.event(
                "encryption",
                ("pass", "info", None) if protected else ("open", "high", "not_data_protected"),
                {"data_protected": protected},
            )
        )
    if "passcodePresent" in security:
        present = security.get("passcodePresent") is True
        compliant = security.get("passcodeCompliant") is True
        if not present:
            verdict = ("open", "high", "no_passcode")
        elif not compliant:
            verdict = ("open", "medium", "passcode_noncompliant")
        else:
            verdict = ("pass", "info", None)
        events.append(
            device.event("screen_lock", verdict, {"passcode_present": present, "passcode_compliant": compliant})
        )
    feed_key = MOBILE_UPDATE_FEED.get(device_type.lower())
    if feed_key and updates is not None:
        patch = _os_patch(device, updates.get(feed_key))
        if patch:
            events.append(patch)
    return events


def _computer_encryption(device: _Device, os_info: dict[str, Any], disk: dict[str, Any]) -> dict[str, Any]:
    status = str(os_info.get("fileVault2Status") or "")
    partition = str(_obj(disk.get("bootPartitionEncryptionDetails")).get("partitionFileVault2State") or "")
    if status in ENCRYPTED_FILEVAULT_STATUSES or partition == "ENCRYPTED":
        verdict = ("pass", "info", None)
    elif partition in IN_PROGRESS_PARTITION_STATES:
        verdict = ("open", "low", "encryption_in_progress")
    elif status == "SOME_ENCRYPTED":
        verdict = ("open", "medium", "partially_encrypted")
    elif status == "NOT_ENCRYPTED" or partition in {"UNENCRYPTED", "DECRYPTED", "DECRYPTING"}:
        verdict = ("open", "high", "not_encrypted")
    else:
        verdict = ("open", "medium", "encryption_not_reported")
    return device.event(
        "encryption", verdict, {"file_vault_status": status or None, "boot_partition_state": partition or None}
    )


def _management(device: _Device, *, jailbroken: bool) -> dict[str, Any]:
    last_contact = _parse_time(device.base.get("last_contact"))
    if jailbroken:
        verdict = ("open", "high", "jailbroken")
    elif not device.base["managed"]:
        verdict = ("open", "high", "not_managed")
    elif last_contact is None:
        verdict = ("open", "medium", "check_in_not_reported")
    elif device.ctx.collected_at - last_contact > CHECK_IN_STALE_AFTER:
        verdict = ("open", "medium", "not_checking_in")
    else:
        verdict = ("pass", "info", None)
    return device.event("management", verdict, {"jailbroken": jailbroken})


def _os_patch(device: _Device, available: list[str] | None) -> dict[str, Any] | None:
    current = _version(device.base.get("os_version"))
    versions = sorted({v for v in (_version(a) for a in available or []) if v})
    if not current or not versions:
        return None
    same_major = [v for v in versions if v[0] == current[0]]
    if same_major:
        latest = same_major[-1]
        verdict = ("pass", "info", None) if current >= latest else ("open", "medium", "os_update_available")
    elif current[0] < versions[0][0]:
        latest = versions[-1]
        verdict = ("open", "high", "os_major_unsupported")
    else:
        # Newer than anything Apple is offering (e.g. a beta): nothing to patch to.
        latest = current
        verdict = ("pass", "info", None)
    return device.event("os_patch", verdict, {"latest_available_version": ".".join(str(p) for p in latest)})


class _Device:
    def __init__(self, ctx: _Context, kind: str, device_id: str, ref_path: str, base: dict[str, Any]) -> None:
        self.ctx = ctx
        self.kind = kind
        self.device_id = device_id
        self.ref_path = ref_path
        self.base = base

    def event(self, signal: str, verdict: tuple[str, str, str | None], extra: dict[str, Any]) -> dict[str, Any]:
        status, severity, reason = verdict
        stable = re.sub(r"[^a-z0-9_.:-]+", "-", f"{self.ctx.org}:{signal}:{self.kind}:{self.device_id}".lower()).strip(
            "-"
        )[:120]
        return {
            "event_id": f"jamf-{stable}",
            "tenant_id": self.ctx.tenant_id,
            "workspace_id": "default",
            "event_time": utc_iso(self.ctx.collected_at),
            "source": "jamf",
            "event_type": f"jamf.device.{signal}",
            "entity": {
                "asset_id": f"jamf:{self.kind}:{self.device_id}",
                "asset_type": "managed_device",
                "asset_owner": self.ctx.org,
                "environment": "prod",
                "org": self.ctx.org,
            },
            "severity": severity,
            "status": status,
            "controls": list(SIGNAL_CONTROLS[signal]),
            "evidence": {
                "evidence_id": f"ev-{stable}",
                "evidence_ref": f"{self.ctx.base_url}{self.ref_path}",
                "evidence_collected_at": utc_iso(self.ctx.collected_at),
            },
            "attributes": {**self.base, **extra, "finding_reason": reason},
        }


def _extension_attribute(computer: dict[str, Any], name: str) -> str | None:
    wanted = name.strip().lower()
    pools = [computer.get("extensionAttributes"), _obj(computer.get("general")).get("extensionAttributes")]
    for pool in pools:
        for attribute in pool or []:
            if isinstance(attribute, dict) and str(attribute.get("name") or "").strip().lower() == wanted:
                values = [str(v) for v in attribute.get("values") or [] if str(v).strip()]
                return values[0] if values else None
    return None


def _version(raw: Any) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in str(raw or "").strip().split("."):
        match = re.match(r"\d+", piece)
        if not match:
            break
        parts.append(int(match.group()))
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _parse_time(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return parse_event_time(str(raw))
    except (TypeError, ValueError):
        return None


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
