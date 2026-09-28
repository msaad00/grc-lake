"""Microsoft Intune device-posture evidence collector.

Collects read-only managed-device posture — disk encryption, compliance state,
and jailbreak/root detection — from Microsoft Graph
``GET /deviceManagement/managedDevices`` and emits it in the lake's raw
evidence shape.

Two clients sit behind one interface, mirroring ``connectors_azure``:

* :class:`IntuneClient` — bearer-authenticated ``urllib`` reads against
  Microsoft Graph v1.0. The token comes from ``DefaultAzureCredential`` (the
  same identity model ``azure-posture`` uses) scoped to Graph, so no stored
  secret is needed. Requires the application permission
  ``DeviceManagementManagedDevices.Read.All``.
* :class:`IntuneFixtureClient` — reads ``managed_devices.json`` from a fixture
  directory.

Data minimization: the list request uses ``$select`` for posture fields only,
so hardware identifiers (IMEI, serial, MAC), phone numbers, display names, and
admin notes are never fetched. ``userPrincipalName`` is kept as the join key to
identity-provider users.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json
from security_lakehouse.models import utc_iso

GRAPH_HOST = "graph.microsoft.com"
GRAPH_SCOPE = f"https://{GRAPH_HOST}/.default"
SELECT_FIELDS = (
    "id",
    "deviceName",
    "userPrincipalName",
    "operatingSystem",
    "osVersion",
    "isEncrypted",
    "complianceState",
    "jailBroken",
    "lastSyncDateTime",
    "enrolledDateTime",
    "managedDeviceOwnerType",
    "managementAgent",
    "azureADDeviceId",
    "isSupervised",
)
GRAPH_MANAGED_DEVICES_URL = (
    f"https://{GRAPH_HOST}/v1.0/deviceManagement/managedDevices?$select={','.join(SELECT_FIELDS)}"
)
DEFAULT_TIMEOUT = 20

# Controls verified to exist in controls/catalog.json.
ENCRYPTION_CONTROLS = ["FEDRAMP-AC-19.5", "CMMC-3.1.19", "ISO27001-A.8.1"]
COMPLIANCE_CONTROLS = ["FEDRAMP-AC-19", "CMMC-3.1.18", "SOC2-CC6.8", "ISO27001-A.8.1"]

# Graph complianceState values that are a policy failure, not merely unknown.
FAILED_COMPLIANCE_STATES = {"noncompliant", "conflict", "error"}


class IntuneClient:
    """Authenticated, read-only Microsoft Graph client for Intune devices."""

    def __init__(
        self,
        tenant_id: str,
        *,
        token_provider: Callable[[], str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.tenant_id = tenant_id
        self.timeout = timeout
        self._token_provider = token_provider or _default_credential_token(tenant_id)

    def managed_devices(self) -> list[dict[str, Any]]:
        def fetch_page(url: str | None) -> dict[str, Any]:
            page_url = url or GRAPH_MANAGED_DEVICES_URL
            payload = backoff.http_retry(lambda: self._get_json(page_url))
            if not isinstance(payload, dict):
                raise ValueError("Microsoft Graph returned non-object JSON for managedDevices")
            return payload

        def extract_items(page: dict[str, Any]) -> list[dict[str, Any]]:
            return [item for item in page.get("value", []) if isinstance(item, dict)]

        def next_cursor(page: dict[str, Any]) -> str | None:
            next_link = str(page.get("@odata.nextLink") or "")
            if not next_link:
                return None
            # The bearer token is only ever sent to Graph; a nextLink pointing
            # anywhere else would hand it to that host.
            parsed = urllib.parse.urlparse(next_link)
            if parsed.scheme != "https" or parsed.hostname != GRAPH_HOST:
                raise ValueError(f"refusing @odata.nextLink outside https://{GRAPH_HOST}")
            return next_link

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _get_json(self, url: str) -> Any:
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self._token_provider()}",
                "user-agent": "trustops-security-data-lake",
            },
        )
        with netguard.open_public(request, timeout=self.timeout, label="microsoft graph") as resp:
            return json.loads(resp.read().decode("utf-8"))


def _default_credential_token(tenant_id: str) -> Callable[[], str]:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only with live Graph
        raise RuntimeError(
            "intune-devices live collection requires azure-identity; install the cloud extra or use --fixture-dir"
        ) from exc
    credential = DefaultAzureCredential()
    return lambda: str(credential.get_token(GRAPH_SCOPE, tenant_id=tenant_id).token)


class IntuneFixtureClient:
    """Offline Intune client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, tenant_id: str) -> None:
        self.fixture = Path(fixture_dir)
        self.tenant_id = tenant_id

    def managed_devices(self) -> list[dict[str, Any]]:
        path = self.fixture / "managed_devices.json"
        payload = read_json(path) if path.exists() else []
        return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def collect_intune_evidence(
    client: IntuneClient | IntuneFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Emit one encryption event and one compliance event per managed device."""
    now = collected_at or datetime.now(UTC)
    rows: list[dict[str, Any]] = []
    for device in client.managed_devices():
        device_id = str(device.get("id") or "").strip()
        if not device_id:
            continue
        attributes = _device_attributes(device_id, device)
        rows.append(_encryption_event(client.tenant_id, device_id, attributes, now, tenant_id))
        rows.append(_compliance_event(client.tenant_id, device_id, attributes, now, tenant_id))
    return rows


def _device_attributes(device_id: str, device: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "device_name": device.get("deviceName"),
        "user_principal_name": device.get("userPrincipalName"),
        "operating_system": device.get("operatingSystem"),
        "os_version": device.get("osVersion"),
        "owner_type": device.get("managedDeviceOwnerType"),
        "management_agent": device.get("managementAgent"),
        "azure_ad_device_id": device.get("azureADDeviceId"),
        "is_supervised": device.get("isSupervised"),
        "last_sync": device.get("lastSyncDateTime"),
        "enrolled": device.get("enrolledDateTime"),
        "is_encrypted": device.get("isEncrypted") is True,
        "compliance_state": str(device.get("complianceState") or "unknown"),
        "jailbroken": str(device.get("jailBroken") or "").lower() == "true",
    }


def _encryption_event(
    graph_tenant: str, device_id: str, attributes: dict[str, Any], collected_at: datetime, tenant_id: str
) -> dict[str, Any]:
    encrypted = attributes["is_encrypted"]
    return _event(
        graph_tenant=graph_tenant,
        device_id=device_id,
        signal="encryption",
        controls=ENCRYPTION_CONTROLS,
        status="pass" if encrypted else "open",
        severity="info" if encrypted else "high",
        attributes={**attributes, "finding_reason": None if encrypted else "not_encrypted"},
        collected_at=collected_at,
        tenant_id=tenant_id,
    )


def _compliance_event(
    graph_tenant: str, device_id: str, attributes: dict[str, Any], collected_at: datetime, tenant_id: str
) -> dict[str, Any]:
    state = attributes["compliance_state"]
    if attributes["jailbroken"]:
        status, severity, reason = "open", "high", "jailbroken"
    elif state in FAILED_COMPLIANCE_STATES:
        status, severity, reason = "open", "high", state
    elif state == "inGracePeriod":
        status, severity, reason = "open", "low", "in_grace_period"
    elif state == "compliant":
        status, severity, reason = "pass", "info", None
    else:
        # unknown / configManager: Intune has no compliance verdict to rely on.
        status, severity, reason = "open", "medium", "compliance_not_reported"
    return _event(
        graph_tenant=graph_tenant,
        device_id=device_id,
        signal="compliance",
        controls=COMPLIANCE_CONTROLS,
        status=status,
        severity=severity,
        attributes={**attributes, "finding_reason": reason},
        collected_at=collected_at,
        tenant_id=tenant_id,
    )


def _event(
    *,
    graph_tenant: str,
    device_id: str,
    signal: str,
    controls: list[str],
    status: str,
    severity: str,
    attributes: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    stable = stable_id_slug(f"{graph_tenant}:{signal}:{device_id}", fallback="intune")
    return {
        "event_id": f"intune-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "intune",
        "event_type": f"intune.device.{signal}",
        "entity": {
            "asset_id": f"intune:device:{device_id}",
            "asset_type": "managed_device",
            "asset_owner": graph_tenant,
            "environment": "prod",
            "org": graph_tenant,
        },
        "severity": severity,
        "status": status,
        "controls": controls,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": f"https://{GRAPH_HOST}/v1.0/deviceManagement/managedDevices/{device_id}",
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": attributes,
    }
