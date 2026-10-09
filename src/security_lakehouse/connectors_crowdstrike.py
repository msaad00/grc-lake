"""CrowdStrike Falcon sensor-coverage, prevention, and alert evidence collector.

Read-only collection from the Falcon API (verified 2026-09-27 against the
CrowdStrike-maintained FalconPy SDK endpoint modules on ``main`` and the API
reference at developer.crowdstrike.com/api-reference/collections):

* Auth: ``POST /oauth2/token`` with form fields ``client_id`` and
  ``client_secret`` (FalconPy ``_util/_auth.py`` sends no ``grant_type``).
* Hosts (scope ``Hosts: READ``): ``GET /devices/queries/devices-scroll/v1``
  (``limit`` 1-10000, opaque ``offset`` scroll token that expires after two
  minutes) then ``POST /devices/entities/devices/v2`` with body ``{"ids": [...]}``
  (up to 5000 ids per call).
* Prevention policies (scope ``Prevention policies: READ``):
  ``GET /policy/combined/prevention/v1`` (``limit`` 1-5000, integer ``offset``).
* Alerts (scope ``Alerts: READ``): ``POST /alerts/combined/alerts/v1`` with body
  ``{"filter", "limit" (max 1000), "sort", "after"}``; pages until a response has
  no ``meta.pagination.after``. The legacy Detects API is superseded by Alerts.

Every response uses the ``{"meta": {...}, "resources": [...], "errors": [...]}``
envelope. Rate limits answer HTTP 429 with ``X-RateLimit-RetryAfter`` (a UTC
epoch timestamp), which the retry honors before falling back to ``Retry-After``.

Every request goes to the configured cloud's API host only; no pagination value
is ever followed as a URL. Only posture fields are kept: MAC and IP addresses,
serial numbers, and user names are dropped at the client.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.oauth import ClientCredentialsToken
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json
from security_lakehouse.models import utc_iso
from security_lakehouse.timeutil import parse_iso

SOURCE = "crowdstrike"
DEFAULT_TIMEOUT = 30
CROWDSTRIKE_CLOUDS: dict[str, str] = {
    "us-1": "api.crowdstrike.com",
    "us-2": "api.us-2.crowdstrike.com",
    "eu-1": "api.eu-1.crowdstrike.com",
    "us-gov-1": "api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "api.us-gov-2.crowdstrike.mil",
}

HOST_SCROLL_PATH = "/devices/queries/devices-scroll/v1"
HOST_DETAILS_PATH = "/devices/entities/devices/v2"
PREVENTION_POLICIES_PATH = "/policy/combined/prevention/v1"
ALERTS_COMBINED_PATH = "/alerts/combined/alerts/v1"
HOST_SCROLL_LIMIT = 5000
HOST_DETAILS_BATCH = 5000
POLICY_PAGE_LIMIT = 5000
ALERT_PAGE_LIMIT = 1000
ALERT_LOOKBACK = timedelta(days=30)
SENSOR_STALE_AFTER = timedelta(days=7)

# Fields kept from a host record; everything else (MAC/IP addresses, serial
# numbers, logged-in user names, tags) is dropped before it leaves the client.
HOST_FIELDS = (
    "device_id",
    "hostname",
    "platform_name",
    "os_version",
    "product_type_desc",
    "agent_version",
    "first_seen",
    "last_seen",
    "status",
    "reduced_functionality_mode",
    "device_policies",
)
POLICY_FIELDS = ("id", "name", "enabled", "platform_name")
ALERT_FIELDS = ("composite_id", "status", "severity", "severity_name", "created_timestamp")

# Controls verified to exist in controls/catalog.json.
SENSOR_CONTROLS = [
    "SOC2-CC6.8",
    "FEDRAMP-SI-3",
    "CMMC-3.14.2",
    "ISO27001-A.8.7",
    "CIS-CONTROLS-10",
    "NIST-CSF-DE.CM-09",
]
PREVENTION_CONTROLS = ["SOC2-CC6.8", "FEDRAMP-SI-3", "CMMC-3.14.2", "ISO27001-A.8.7"]
DETECTION_CONTROLS = ["SOC2-CC7.2", "FEDRAMP-SI-4", "CMMC-3.14.6", "ISO27001-A.8.16", "NIST-CSF-DE.CM-09"]

UNRESOLVED_ALERT_STATUSES = {"new", "in_progress", "reopened"}
SEVERITY_BANDS = ("critical", "high", "medium", "low", "informational")


def api_host(cloud: str) -> str:
    host = CROWDSTRIKE_CLOUDS.get(str(cloud or "").strip().lower())
    if host is None:
        raise ValueError(f"unknown CrowdStrike cloud {cloud!r}; expected one of {sorted(CROWDSTRIKE_CLOUDS)}")
    return host


def crowdstrike_retry_after(exc: BaseException) -> float | None:
    """Seconds until ``X-RateLimit-RetryAfter`` (epoch s or ms), else ``Retry-After``."""
    if isinstance(exc, urllib.error.HTTPError) and exc.headers:
        raw = str(exc.headers.get("X-RateLimit-RetryAfter") or "").strip()
        if raw:
            try:
                epoch = float(raw)
            except ValueError:
                epoch = None
            if epoch is not None:
                if epoch > 1e12:
                    epoch /= 1000.0
                return max(0.0, epoch - time.time())
    return backoff.http_retry_after(exc)


class CrowdStrikeClient:
    """Authenticated, read-only Falcon API client."""

    def __init__(
        self,
        cloud: str,
        *,
        client_id: str,
        client_secret: str,
        timeout: int = DEFAULT_TIMEOUT,
        token_source: ClientCredentialsToken | None = None,
    ) -> None:
        self.cloud = str(cloud).strip().lower()
        self.host = api_host(self.cloud)
        self.timeout = timeout
        self._token = token_source or ClientCredentialsToken(
            f"https://{self.host}/oauth2/token",
            form={"client_id": client_id, "client_secret": client_secret},
            label="CrowdStrike Falcon",
            timeout=timeout,
        )

    def hosts(self) -> list[dict[str, Any]]:
        seen = 0

        def fetch_page(offset: str | None) -> dict[str, Any]:
            query: dict[str, Any] = {"limit": HOST_SCROLL_LIMIT}
            if offset:
                query["offset"] = offset
            return self._request("GET", HOST_SCROLL_PATH, query=query)

        def extract(page: dict[str, Any]) -> list[str]:
            return [str(item) for item in page.get("resources") or [] if item]

        def next_cursor(page: dict[str, Any]) -> str | None:
            nonlocal seen
            resources = page.get("resources") or []
            seen += len(resources)
            pagination = (page.get("meta") or {}).get("pagination") or {}
            offset = str(pagination.get("offset") or "")
            total = int(pagination.get("total") or 0)
            if not resources or not offset or (total and seen >= total):
                return None
            return offset

        ids = list(dict.fromkeys(paginate(fetch_page, extract, next_cursor)))
        details: list[dict[str, Any]] = []
        for start in range(0, len(ids), HOST_DETAILS_BATCH):
            page = self._request("POST", HOST_DETAILS_PATH, body={"ids": ids[start : start + HOST_DETAILS_BATCH]})
            details.extend(_pick(item, HOST_FIELDS) for item in _resources(page))
        return details

    def prevention_policies(self) -> list[dict[str, Any]]:
        def fetch_page(offset: int | None) -> dict[str, Any]:
            return self._request(
                "GET", PREVENTION_POLICIES_PATH, query={"limit": POLICY_PAGE_LIMIT, "offset": offset or 0}
            )

        def next_cursor(page: dict[str, Any]) -> int | None:
            pagination = (page.get("meta") or {}).get("pagination") or {}
            count = len(page.get("resources") or [])
            offset = int(pagination.get("offset") or 0)
            total = int(pagination.get("total") or 0)
            # The combined endpoints report the offset of this page's first item.
            nxt = offset + count
            return nxt if count and nxt < total else None

        return [_pick(item, POLICY_FIELDS) for item in paginate(fetch_page, _resources, next_cursor)]

    def alerts(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        """Unresolved alerts created within :data:`ALERT_LOOKBACK`."""
        since = (now or datetime.now(UTC)) - ALERT_LOOKBACK
        fql = f"status:!'closed'+created_timestamp:>='{utc_iso(since)}'"

        def fetch_page(after: str | None) -> dict[str, Any]:
            body: dict[str, Any] = {"filter": fql, "limit": ALERT_PAGE_LIMIT, "sort": "created_timestamp.desc"}
            if after:
                body["after"] = after
            return self._request("POST", ALERTS_COMBINED_PATH, body=body)

        def next_cursor(page: dict[str, Any]) -> str | None:
            after = str(((page.get("meta") or {}).get("pagination") or {}).get("after") or "")
            return after if after and page.get("resources") else None

        return [_pick(item, ALERT_FIELDS) for item in paginate(fetch_page, _resources, next_cursor)]

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"https://{self.host}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        def call(token: str) -> Any:
            request = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8") if body is not None else None,
                method=method,
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {token}",
                    "content-type": "application/json",
                    "user-agent": "grc-lake",
                },
            )
            return backoff.retry(
                lambda: self._open(request),
                is_retryable=backoff.is_retryable_http,
                retry_after=crowdstrike_retry_after,
            )

        payload = self._token.call_with_bearer(call)
        if not isinstance(payload, dict):
            raise ValueError(f"CrowdStrike returned non-object JSON for {path}")
        return payload

    def _open(self, request: urllib.request.Request) -> Any:
        with netguard.open_public(request, timeout=self.timeout, label="crowdstrike falcon") as resp:
            return json.loads(resp.read().decode("utf-8"))


class CrowdStrikeFixtureClient:
    """Offline client backed by hosts.json, prevention_policies.json, alerts.json."""

    def __init__(self, fixture_dir: str | Path, *, cloud: str) -> None:
        self.fixture = Path(fixture_dir)
        self.cloud = str(cloud).strip().lower()
        self.host = api_host(self.cloud)

    def hosts(self) -> list[dict[str, Any]]:
        return [_pick(item, HOST_FIELDS) for item in self._read("hosts.json")]

    def prevention_policies(self) -> list[dict[str, Any]]:
        return [_pick(item, POLICY_FIELDS) for item in self._read("prevention_policies.json")]

    def alerts(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        return [_pick(item, ALERT_FIELDS) for item in self._read("alerts.json")]

    def _read(self, name: str) -> list[dict[str, Any]]:
        path = self.fixture / name
        payload = read_json(path) if path.exists() else []
        if isinstance(payload, dict):
            payload = payload.get("resources") or []
        return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def collect_crowdstrike_evidence(
    client: CrowdStrikeClient | CrowdStrikeFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """One sensor and one prevention event per host, plus one alert summary."""
    now = collected_at or datetime.now(UTC)
    policies = {str(p.get("id")): p for p in client.prevention_policies() if p.get("id")}
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for host in client.hosts():
        device_id = str(host.get("device_id") or "").strip()
        if not device_id or device_id in seen:
            continue
        seen.add(device_id)
        attributes = _host_attributes(host)
        rows.append(_sensor_event(client, device_id, attributes, now, tenant_id))
        rows.append(_prevention_event(client, device_id, attributes, host, policies, now, tenant_id))
    rows.append(_detections_event(client, client.alerts(now=now), len(seen), now, tenant_id))
    return rows


def _host_attributes(host: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": host.get("device_id"),
        "hostname": host.get("hostname"),
        "platform": host.get("platform_name"),
        "os_version": host.get("os_version"),
        "product_type": host.get("product_type_desc"),
        "agent_version": host.get("agent_version"),
        "first_seen": host.get("first_seen"),
        "last_seen": host.get("last_seen"),
        "containment_status": host.get("status"),
        "reduced_functionality_mode": str(host.get("reduced_functionality_mode") or "").lower() == "yes",
    }


def _sensor_event(
    client: Any, device_id: str, attributes: dict[str, Any], now: datetime, tenant_id: str
) -> dict[str, Any]:
    last_seen = parse_iso(attributes["last_seen"], lenient=True)
    if attributes["reduced_functionality_mode"]:
        status, severity, reason = "open", "high", "reduced_functionality_mode"
    elif last_seen is None:
        status, severity, reason = "open", "medium", "last_seen_not_reported"
    elif now - last_seen > SENSOR_STALE_AFTER:
        status, severity, reason = "open", "medium", "sensor_not_reporting"
    else:
        status, severity, reason = "pass", "info", None
    return _event(
        client=client,
        key=device_id,
        entity=_host_entity(client, device_id),
        signal="host.sensor",
        controls=SENSOR_CONTROLS,
        status=status,
        severity=severity,
        attributes={**attributes, "finding_reason": reason},
        evidence_ref=f"https://{client.host}{HOST_DETAILS_PATH}?ids={urllib.parse.quote(device_id)}",
        now=now,
        tenant_id=tenant_id,
    )


def _prevention_event(
    client: Any,
    device_id: str,
    attributes: dict[str, Any],
    host: dict[str, Any],
    policies: dict[str, dict[str, Any]],
    now: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    assigned = ((host.get("device_policies") or {}).get("prevention")) or {}
    policy_id = str(assigned.get("policy_id") or "")
    policy = policies.get(policy_id)
    if not policy_id:
        status, severity, reason = "open", "high", "no_prevention_policy"
    elif assigned.get("applied") is not True:
        status, severity, reason = "open", "high", "policy_not_applied"
    elif policy is None:
        status, severity, reason = "open", "high", "policy_not_found"
    elif policy.get("enabled") is not True:
        status, severity, reason = "open", "high", "policy_disabled"
    else:
        status, severity, reason = "pass", "info", None
    return _event(
        client=client,
        key=device_id,
        entity=_host_entity(client, device_id),
        signal="host.prevention_policy",
        controls=PREVENTION_CONTROLS,
        status=status,
        severity=severity,
        attributes={
            **attributes,
            "prevention_policy_id": policy_id or None,
            "prevention_policy_name": (policy or {}).get("name"),
            "prevention_policy_applied": assigned.get("applied") is True,
            "prevention_policy_enabled": (policy or {}).get("enabled") is True,
            "finding_reason": reason,
        },
        evidence_ref=f"https://{client.host}/policy/entities/prevention/v1?ids={urllib.parse.quote(policy_id)}"
        if policy_id
        else f"https://{client.host}{HOST_DETAILS_PATH}?ids={urllib.parse.quote(device_id)}",
        now=now,
        tenant_id=tenant_id,
    )


def _detections_event(
    client: Any, alerts: list[dict[str, Any]], host_count: int, now: datetime, tenant_id: str
) -> dict[str, Any]:
    counts = dict.fromkeys(SEVERITY_BANDS, 0)
    for alert in alerts:
        if str(alert.get("status") or "").lower() not in UNRESOLVED_ALERT_STATUSES:
            continue
        counts[_severity_band(alert)] += 1
    if counts["critical"] or counts["high"]:
        status, severity, reason = "open", "high", "unresolved_high_severity_alerts"
    elif counts["medium"]:
        status, severity, reason = "open", "medium", "unresolved_medium_severity_alerts"
    else:
        status, severity, reason = "pass", "info", None
    return _event(
        client=client,
        key="alerts",
        entity={
            "asset_id": f"crowdstrike:tenant:{client.cloud}",
            "asset_type": "edr_tenant",
            "asset_owner": client.cloud,
            "environment": "prod",
            "org": client.cloud,
        },
        signal="detections.summary",
        controls=DETECTION_CONTROLS,
        status=status,
        severity=severity,
        attributes={
            "cloud": client.cloud,
            "lookback_days": ALERT_LOOKBACK.days,
            "unresolved_alert_counts": counts,
            "unresolved_alert_total": sum(counts.values()),
            "host_count": host_count,
            "finding_reason": reason,
        },
        evidence_ref=f"https://{client.host}{ALERTS_COMBINED_PATH}",
        now=now,
        tenant_id=tenant_id,
    )


def _severity_band(alert: dict[str, Any]) -> str:
    name = str(alert.get("severity_name") or "").strip().lower()
    if name in SEVERITY_BANDS:
        return name
    # Falcon severity is 1-100; bands follow the console's severity_name cut-offs.
    try:
        score = int(alert.get("severity") or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


def _host_entity(client: Any, device_id: str) -> dict[str, Any]:
    return {
        "asset_id": f"{SOURCE}:host:{device_id}",
        "asset_type": "endpoint_host",
        "asset_owner": client.cloud,
        "environment": "prod",
        "org": client.cloud,
    }


def _event(
    *,
    client: Any,
    key: str,
    entity: dict[str, Any],
    signal: str,
    controls: list[str],
    status: str,
    severity: str,
    attributes: dict[str, Any],
    evidence_ref: str,
    now: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    stable = stable_id_slug(f"{client.cloud}:{signal}:{key}", fallback="crowdstrike")
    return {
        "event_id": f"{SOURCE}-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(now),
        "source": SOURCE,
        "event_type": f"{SOURCE}.{signal}",
        "entity": entity,
        "severity": severity,
        "status": status,
        "controls": list(controls),
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": evidence_ref,
            "evidence_collected_at": utc_iso(now),
        },
        "attributes": attributes,
    }


def _resources(page: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in page.get("resources") or [] if isinstance(item, dict)]


def _pick(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: item[field] for field in fields if field in item}


__all__ = [
    "CROWDSTRIKE_CLOUDS",
    "CrowdStrikeClient",
    "CrowdStrikeFixtureClient",
    "collect_crowdstrike_evidence",
    "crowdstrike_retry_after",
]
