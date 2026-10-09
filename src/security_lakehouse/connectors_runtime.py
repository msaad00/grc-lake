"""Runtime gateway event export collector.

Read-only HTTP export against a customer's AI runtime policy gateway. Emits
tool-call, policy-decision, and runtime-block rows in the lake raw evidence
shape for append-mode sync with watermark cursors.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json
from security_lakehouse.models import parse_event_time, utc_iso
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.secret_refs import resolve_ref_or_default

CONNECTOR_ID = "runtime-gateway"
SOURCE = "runtime-gateway"
DEFAULT_CONTROLS = ["SOC2-CC7.2", "NIST-AI-RMF-MEASURE-2.7"]
DEFAULT_TIMEOUT = 30
# Runaway guard on the cursor loop.
MAX_PAGES = 10_000
ITEM_KEYS = ("events", "items", "data")
BLOCKED_STATUSES = frozenset({"blocked", "denied", "rejected"})
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]+$")


class RuntimeGatewayClient:
    """Read-only runtime gateway export client."""

    def __init__(
        self,
        host: str,
        *,
        token: str,
        stream: str = "runtime-events",
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = host.rstrip("/")
        self.token = token
        self.stream = _safe_scope(stream)
        self.timeout = timeout

    def events(self, *, since: str | None = None) -> list[dict[str, Any]]:
        base = f"{self.base_url}/api/v1/streams/{self.stream}/events"
        params = {"since": since} if since else {}
        return self._json_list_paginated(base, params)

    def list_streams(self) -> list[str]:
        rows = self._json_list(f"{self.base_url}/api/v1/streams")
        streams: list[str] = []
        for row in rows:
            if isinstance(row, dict):
                name = str(row.get("name") or row.get("stream") or "").strip()
                if name:
                    streams.append(name)
            elif isinstance(row, str) and row.strip():
                streams.append(row.strip())
        return streams

    def probe(self) -> dict[str, Any]:
        try:
            rows = self.events()
            return {
                "ok": True,
                "stream": self.stream,
                "event_count": len(rows),
                "error": None,
            }
        except Exception as exc:  # noqa: BLE001 - probe surfaces sanitized errors
            return {
                "ok": False,
                "stream": self.stream,
                "event_count": None,
                "error": exc.__class__.__name__,
            }

    def discover_scope(self) -> dict[str, Any]:
        streams = self.list_streams()
        selected = self.stream or (streams[0] if streams else "runtime-events")
        selectors = [
            *[
                {
                    "kind": "stream",
                    "name": name,
                    "required": False,
                    "selected": name == selected,
                }
                for name in streams
            ],
        ]
        if selected and not any(item["name"] == selected for item in selectors):
            selectors.append(
                {"kind": "stream", "name": selected, "required": True, "selected": True},
            )
        return {
            "ok": True,
            "selection_mode": "visible_streams",
            "selectors": selectors,
            "recommended_options": {"stream": selected},
        }

    def _fetch_json(self, url: str) -> Any:
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self.token}",
                "user-agent": "grc-lake",
            },
        )

        def _fetch() -> Any:
            with netguard.open_public(request, timeout=self.timeout, label="runtime gateway url") as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            # Retry transient 429/5xx (honoring Retry-After); a terminal 4xx or an
            # exhausted retry surfaces as a sanitized error rather than failing loud.
            return backoff.http_retry(_fetch)
        except urllib.error.HTTPError as exc:  # pragma: no cover - live only
            raise ValueError(exc.__class__.__name__) from exc

    @staticmethod
    def _extract_items(payload: Any, url: str) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ITEM_KEYS:
                value = payload.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        raise ValueError(f"runtime gateway returned non-list JSON for {url}")

    def _json_list(self, url: str) -> list[dict[str, Any]]:
        return self._extract_items(self._fetch_json(url), url)

    def _json_list_paginated(self, base_url: str, params: dict[str, str]) -> list[dict[str, Any]]:
        """Follow the export's ``next_cursor`` envelope until it is exhausted.

        A bare-list (or cursor-less object) response yields exactly one page, so
        this is backward compatible with an export that does not paginate.
        ``since`` and any other params ride on every page.
        """

        def fetch_page(cursor: str | None) -> tuple[str, Any]:
            query = dict(params)
            if cursor:
                query["cursor"] = cursor
            url = f"{base_url}?{urllib.parse.urlencode(query)}" if query else base_url
            return url, self._fetch_json(url)

        def extract_items(page: tuple[str, Any]) -> list[dict[str, Any]]:
            url, payload = page
            return self._extract_items(payload, url)

        def next_cursor(page: tuple[str, Any]) -> str | None:
            _url, payload = page
            if isinstance(payload, dict):
                return str(payload.get("next_cursor") or "") or None
            return None

        return list(paginate(fetch_page, extract_items, next_cursor, max_pages=MAX_PAGES))


class RuntimeGatewayFixtureClient:
    """Offline client backed by JSON fixtures."""

    def __init__(self, fixture_dir: str | Path, *, stream: str = "runtime-events") -> None:
        self.fixture = Path(fixture_dir)
        self.stream = stream

    def events(self, *, since: str | None = None) -> list[dict[str, Any]]:
        rows = self._read_events()
        if not since:
            return rows
        return [row for row in rows if str(row.get("event_time") or "") > since]

    def list_streams(self) -> list[str]:
        return ["runtime-events", "policy-decisions"]

    def probe(self) -> dict[str, Any]:
        rows = self.events()
        return {
            "ok": True,
            "stream": self.stream,
            "event_count": len(rows),
            "error": None,
        }

    def discover_scope(self) -> dict[str, Any]:
        streams = self.list_streams()
        selected = self.stream or streams[0]
        return {
            "ok": True,
            "selection_mode": "visible_streams",
            "selectors": [
                {
                    "kind": "stream",
                    "name": name,
                    "required": name == selected,
                    "selected": name == selected,
                }
                for name in streams
            ],
            "recommended_options": {"stream": selected},
        }

    def _read_events(self) -> list[dict[str, Any]]:
        path = self.fixture / "events.json"
        if not path.is_file():
            return []
        payload = read_json(path)
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        return []


def collect_runtime_gateway_evidence(
    client: RuntimeGatewayClient | RuntimeGatewayFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
    since: str | None = None,
) -> list[dict[str, Any]]:
    """Collect raw evidence rows from a runtime gateway export."""
    moment = collected_at or datetime.now(UTC)
    rows: list[dict[str, Any]] = []
    for event in client.events(since=since):
        raw = _raw_from_event(event, collected_at=moment, tenant_id=tenant_id)
        if raw is not None:
            rows.append(raw)
    return rows


def probe_runtime_gateway_access(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = runtime_env(env)
    host, token, stream = _connection_params(credentials, options, env=env)
    if not host:
        raise ValueError("runtime-gateway probe requires host")
    return RuntimeGatewayClient(host, token=token, stream=stream).probe()


def discover_runtime_gateway_scope(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = runtime_env(env)
    host, token, stream = _connection_params(credentials, options, env=env)
    if not host:
        return {"ok": False, "error": "host is required", "selectors": []}
    try:
        return RuntimeGatewayClient(host, token=token, stream=stream).discover_scope()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": exc.__class__.__name__, "selectors": []}


def _connection_params(
    credentials: dict[str, Any],
    options: dict[str, Any],
    *,
    env: dict[str, str] | None = None,
) -> tuple[str, str, str]:
    env = runtime_env(env)
    environment = env or {}
    host = str(credentials.get("host") or environment.get("RUNTIME_GATEWAY_URL") or "").strip()
    token = str(
        credentials.get("token")
        or resolve_ref_or_default(
            credentials.get("credential_ref"),
            "GRC_LAKE_RUNTIME_GATEWAY_TOKEN",
            environment,
            field="credential_ref",
            file_first=False,
        )
        or ""
    ).strip()
    stream = str(options.get("stream") or "runtime-events").strip() or "runtime-events"
    return host, token, stream


def _raw_from_event(
    event: dict[str, Any],
    *,
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any] | None:
    event_id = str(event.get("event_id") or event.get("id") or "").strip()
    event_time = _event_time_iso(event.get("event_time") or event.get("timestamp"))
    if not event_id or not event_time:
        return None
    entity = event.get("entity")
    if not isinstance(entity, dict):
        entity = {}
    asset_id = str(entity.get("asset_id") or event.get("asset_id") or f"runtime:event:{event_id}")
    controls = [str(item) for item in event.get("controls") or DEFAULT_CONTROLS]
    status = str(event.get("status") or "observed").lower()
    severity = str(event.get("severity") or ("high" if status in BLOCKED_STATUSES else "info"))
    event_type = str(event.get("event_type") or "runtime.tool_call")
    return {
        "event_id": f"runtime-{event_id}",
        "tenant_id": str(event.get("tenant_id") or tenant_id),
        "workspace_id": "default",
        "event_time": event_time,
        "source": SOURCE,
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": str(entity.get("asset_type") or "ai_agent"),
            "asset_owner": str(entity.get("owner") or entity.get("asset_owner") or "ai-security"),
            "environment": str(entity.get("environment") or "prod"),
            "org": SOURCE,
        },
        "severity": severity,
        "status": "observed" if status in BLOCKED_STATUSES else status,
        "controls": controls or list(DEFAULT_CONTROLS),
        "evidence": {
            "evidence_id": str(event.get("evidence_id") or f"ev-runtime-{event_id}"),
            "evidence_ref": str(event.get("evidence_ref") or f"runtime://{event_id}"),
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": {
            "source_status": status,
            "tool": event.get("tool"),
            "policy": event.get("policy"),
            "reason": event.get("reason"),
            "stream": event.get("stream"),
        },
    }


def _event_time_iso(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return utc_iso(parse_event_time(text))
    except ValueError:
        return text.replace(" ", "T") + ("Z" if not text.endswith("Z") and "+" not in text else "")


def _safe_scope(value: str) -> str:
    text = str(value or "").strip()
    if not text or not IDENTIFIER.fullmatch(text):
        raise ValueError(f"unsafe runtime stream name {value!r}")
    return text
