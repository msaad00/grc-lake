"""ClickHouse telemetry-lake collector.

Read-only SELECT against TrustOps-shaped analytics tables (see
``deploy/clickhouse/schema.sql``). Uses the HTTP interface so the base package
does not require ``clickhouse-connect``; CI runs from fixtures.
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
from security_lakehouse.io import read_json
from security_lakehouse.lake_mapping import (
    MappingSpec,
    compile_select,
    probe_mappings,
    read_fixture_table,
    resolve_mappings,
)
from security_lakehouse.models import parse_event_time, utc_iso
from security_lakehouse.secret_refs import resolve_ref_or_default

CONNECTOR_ID = "clickhouse-telemetry-lake"
SOURCE = "clickhouse"
DEFAULT_DATABASE = "security"
DEFAULT_TABLE = "normalized_events"
DEFAULT_CONTROLS = ["SOC2-CC7.2", "ISO27001-A.8.16"]
DEFAULT_TIMEOUT = 30
# Server-side page size for keyset paging. Large enough that small tables take
# one round trip, bounded so a huge table streams instead of one giant response.
DEFAULT_PAGE_SIZE = 50_000
# Runaway guard on the page loop (DEFAULT_PAGE_SIZE * MAX_PAGES rows).
MAX_PAGES = 10_000
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ClickHouseClient:
    """Read-only ClickHouse HTTP client."""

    def __init__(
        self,
        host: str,
        *,
        user: str,
        password: str = "",
        database: str = DEFAULT_DATABASE,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = host.rstrip("/")
        self.user = user
        self.password = password
        self.database = database
        self.timeout = timeout

    def normalized_events(
        self,
        *,
        table: str = DEFAULT_TABLE,
        since: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        """Read normalized events, keyset-paginated so a large table is not one
        unbounded response.

        The cursor is the composite ``(event_time, event_id)`` — a total order over
        the table's own sort key — so rows sharing an ``event_time`` across a page
        boundary are never dropped and the loop always advances. ``since`` (the
        watermark) still bounds the first page; downstream merge dedups by
        ``event_id`` as a second safety net.
        """
        safe_table = _safe_table_ref(self.database, table)
        rows: list[dict[str, Any]] = []
        last_time: str | None = None
        last_id: str | None = None
        for _ in range(MAX_PAGES):
            # Watermark and cursor values come from source rows, so they are
            # bound as typed HTTP query parameters and never spliced into SQL.
            conditions: list[str] = []
            params: dict[str, str] = {}
            if since:
                conditions.append("event_time > parseDateTime64BestEffort({since:String})")
                params["since"] = since
            if last_time is not None and last_id is not None:
                boundary = "parseDateTime64BestEffort({cursor_time:String})"
                conditions.append(
                    f"(event_time > {boundary} OR (event_time = {boundary} AND event_id > {{cursor_id:String}}))"
                )
                params["cursor_time"] = last_time
                params["cursor_id"] = last_id
            where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
            query = (
                f"SELECT * FROM {safe_table}{where} ORDER BY event_time, event_id "
                f"LIMIT {int(page_size)} FORMAT JSONEachRow"
            )
            page = self._query_json_each_row(query, params=params)
            rows.extend(page)
            if len(page) < page_size:
                break
            last_time = str(page[-1].get("event_time") or "")
            last_id = str(page[-1].get("event_id") or "")
            if not last_time or not last_id:
                raise ValueError("ClickHouse collection incomplete: missing pagination cursor")
        else:
            raise ValueError("ClickHouse collection incomplete: pagination limit reached")
        return rows

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        """Read a customer table through a mapping spec with typed ``{name:Type}`` parameters."""
        query = compile_select(
            spec, "clickhouse", since=since, limit=limit, default_namespace=(safe_identifier(self.database),)
        )
        return self._query_json_each_row(query.sql, params=query.clickhouse_parameters())

    def show_tables(self) -> list[str]:
        rows = self._query_json_each_row(f"SHOW TABLES FROM {safe_identifier(self.database)} FORMAT JSONEachRow")
        return [str(row.get("name") or "") for row in rows if row.get("name")]

    def probe(self, *, table: str = DEFAULT_TABLE) -> dict[str, Any]:
        safe_table = _safe_table_ref(self.database, table)
        try:
            rows = self._query_json_each_row(f"SELECT count() AS row_count FROM {safe_table} FORMAT JSONEachRow")
            count = int(rows[0].get("row_count") or 0) if rows else 0
            return {"ok": True, "table": safe_table, "row_count": count, "error": None}
        except Exception as exc:  # noqa: BLE001 - probe surfaces sanitized errors
            return {"ok": False, "table": safe_table, "row_count": None, "error": exc.__class__.__name__}

    def discover_scope(self) -> dict[str, Any]:
        tables = [name for name in self.show_tables() if name]
        selectors = [
            {"kind": "database", "name": self.database, "required": True, "selected": True},
            *[
                {
                    "kind": "table",
                    "name": name,
                    "required": name == DEFAULT_TABLE,
                    "selected": name == DEFAULT_TABLE,
                    "purpose": "normalized_events" if name == DEFAULT_TABLE else "table",
                }
                for name in tables
            ],
        ]
        return {
            "ok": True,
            "selection_mode": "visible_tables",
            "selectors": selectors,
            "recommended_options": {"database": self.database, "table": DEFAULT_TABLE},
        }

    def _query_json_each_row(self, query: str, *, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        query_string: dict[str, str] = {"database": self.database, "readonly": "1"}
        for name, value in (params or {}).items():
            query_string[f"param_{name}"] = escape_query_parameter(value)
        url = f"{self.base_url}/?{urllib.parse.urlencode(query_string)}"
        request = urllib.request.Request(
            url,
            data=query.encode("utf-8"),
            method="POST",
            headers={
                "content-type": "text/plain; charset=utf-8",
                "user-agent": "trustops-security-data-lake",
            },
        )
        if self.user:
            request.add_header("X-ClickHouse-User", self.user)
        if self.password:
            request.add_header("X-ClickHouse-Key", self.password)

        def _fetch() -> str:
            with netguard.open_public(request, timeout=self.timeout, label="clickhouse host") as resp:
                return resp.read().decode("utf-8")

        try:
            # A read-only SELECT/SHOW is safe to retry; recover from a transient
            # 429/5xx (honoring Retry-After) instead of failing the whole sync.
            body = backoff.http_retry(_fetch)
        except urllib.error.HTTPError as exc:  # pragma: no cover - live only
            raise ValueError(exc.__class__.__name__) from exc
        rows: list[dict[str, Any]] = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
        return rows


class ClickHouseFixtureClient:
    """Offline client backed by JSON fixtures."""

    def __init__(self, fixture_dir: str | Path, *, database: str = DEFAULT_DATABASE) -> None:
        self.fixture = Path(fixture_dir)
        self.database = database

    def normalized_events(
        self,
        *,
        table: str = DEFAULT_TABLE,
        since: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        _ = page_size  # fixtures return the whole table; paging is a live-only concern
        rows = self._read_table(table)
        if not since:
            return rows
        return [row for row in rows if str(row.get("event_time") or "") > since]

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        _ = since, limit  # fixtures return the whole table; map_rows applies the same bound
        return read_fixture_table(self.fixture, spec.source_table)

    def show_tables(self) -> list[str]:
        return [path.stem for path in self.fixture.glob("*.json")]

    def probe(self, *, table: str = DEFAULT_TABLE) -> dict[str, Any]:
        rows = self.normalized_events(table=table)
        return {
            "ok": True,
            "table": f"{self.database}.{table}",
            "row_count": len(rows),
            "error": None,
        }

    def discover_scope(self) -> dict[str, Any]:
        tables = [name for name in self.show_tables() if name]
        selectors = [
            {"kind": "database", "name": self.database, "required": True, "selected": True},
            *[
                {
                    "kind": "table",
                    "name": name,
                    "required": name == DEFAULT_TABLE,
                    "selected": name == DEFAULT_TABLE,
                    "purpose": "normalized_events" if name == DEFAULT_TABLE else "table",
                }
                for name in tables
            ],
        ]
        return {
            "ok": True,
            "selection_mode": "visible_tables",
            "selectors": selectors,
            "recommended_options": {"database": self.database, "table": DEFAULT_TABLE},
        }

    def _read_table(self, table: str) -> list[dict[str, Any]]:
        path = self.fixture / f"{table}.json"
        if not path.is_file():
            return []
        payload = read_json(path)
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        return []


def collect_clickhouse_evidence(
    client: ClickHouseClient | ClickHouseFixtureClient,
    *,
    table: str = DEFAULT_TABLE,
    since: str | None = None,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect raw evidence rows from a ClickHouse telemetry table."""
    _ = collected_at
    rows: list[dict[str, Any]] = []
    for row in client.normalized_events(table=table, since=since):
        event = _raw_from_row(row, tenant_id=tenant_id)
        if event is not None:
            rows.append(event)
    return rows


def probe_clickhouse_access(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    host, user, password, database, table = _connection_params(credentials, options, env=env)
    if not host:
        raise ValueError("clickhouse-telemetry-lake probe requires host")
    client = ClickHouseClient(host, user=user, password=password, database=database)
    specs = resolve_mappings(options)
    if specs:
        mapped = probe_mappings(client, specs)
        failed = next((check for check in mapped["mappings"] if not check["ok"]), None)
        return {
            "ok": mapped["ok"],
            "table": ", ".join(check["table"] for check in mapped["mappings"]),
            "row_count": sum(check["sample_rows"] or 0 for check in mapped["mappings"]),
            "error": failed["error"] if failed else None,
            "mappings": mapped["mappings"],
        }
    return client.probe(table=table)


def discover_clickhouse_scope(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    host, user, password, database, _table = _connection_params(credentials, options, env=env)
    if not host:
        return {"ok": False, "error": "host is required", "selectors": []}
    try:
        return ClickHouseClient(host, user=user, password=password, database=database).discover_scope()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": exc.__class__.__name__, "selectors": []}


def _connection_params(
    credentials: dict[str, Any],
    options: dict[str, Any],
    *,
    env: dict[str, str] | None = None,
) -> tuple[str, str, str, str, str]:
    environment = env or {}
    host = str(credentials.get("host") or environment.get("CLICKHOUSE_HOST") or "").strip()
    user = str(credentials.get("user") or environment.get("CLICKHOUSE_USER") or "default").strip() or "default"
    password = str(
        credentials.get("token")
        or credentials.get("password")
        or resolve_ref_or_default(
            credentials.get("credential_ref"),
            "CLICKHOUSE_PASSWORD",
            environment,
            field="credential_ref",
            file_first=False,
        )
        or ""
    ).strip()
    database = str(options.get("database") or DEFAULT_DATABASE).strip() or DEFAULT_DATABASE
    table = str(options.get("table") or DEFAULT_TABLE).strip() or DEFAULT_TABLE
    return host, user, password, database, table


def _raw_from_row(row: dict[str, Any], *, tenant_id: str) -> dict[str, Any] | None:
    event_id = str(row.get("event_id") or "").strip()
    if not event_id:
        return None
    event_time = _event_time_iso(row.get("event_time"))
    controls = [str(item) for item in row.get("control_ids") or row.get("controls") or DEFAULT_CONTROLS]
    asset_id = str(row.get("asset_id") or f"clickhouse:event:{event_id}")
    evidence_id = str(row.get("evidence_id") or f"ev-{event_id}")
    evidence_ref = str(row.get("evidence_ref") or f"clickhouse://{event_id}")
    evidence_collected_at = _event_time_iso(row.get("evidence_collected_at") or event_time)
    return {
        "event_id": event_id,
        "tenant_id": str(row.get("tenant_id") or tenant_id),
        "workspace_id": "default",
        "event_time": event_time,
        "source": str(row.get("source") or SOURCE),
        "event_type": str(row.get("event_type") or "clickhouse.telemetry.event"),
        "entity": {
            "asset_id": asset_id,
            "asset_type": str(row.get("asset_type") or "telemetry_asset"),
            "asset_owner": str(row.get("asset_owner") or "security-platform"),
            "environment": str(row.get("environment") or "prod"),
            "org": SOURCE,
        },
        "severity": str(row.get("severity") or "info"),
        "status": str(row.get("status") or "observed"),
        "controls": controls or list(DEFAULT_CONTROLS),
        "evidence": {
            "evidence_id": evidence_id,
            "evidence_ref": evidence_ref,
            "evidence_collected_at": evidence_collected_at,
        },
        "attributes": {
            "severity_score": row.get("severity_score"),
            "raw_sha256": row.get("raw_sha256"),
            "table": DEFAULT_TABLE,
        },
    }


def _event_time_iso(value: Any) -> str:
    if value is None:
        return utc_iso(datetime.now(UTC))
    text = str(value).strip()
    if not text:
        return utc_iso(datetime.now(UTC))
    try:
        return utc_iso(parse_event_time(text))
    except ValueError:
        return text.replace(" ", "T") + ("Z" if not text.endswith("Z") and "+" not in text else "")


def safe_identifier(value: str) -> str:
    text = str(value or "").strip()
    if not IDENTIFIER.fullmatch(text):
        raise ValueError(f"unsafe ClickHouse identifier {value!r}")
    return text


def _safe_table_ref(database: str, table: str) -> str:
    return f"{safe_identifier(database)}.{safe_identifier(table)}"


_PARAMETER_ESCAPES = str.maketrans({"\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r", "\0": "\\0"})


def escape_query_parameter(value: str) -> str:
    """Encode an HTTP query-parameter value in ClickHouse's escaped (TSV) format.

    ClickHouse decodes ``param_<name>`` values with backslash escapes and rejects
    raw control characters, so a cursor taken from a row must be re-escaped to
    compare equal to that row.
    """
    return str(value).translate(_PARAMETER_ESCAPES)
