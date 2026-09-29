"""Snowflake evidence-lake collector.

The Snowflake connector is an existing-lake reader: it expects TrustOps-shaped
evidence views to already exist in the customer's Snowflake account and reads
them with a least-privilege role. It never creates, updates, or deletes
Snowflake objects.

Two clients sit behind one interface:

* :class:`SnowflakeClient` — optional live client backed by
  ``snowflake.connector`` when it is installed. The base package does not
  depend on the driver; CI runs entirely from fixtures.
* :class:`SnowflakeFixtureClient` — reads JSON fixtures that mirror the four
  evidence views so collection is deterministic and network-free in tests.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.io import read_json
from security_lakehouse.lake_mapping import (
    MappingSpec,
    compile_select,
    json_safe_row,
    probe_mappings,
    read_fixture_table,
    resolve_mappings,
)
from security_lakehouse.models import utc_iso
from security_lakehouse.secret_refs import resolve_secret_ref

CONNECTOR_ID = "snowflake-evidence-lake"
SOURCE = "snowflake"

DEFAULT_VIEWS = {
    "audit_events": "TRUSTOPS_AUDIT_EVENTS",
    "control_posture": "TRUSTOPS_CONTROL_POSTURE",
    "asset_risk": "TRUSTOPS_ASSET_RISK",
    "evidence_bundles": "TRUSTOPS_EVIDENCE_BUNDLES",
}
VIEW_PURPOSES = tuple(DEFAULT_VIEWS)

AUDIT_CONTROLS = ["SOC2-CC7.2", "ISO27001-A.8.16"]
CONTROL_POSTURE_CONTROLS = ["SOC2-CC6.1", "SOC2-CC7.2"]
ASSET_RISK_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.8.8", "NIST-AI-RMF-MAP-1.5"]
BUNDLE_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15"]


class SnowflakeClient:
    """Read-only Snowflake client backed by ``snowflake.connector``.

    The connector is imported lazily so TrustOps remains lightweight unless a
    user opts into live Snowflake collection. Authentication supports the
    Snowflake Python connector's standard keyword arguments passed by the runner
    (account, user, authenticator, token, warehouse, database, schema, role).
    Human POCs can use ``authenticator=externalbrowser``; automation can use
    OAuth without persisting the raw credential in TrustOps.
    """

    def __init__(self, *, query_params: dict[str, Any], views: dict[str, str] | None = None) -> None:
        try:
            import snowflake.connector  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - live Snowflake only
            raise RuntimeError(
                "snowflake-evidence-lake live collection requires snowflake-connector-python; "
                "install it or use --fixture-dir"
            ) from exc
        self._connector = snowflake.connector
        self.query_params = {key: value for key, value in query_params.items() if value}
        self.views = views or DEFAULT_VIEWS

    def audit_events(self) -> list[dict[str, Any]]:
        return self._select_view("audit_events")

    def control_posture(self) -> list[dict[str, Any]]:
        return self._select_view("control_posture")

    def asset_risk(self) -> list[dict[str, Any]]:
        return self._select_view("asset_risk")

    def evidence_bundles(self) -> list[dict[str, Any]]:
        return self._select_view("evidence_bundles")

    def probe(self) -> dict[str, Any]:
        """Run lightweight read checks for the configured Snowflake views."""
        checks: list[dict[str, Any]] = []
        context: dict[str, Any] = {}
        with self._connector.connect(**self.query_params) as conn:  # pragma: no cover - live Snowflake only
            cursor = conn.cursor()
            try:
                context = _connection_context(cursor)
                for purpose in VIEW_PURPOSES:
                    view = _safe_identifier(self.views[purpose])
                    checks.append(_view_probe_check(cursor, purpose=purpose, view=view))
            finally:
                cursor.close()
        return {
            "ok": all(check["ok"] for check in checks),
            "context": context,
            "views": checks,
        }

    def discover_scope(self) -> dict[str, Any]:
        """Return read-scope objects visible to the active Snowflake role."""
        with self._connector.connect(**self.query_params) as conn:  # pragma: no cover - live Snowflake only
            cursor = conn.cursor()
            try:
                context = _connection_context(cursor)
                warehouse = str(self.query_params.get("warehouse") or context.get("warehouse") or "")
                database = str(self.query_params.get("database") or context.get("database") or "")
                schema = str(self.query_params.get("schema") or context.get("schema") or "")
                warehouses = _show_names(cursor, "SHOW WAREHOUSES")
                databases = _show_names(cursor, "SHOW DATABASES")
                schemas: list[str] = []
                views: list[str] = []
                if database:
                    schemas = _show_names(cursor, f"SHOW SCHEMAS IN DATABASE {_safe_identifier(database)}")
                if database and schema:
                    views = _show_names(
                        cursor,
                        f"SHOW VIEWS IN SCHEMA {_safe_identifier(database)}.{_safe_identifier(schema)}",
                    )
                return _snowflake_scope_metadata(
                    context=context,
                    warehouses=warehouses,
                    databases=databases,
                    schemas=schemas,
                    views=views,
                    selected={
                        "warehouse": warehouse,
                        "database": database,
                        "schema": schema,
                        **{key: str(self.views.get(key) or "") for key in VIEW_PURPOSES},
                    },
                )
            finally:
                cursor.close()

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        """Read a customer table through a mapping spec; values are bound client-side by the driver."""
        query = compile_select(spec, "snowflake", since=since, limit=limit)
        with self._connector.connect(**self.query_params) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query.sql, query.params)
                names = [str(col[0]) for col in cursor.description or []]
                return [json_safe_row(dict(zip(names, row, strict=False))) for row in cursor.fetchall()]
            finally:
                cursor.close()

    def _select_view(self, key: str) -> list[dict[str, Any]]:
        view = _safe_identifier(self.views[key])
        with self._connector.connect(**self.query_params) as conn:  # pragma: no cover - live Snowflake only
            cursor = conn.cursor()
            try:
                cursor.execute(f"SELECT * FROM {view}")  # noqa: S608 - identifier is strictly validated above
                names = [str(col[0]).lower() for col in cursor.description or []]
                return [
                    {key: _json_safe_snowflake_value(value) for key, value in zip(names, row, strict=False)}
                    for row in cursor.fetchall()
                ]
            finally:
                cursor.close()


class SnowflakeFixtureClient:
    """Offline Snowflake evidence client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, account: str = "fixture-snowflake") -> None:
        self.fixture = Path(fixture_dir)
        self.account = account

    def audit_events(self) -> list[dict[str, Any]]:
        return self._read_list("audit_events.json")

    def control_posture(self) -> list[dict[str, Any]]:
        return self._read_list("control_posture.json")

    def asset_risk(self) -> list[dict[str, Any]]:
        return self._read_list("asset_risk.json")

    def evidence_bundles(self) -> list[dict[str, Any]]:
        return self._read_list("evidence_bundles.json")

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        _ = since, limit  # fixtures return the whole table; map_rows applies the same bound
        return read_fixture_table(self.fixture, spec.source_table)

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        path = self.fixture / name
        if not path.exists():
            return []
        payload = read_json(path)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []


def collect_snowflake_evidence(
    client: Any,
    *,
    account: str | None = None,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
    source: str = SOURCE,
) -> list[dict[str, Any]]:
    """Collect canonical raw evidence from the four TrustOps evidence views.

    ``source`` labels the lake the views live in; the Databricks connector
    reuses this contract with ``source="databricks"``.
    """
    now = collected_at or datetime.now(UTC)
    account_slug = _slug(account or getattr(client, "account", None) or source)
    rows: list[dict[str, Any]] = []

    for row in client.audit_events():
        event = _audit_event(account_slug, row, now, tenant_id, source)
        if event:
            rows.append(event)
    for row in client.control_posture():
        event = _control_posture_event(account_slug, row, now, tenant_id, source)
        if event:
            rows.append(event)
    for row in client.asset_risk():
        event = _asset_risk_event(account_slug, row, now, tenant_id, source)
        if event:
            rows.append(event)
    for row in client.evidence_bundles():
        event = _evidence_bundle_event(account_slug, row, now, tenant_id, source)
        if event:
            rows.append(event)
    return rows


def probe_snowflake_access(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate Snowflake read scope without collecting evidence.

    The probe uses browser SSO for human POCs, a named OAuth token environment
    variable, or a service-user private-key file reference. It returns object
    names, row counts, and sanitized diagnostics only; raw credential material is
    never returned.
    """
    environment = env or dict(os.environ)
    query_params = _probe_query_params(credentials=credentials, options=options, env=environment)
    specs = resolve_mappings(options)
    if specs:
        # Mapped reads never touch the TrustOps views, so probe the mapped tables.
        mapped = probe_mappings(SnowflakeClient(query_params=query_params), specs)
        return {
            "ok": mapped["ok"],
            "context": {},
            "views": [
                {
                    "purpose": check["mapping"],
                    "view": check["table"],
                    "ok": check["ok"],
                    "row_count": check["sample_rows"],
                    "error": check["error"],
                }
                for check in mapped["mappings"]
            ],
        }
    views = {key: str(options.get(key) or default) for key, default in DEFAULT_VIEWS.items()}
    try:
        result = SnowflakeClient(query_params=query_params, views=views).probe()
    except Exception as exc:  # pragma: no cover - exercised with the live driver
        return {
            "ok": False,
            "context": {},
            "views": [
                {
                    "purpose": key,
                    "view": view,
                    "ok": False,
                    "row_count": None,
                    "error": _snowflake_error_message(exc),
                }
                for key, view in views.items()
            ],
        }
    return result


def discover_snowflake_scope(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Discover Snowflake warehouses, databases, schemas, and views granted to the role.

    Discovery uses the same server-side credential references as probing. The
    UI should collect only account + service identity + a secret reference, then
    let the active Snowflake grants drive which scope objects can be selected.
    """
    environment = env or dict(os.environ)
    try:
        query_params = _probe_query_params(credentials=credentials, options=options, env=environment)
        views = {key: str(options.get(key) or default) for key, default in DEFAULT_VIEWS.items()}
        return SnowflakeClient(query_params=query_params, views=views).discover_scope()
    except Exception as exc:  # pragma: no cover - exercised with the live driver
        return {
            "ok": False,
            "selection_mode": "live_snowflake_scope",
            "context": {},
            "selectors": [],
            "candidates": {},
            "recommended_options": {},
            "error": _snowflake_error_message(exc),
        }


def _probe_query_params(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str],
) -> dict[str, Any]:
    account = str(credentials.get("account") or "").strip()
    user = str(credentials.get("user") or "").strip()
    if not account or not user:
        raise ValueError("Snowflake probe requires account and user")

    credential_ref = str(
        credentials.get("credential_ref") or credentials.get("oauth_token_ref") or credentials.get("token_env") or ""
    ).strip()
    oauth_token = str(credentials.get("oauth_token") or credentials.get("token") or "").strip() or None
    private_key_ref = str(credentials.get("private_key_ref") or credentials.get("private_key_file_ref") or "").strip()
    private_key_file = str(credentials.get("private_key_file") or "").strip() or None
    private_key_file_pwd_ref = str(credentials.get("private_key_file_pwd_ref") or "").strip()
    authenticator = str(options.get("authenticator") or credentials.get("authenticator") or "").strip()

    if in_server_mode(env):
        # A hosted tenant must not point the connector at a key file on the
        # server's disk or open a browser on the server.
        if private_key_file:
            raise ConnectorConfigError("Snowflake private_key_file is not accepted in hosted mode; use private_key_ref")
        if credential_ref.lower() == "externalbrowser" or authenticator.lower() == "externalbrowser":
            raise ConnectorConfigError("Snowflake externalbrowser auth is not available in hosted mode")

    if private_key_ref:
        private_key_file = resolve_secret_ref(private_key_ref, env, field="private_key_ref", file_first=False)
        if not private_key_file:
            raise ValueError(f"Snowflake private_key_ref environment variable {private_key_ref!r} is not set")
        authenticator = authenticator or "SNOWFLAKE_JWT"
    elif private_key_file:
        authenticator = authenticator or "SNOWFLAKE_JWT"
    elif credential_ref and credential_ref.lower() != "externalbrowser":
        oauth_token = resolve_secret_ref(credential_ref, env, field="credential_ref", file_first=False)
        if not oauth_token:
            raise ValueError(f"Snowflake credential_ref environment variable {credential_ref!r} is not set")
        authenticator = authenticator or "oauth"
    elif credential_ref.lower() == "externalbrowser":
        authenticator = authenticator or "externalbrowser"
    elif oauth_token:
        authenticator = authenticator or "oauth"
    else:
        authenticator = authenticator or "externalbrowser"

    private_key_file_pwd = (
        resolve_secret_ref(private_key_file_pwd_ref, env, field="private_key_file_pwd_ref", file_first=False)
        if private_key_file_pwd_ref
        else None
    )
    params = {
        "account": account,
        "user": user,
        "authenticator": authenticator,
        "token": oauth_token,
        "warehouse": str(options.get("warehouse") or "").strip() or None,
        "database": str(options.get("database") or "").strip() or None,
        "schema": str(options.get("schema") or "").strip() or None,
        "role": str(options.get("role") or credentials.get("role") or "").strip() or None,
    }
    if private_key_file and not oauth_token:
        params["private_key_file"] = private_key_file
        params["private_key_file_pwd"] = private_key_file_pwd
    return params


def _audit_event(
    account: str,
    row: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
    source: str = SOURCE,
) -> dict[str, Any] | None:
    audit_id = _first(row, "audit_id", "event_id", "id")
    if not audit_id:
        return None
    actor = _first(row, "actor", "user_name", "principal") or "unknown"
    object_name = _first(row, "object_name", "target", "asset_id") or f"{source}:audit"
    status = _status(row.get("status") or row.get("result") or "observed")
    severity = _severity(row.get("severity") or ("medium" if status == "open" else "info"))
    evidence_ref = _first(row, "evidence_ref", "query_id", "event_id") or str(audit_id)
    return _event(
        source=source,
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="audit_event",
        dedupe_key=str(audit_id),
        event_type=f"{source}.audit.event",
        asset_id=f"{source}:audit:{_slug(object_name)}",
        asset_type="audit_event",
        controls=_controls(row, AUDIT_CONTROLS),
        status=status,
        severity=severity,
        evidence_ref=f"{source}://audit/{evidence_ref}",
        attributes={
            "audit_id": audit_id,
            "actor": actor,
            "object_name": object_name,
            "query_id": row.get("query_id"),
            "event_action": row.get("event_action") or row.get("action"),
            "source_view": "audit_events",
        },
    )


def _control_posture_event(
    account: str,
    row: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
    source: str = SOURCE,
) -> dict[str, Any] | None:
    control_id = _first(row, "control_id", "control")
    if not control_id:
        return None
    status = _status(row.get("status") or row.get("result") or "observed")
    risk = _int(row.get("risk_score"))
    severity = _severity(row.get("severity") or _severity_from_risk(risk, status))
    evidence_ref = _first(row, "evidence_ref", "snapshot_id") or str(control_id)
    return _event(
        source=source,
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="control_posture",
        dedupe_key=str(control_id),
        event_type=f"{source}.control.posture",
        asset_id=f"{source}:control:{_slug(control_id)}",
        asset_type="control_posture",
        controls=_controls(row, [str(control_id), *CONTROL_POSTURE_CONTROLS]),
        status=status,
        severity=severity,
        evidence_ref=f"{source}://control_posture/{evidence_ref}",
        attributes={
            "control_id": control_id,
            "framework_id": row.get("framework_id"),
            "risk_score": risk,
            "confidence": row.get("confidence"),
            "source_view": "control_posture",
        },
    )


def _asset_risk_event(
    account: str,
    row: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
    source: str = SOURCE,
) -> dict[str, Any] | None:
    asset_id = _first(row, "asset_id", "asset")
    if not asset_id:
        return None
    risk = _int(row.get("risk_score"))
    status = _status(row.get("status") or ("open" if risk is not None and risk >= 70 else "observed"))
    severity = _severity(row.get("severity") or _severity_from_risk(risk, status))
    evidence_ref = _first(row, "evidence_ref", "asset_id") or str(asset_id)
    return _event(
        source=source,
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="asset_risk",
        dedupe_key=str(asset_id),
        event_type=f"{source}.asset.risk",
        asset_id=str(asset_id),
        asset_type=str(row.get("asset_type") or "asset"),
        controls=_controls(row, ASSET_RISK_CONTROLS),
        status=status,
        severity=severity,
        evidence_ref=f"{source}://asset_risk/{evidence_ref}",
        attributes={
            "asset_id": asset_id,
            "asset_type": row.get("asset_type"),
            "owner": row.get("owner") or row.get("asset_owner"),
            "environment": row.get("environment"),
            "risk_score": risk,
            "source_view": "asset_risk",
        },
    )


def _evidence_bundle_event(
    account: str,
    row: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
    source: str = SOURCE,
) -> dict[str, Any] | None:
    bundle_id = _first(row, "bundle_id", "evidence_id", "id")
    if not bundle_id:
        return None
    evidence_ref = _first(row, "evidence_ref", "object_uri", "bundle_uri") or str(bundle_id)
    status = _status(row.get("status") or "observed")
    severity = _severity(row.get("severity") or "info")
    return _event(
        source=source,
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="evidence_bundle",
        dedupe_key=str(bundle_id),
        event_type=f"{source}.evidence.bundle",
        asset_id=f"{source}:evidence_bundle:{_slug(bundle_id)}",
        asset_type="evidence_bundle",
        controls=_controls(row, BUNDLE_CONTROLS),
        status=status,
        severity=severity,
        evidence_ref=str(evidence_ref),
        attributes={
            "bundle_id": bundle_id,
            "hash_sha256": row.get("hash_sha256") or row.get("sha256"),
            "object_uri": row.get("object_uri"),
            "source_view": "evidence_bundles",
        },
    )


def _event(
    *,
    account: str,
    collected_at: datetime,
    tenant_id: str,
    signal: str,
    event_type: str,
    asset_id: str,
    asset_type: str,
    controls: list[str],
    status: str,
    severity: str,
    evidence_ref: str,
    attributes: dict[str, Any],
    dedupe_key: str | None = None,
    source: str = SOURCE,
) -> dict[str, Any]:
    stable = _stable_suffix(account=account, signal=signal, asset_id=asset_id, dedupe_key=dedupe_key)
    owner = str(attributes.get("owner") or attributes.get("actor") or account)
    environment = str(attributes.get("environment") or "prod")
    return {
        "event_id": f"{source}-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": source,
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": owner,
            "environment": environment,
            "org": account,
        },
        "severity": severity,
        "status": status,
        "controls": controls,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": evidence_ref,
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": attributes,
    }


def _controls(row: dict[str, Any], default: list[str]) -> list[str]:
    raw = row.get("controls") or row.get("control_ids") or row.get("control_id")
    values: list[str]
    if isinstance(raw, list):
        values = [str(item).strip() for item in raw if str(item).strip()]
    elif isinstance(raw, str):
        values = [part.strip() for part in re.split(r"[,|]", raw) if part.strip()]
    else:
        values = []
    out: list[str] = []
    for item in [*values, *default]:
        if item and item not in out:
            out.append(item)
    return out


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return value
    return None


def _status(value: Any) -> str:
    text = str(value or "observed").strip().lower()
    if text in {"pass", "passed", "ok", "ready", "compliant", "closed", "resolved"}:
        return "pass"
    if text in {"fail", "failed", "failing", "blocked", "open", "noncompliant", "non-compliant"}:
        return "open"
    return "observed"


def _severity(value: Any) -> str:
    text = str(value or "info").strip().lower()
    if text in {"critical", "high", "medium", "low", "info", "none"}:
        return text
    return "info"


def _severity_from_risk(risk: int | None, status: str) -> str:
    if status != "open":
        return "info"
    if risk is None:
        return "medium"
    if risk >= 90:
        return "critical"
    if risk >= 70:
        return "high"
    if risk >= 40:
        return "medium"
    return "low"


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _json_safe_snowflake_value(value: Any) -> Any:
    """Return a JSON-serializable representation of Snowflake driver values."""
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    if isinstance(value, datetime):
        return utc_iso(value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC))
    if isinstance(value, date):
        return value.isoformat()
    return value


def _slug(value: Any) -> str:
    slug = re.sub(r"[^a-z0-9_.:@/-]+", "-", str(value or "").lower()).strip("-")
    return slug[:128] or "snowflake"


def _stable_suffix(*, account: str, signal: str, asset_id: str, dedupe_key: str | None) -> str:
    seed = f"{account}:{signal}:{dedupe_key or asset_id}".lower()
    return stable_id_slug(seed, fallback="snowflake")


def _connection_context(cursor: Any) -> dict[str, Any]:
    cursor.execute("SELECT CURRENT_ROLE(), CURRENT_WAREHOUSE(), CURRENT_DATABASE(), CURRENT_SCHEMA()")
    row = cursor.fetchone() or (None, None, None, None)
    return {
        "role": row[0],
        "warehouse": row[1],
        "database": row[2],
        "schema": row[3],
    }


def _show_names(cursor: Any, query: str) -> list[str]:
    cursor.execute(query)
    names = [str(col[0]).lower() for col in cursor.description or []]
    try:
        name_index = names.index("name")
    except ValueError:
        name_index = 1 if len(names) > 1 else 0
    out: list[str] = []
    for row in cursor.fetchall():
        if name_index < len(row):
            value = str(row[name_index] or "").strip()
            if value:
                out.append(value)
    return sorted(set(out), key=str.lower)


def _snowflake_scope_metadata(
    *,
    context: dict[str, Any],
    warehouses: list[str],
    databases: list[str],
    schemas: list[str],
    views: list[str],
    selected: dict[str, str],
) -> dict[str, Any]:
    recommended = {
        "warehouse": _pick_scope_value(warehouses, selected.get("warehouse"), "TRUSTOPS_READ_WH"),
        "database": _pick_scope_value(databases, selected.get("database"), "TRUSTOPS_SECURITY_LAKE"),
        "schema": _pick_scope_value(schemas, selected.get("schema"), "EVIDENCE"),
    }
    for purpose, default in DEFAULT_VIEWS.items():
        recommended[purpose] = _pick_view_value(views, selected.get(purpose), purpose, default)
    selectors = [
        *_selector_rows("warehouse", warehouses, selected=recommended["warehouse"], required=True),
        *_selector_rows("database", databases, selected=recommended["database"], required=True),
        *_selector_rows("schema", schemas, selected=recommended["schema"], required=True),
        *[
            {
                "kind": "view",
                "name": view,
                "purpose": _view_purpose(view),
                "required": _view_purpose(view) in DEFAULT_VIEWS,
                "selected": view.upper() in {recommended[purpose].upper() for purpose in VIEW_PURPOSES},
            }
            for view in views
        ],
    ]
    requires_selection = [
        field
        for field in ("warehouse", "database", "schema", *VIEW_PURPOSES)
        if not str(recommended.get(field) or "").strip()
    ]
    return {
        "ok": True,
        "selection_mode": "live_snowflake_scope",
        "context": context,
        "selectors": selectors,
        "requires_selection": requires_selection,
        "candidates": {
            "warehouses": warehouses,
            "databases": databases,
            "schemas": schemas,
            "views": views,
        },
        "recommended_options": {key: value for key, value in recommended.items() if value},
    }


def _selector_rows(kind: str, values: list[str], *, selected: str, required: bool) -> list[dict[str, Any]]:
    if not values and selected:
        values = [selected]
    return [
        {
            "kind": kind,
            "name": value,
            "required": required,
            "selected": bool(selected and value.upper() == selected.upper()),
        }
        for value in values
    ]


def _pick_scope_value(values: list[str], selected: str | None, default: str) -> str:
    return _pick_name(values, selected) or _pick_name(values, default) or (values[0] if values else "")


def _pick_view_value(values: list[str], selected: str | None, purpose: str, default: str) -> str:
    return (
        _pick_name(values, selected)
        or _pick_name(values, default)
        or next((value for value in values if _view_purpose(value) == purpose), "")
    )


def _pick_name(values: list[str], name: str | None) -> str:
    if not name:
        return ""
    for value in values:
        if value.upper() == str(name).upper():
            return value
    return ""


def _view_purpose(name: str) -> str:
    text = name.upper()
    if "AUDIT" in text and "EVENT" in text:
        return "audit_events"
    if "CONTROL" in text and ("POSTURE" in text or "STATUS" in text):
        return "control_posture"
    if "ASSET" in text and "RISK" in text:
        return "asset_risk"
    if "EVIDENCE" in text and ("BUNDLE" in text or "ARTIFACT" in text):
        return "evidence_bundles"
    return "view"


def _view_probe_check(cursor: Any, *, purpose: str, view: str) -> dict[str, Any]:
    try:
        cursor.execute(f"SELECT COUNT(*) FROM {view}")  # noqa: S608 - identifier is strictly validated above
        row = cursor.fetchone() or (0,)
        return {
            "purpose": purpose,
            "view": view,
            "ok": True,
            "row_count": int(row[0] or 0),
            "error": None,
        }
    except Exception as exc:  # pragma: no cover - live Snowflake only
        return {
            "purpose": purpose,
            "view": view,
            "ok": False,
            "row_count": None,
            "error": _snowflake_error_message(exc),
        }


def _snowflake_error_message(exc: Exception) -> str:
    text = str(exc).lower()
    if "does not exist" in text or "not exist" in text:
        return "object not found or not granted to the active role"
    if "not authorized" in text or "insufficient privileges" in text or "privilege" in text:
        return "active role is missing required read privileges"
    if "warehouse" in text and ("suspended" in text or "does not exist" in text):
        return "warehouse is unavailable or not granted to the active role"
    if "timeout" in text or "timed out" in text:
        return "Snowflake probe timed out"
    return exc.__class__.__name__


def _safe_identifier(value: str) -> str:
    """Validate a Snowflake identifier/view reference used in SELECT statements."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("Snowflake view name must not be empty")
    parts = text.split(".")
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", part) for part in parts):
        raise ValueError(f"unsafe Snowflake view identifier {value!r}")
    return ".".join(parts)
