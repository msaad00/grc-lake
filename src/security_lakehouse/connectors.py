"""Connector registry and access-boundary validation."""

from __future__ import annotations

import importlib.metadata
import json
import logging
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import _data_root  # noqa: PLC2701 (reused root lookup)

logger = logging.getLogger(__name__)

ROOT = _data_root()
DEFAULT_CONNECTOR_CATALOG = ROOT / "connectors" / "catalog.json"
CONNECTOR_BUILDER_ENTRY_POINT_GROUP = "trustops.connectors"
CONNECTOR_CATALOG_ENTRY_POINT_GROUP = "trustops.connector_catalog"

VALID_COLLECTION_MODES = {"existing_lake_read", "direct_api_read", "managed_evidence_object"}
VALID_ACCESS_BOUNDARIES = {"read_only_role", "scoped_token", "dedicated_schema"}
VALID_ROUTES = {"Snowflake", "ClickHouse", "dual", "local"}
VALID_PRODUCTION_STATUSES = {"primary_lake", "supported_connector", "local_demo"}
# Optional. "preview" marks an implemented connector not yet verified against a
# live tenant; absent means generally available.
VALID_RELEASE_STAGES = {"ga", "preview"}
DENIED_PERMISSION_WORDS = {"admin", "delete", "drop", "modify", "owner", "write all", "root"}
EXPLICIT_READ_ONLY_PERMISSIONS = {"administration:read"}
SENSITIVE_FIELD_NAMES = {
    "password",
    "passphrase",
    "secret",
    "token",
    "private_key",
    "client_secret",
    "api_key",
    "apikey",
    "authorization",
}


def load_connector_catalog(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the connector catalog.

    With no ``path``, rows contributed by installed packages (see
    :func:`installed_connector_rows`) are merged after the in-repo rows. An
    explicit ``path`` reads that file only.
    """
    catalog = _read_catalog_file(path or DEFAULT_CONNECTOR_CATALOG)
    if path is None:
        catalog.update(installed_connector_rows(frozenset(catalog)))
    return catalog


def _read_catalog_file(path: str | Path) -> dict[str, dict[str, Any]]:
    payload = _read_json(path)
    connectors = payload.get("connectors")
    if not isinstance(connectors, list):
        raise ValueError("connector catalog must contain a connectors list")
    return {str(item["connector_id"]): item for item in connectors}


def installed_connector_rows(builtin_ids: frozenset[str]) -> dict[str, dict[str, Any]]:
    """Catalog rows registered by installed packages under
    ``trustops.connector_catalog``.

    Each entry point's name is the connector_id and must resolve to a mapping
    (or a zero-argument callable returning one) shaped like a
    ``connectors/catalog.json`` row. A row is admitted only if it passes
    :func:`validate_connector_row`, its ``connector_id`` matches the entry
    point name, it does not collide with a built-in connector_id, and a
    callable builder of the same name is registered under
    ``trustops.connectors`` — the catalog never advertises a connector that
    cannot sync. Rejected rows are logged and excluded, never raised.
    """
    rows = _load_entry_points(CONNECTOR_CATALOG_ENTRY_POINT_GROUP)
    if not rows:
        return {}
    builders = {
        name for name, (_, obj) in _load_entry_points(CONNECTOR_BUILDER_ENTRY_POINT_GROUP).items() if callable(obj)
    }
    admitted: dict[str, dict[str, Any]] = {}
    for connector_id, (value, loaded) in rows.items():
        try:
            row = loaded() if callable(loaded) else loaded
        except Exception:
            logger.warning(
                "connector catalog entry point %r (%s) raised building its row; excluding it",
                connector_id,
                value,
                exc_info=True,
            )
            continue
        reason = _reject_reason(connector_id, row, builtin_ids, builders)
        if reason:
            logger.warning("connector catalog entry point %r (%s) excluded: %s", connector_id, value, reason)
            continue
        admitted[connector_id] = {
            **row,
            "is_implemented": True,
            "provenance": {"source": "entry_point", "entry_point": value},
        }
    return admitted


def _reject_reason(connector_id: str, row: Any, builtin_ids: frozenset[str], builders: set[str]) -> str | None:
    if not isinstance(row, dict):
        return "did not resolve to a catalog row mapping"
    if connector_id in builtin_ids:
        return "collides with a built-in connector_id; the built-in row wins"
    if str(row.get("connector_id", "")) != connector_id:
        return f"row connector_id {row.get('connector_id')!r} does not match the entry point name"
    if connector_id not in builders:
        return f"no loadable {CONNECTOR_BUILDER_ENTRY_POINT_GROUP} builder is registered under the same name"
    if row.get("production_status") == "primary_lake":
        return "only a built-in connector may be the primary_lake"
    errors = validate_connector_row(connector_id, row)
    return "; ".join(errors) or None


def _load_entry_points(group: str) -> dict[str, tuple[str, Any]]:
    try:
        entry_points = importlib.metadata.entry_points(group=group)
    except Exception:
        logger.warning("failed to enumerate %s entry points", group, exc_info=True)
        return {}
    loaded: dict[str, tuple[str, Any]] = {}
    for entry_point in entry_points:
        try:
            loaded[entry_point.name] = (entry_point.value, entry_point.load())
        except Exception:
            logger.warning(
                "%s entry point %r (%s) failed to load; excluding it",
                group,
                entry_point.name,
                entry_point.value,
                exc_info=True,
            )
    return loaded


def validate_connector_catalog(path: str | Path | None = None) -> list[str]:
    connectors = _read_catalog_file(path or DEFAULT_CONNECTOR_CATALOG)
    errors: list[str] = []
    for connector_id, connector in connectors.items():
        errors.extend(validate_connector_row(connector_id, connector))
    return errors


def validate_connector_row(connector_id: str, connector: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for required in (
        "name",
        "category",
        "collection_mode",
        "access_boundary",
        "credential_type",
        "minimum_permissions",
        "evidence_types",
        "default_route",
        "freshness_slo_minutes",
        "production_status",
    ):
        if connector.get(required) in (None, "", []):
            errors.append(f"connector {connector_id} missing {required}")

    mode = str(connector.get("collection_mode", ""))
    boundary = str(connector.get("access_boundary", ""))
    route = str(connector.get("default_route", ""))
    production_status = str(connector.get("production_status", ""))
    permissions = [str(item).lower() for item in connector.get("minimum_permissions", [])]

    if mode not in VALID_COLLECTION_MODES:
        errors.append(f"connector {connector_id} has invalid collection_mode {mode}")
    if boundary not in VALID_ACCESS_BOUNDARIES:
        errors.append(f"connector {connector_id} has invalid access_boundary {boundary}")
    if route not in VALID_ROUTES:
        errors.append(f"connector {connector_id} has invalid default_route {route}")
    if production_status not in VALID_PRODUCTION_STATUSES:
        errors.append(f"connector {connector_id} has invalid production_status {production_status}")
    if "release_stage" in connector and connector["release_stage"] not in VALID_RELEASE_STAGES:
        errors.append(f"connector {connector_id} has invalid release_stage {connector['release_stage']}")
    if int(connector.get("freshness_slo_minutes") or 0) <= 0:
        errors.append(f"connector {connector_id} freshness_slo_minutes must be positive")

    if mode == "existing_lake_read" and boundary != "read_only_role":
        errors.append(f"connector {connector_id} existing_lake_read must use read_only_role")
    if mode == "direct_api_read" and boundary != "scoped_token":
        errors.append(f"connector {connector_id} direct_api_read must use scoped_token")
    if mode == "managed_evidence_object" and boundary != "dedicated_schema":
        errors.append(f"connector {connector_id} managed_evidence_object must use dedicated_schema")

    for permission in permissions:
        if permission not in EXPLICIT_READ_ONLY_PERMISSIONS and any(
            word in permission for word in DENIED_PERMISSION_WORDS
        ):
            errors.append(f"connector {connector_id} permission is too broad: {permission}")

    for field_name, value in _flatten(connector):
        lowered = field_name.lower()
        if any(sensitive in lowered for sensitive in SENSITIVE_FIELD_NAMES):
            errors.append(f"connector {connector_id} contains secret-like field {field_name}")
        if isinstance(value, str) and _looks_like_secret(value):
            errors.append(f"connector {connector_id} contains secret-like value in {field_name}")
    return errors


def _read_json(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _flatten(payload: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(payload, dict):
        rows: list[tuple[str, Any]] = []
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_flatten(value, name))
        return rows
    if isinstance(payload, list):
        rows = []
        for index, value in enumerate(payload):
            rows.extend(_flatten(value, f"{prefix}[{index}]"))
        return rows
    return [(prefix, payload)]


def _looks_like_secret(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 24:
        return False
    secret_prefixes = ("ghp_", "gho_", "xoxb-", "sk-", "AKIA")
    return stripped.startswith(secret_prefixes)
