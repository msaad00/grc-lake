"""Strict validation for raw security lake events."""

from __future__ import annotations

from typing import Any

from security_lakehouse.models import parse_event_time

REQUIRED_FIELDS = {"event_id", "tenant_id", "event_time", "source", "event_type", "entity"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "none"}


def validate_raw_event(row: dict[str, Any], *, index: int | None = None) -> list[str]:
    prefix = f"record {index}: " if index is not None else ""
    errors: list[str] = []
    missing = sorted(REQUIRED_FIELDS - set(row))
    if missing:
        errors.append(f"{prefix}missing required fields: {', '.join(missing)}")
    for key in REQUIRED_FIELDS - {"entity"}:
        if key in row and not str(row[key]).strip():
            errors.append(f"{prefix}{key} must not be empty")
    if "event_time" in row:
        try:
            parse_event_time(str(row["event_time"]))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{prefix}event_time is not ISO-8601: {exc}")
    entity = row.get("entity")
    if entity is not None and not isinstance(entity, dict):
        errors.append(f"{prefix}entity must be an object")
    severity = str(row.get("severity", "info")).lower()
    if severity not in VALID_SEVERITIES:
        errors.append(f"{prefix}severity must be one of {sorted(VALID_SEVERITIES)}")
    controls = row.get("controls", [])
    if controls is not None and not isinstance(controls, list):
        errors.append(f"{prefix}controls must be a list")
    safeguard_ids = row.get("safeguard_ids", [])
    if not isinstance(safeguard_ids, list) or any(not isinstance(item, str) or not item for item in safeguard_ids):
        errors.append(f"{prefix}safeguard_ids must be a list of nonempty identifiers")
    evidence = row.get("evidence", {})
    if evidence is not None and not isinstance(evidence, dict):
        errors.append(f"{prefix}evidence must be an object")
    attributes = row.get("attributes", {})
    if attributes is not None and not isinstance(attributes, dict):
        errors.append(f"{prefix}attributes must be an object")
    return errors


def validate_raw_events(rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        errors.extend(validate_raw_event(row, index=index))
        event_id = str(row.get("event_id", ""))
        if event_id in seen:
            errors.append(f"record {index}: duplicate event_id {event_id}")
        seen.add(event_id)
    return errors
