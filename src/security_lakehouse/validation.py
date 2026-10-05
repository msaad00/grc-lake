"""Strict validation for raw security lake events."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from security_lakehouse.strict_json import InvalidJSON, validate

REQUIRED_FIELDS = {"event_id", "tenant_id", "event_time", "source", "event_type", "entity"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "none"}


TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})$"
)


def evidence_timestamp(value: object) -> datetime:
    """New evidence requires an explicit timezone; legacy readers keep their policy."""
    if not isinstance(value, str) or not re.fullmatch(TIMESTAMP_PATTERN, value):
        raise ValueError("timestamp must include a date, time, and timezone")
    return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))


def validate_raw_event(row: dict[str, Any], *, index: int | None = None) -> list[str]:
    prefix = f"record {index}: " if index is not None else ""
    errors: list[str] = []
    if not isinstance(row, dict):
        return [f"{prefix}event must be an object"]
    try:
        validate(row)
    except InvalidJSON as exc:
        errors.append(f"{prefix}{exc.msg}")
    missing = sorted(REQUIRED_FIELDS - set(row))
    if missing:
        errors.append(f"{prefix}missing required fields: {', '.join(missing)}")
    for key in REQUIRED_FIELDS - {"entity"}:
        if key in row and (not isinstance(row[key], str) or not row[key].strip()):
            errors.append(f"{prefix}{key} must be a nonempty string")
    if "event_time" in row:
        try:
            evidence_timestamp(row["event_time"])
        except ValueError:
            errors.append(f"{prefix}event_time must be a timezone-qualified ISO-8601 timestamp")
    if not isinstance(row.get("entity"), dict):
        errors.append(f"{prefix}entity must be an object")
    severity = row.get("severity", "info")
    if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
        errors.append(f"{prefix}severity must be one of {sorted(VALID_SEVERITIES)}")
    if "status" in row and not isinstance(row["status"], str):
        errors.append(f"{prefix}status must be a string")
    for field in ("controls", "safeguard_ids"):
        values = row.get(field, [])
        if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
            errors.append(f"{prefix}{field} must be a list of nonempty identifiers")
    evidence = row.get("evidence", {})
    if not isinstance(evidence, dict):
        errors.append(f"{prefix}evidence must be an object")
    else:
        for key in ("uri", "ref", "evidence_ref", "evidence_id"):
            if key in evidence and not isinstance(evidence[key], str):
                errors.append(f"{prefix}evidence.{key} must be a string")
        for key in ("collected_at", "evidence_collected_at"):
            if key in evidence:
                try:
                    evidence_timestamp(evidence[key])
                except ValueError:
                    errors.append(f"{prefix}evidence.{key} must be a timezone-qualified ISO-8601 timestamp")
    if not isinstance(row.get("attributes", {}), dict):
        errors.append(f"{prefix}attributes must be an object")
    return errors


def validate_raw_events(rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        errors.extend(validate_raw_event(row, index=index))
        if not isinstance(row, dict):
            continue
        event_id = str(row.get("event_id", ""))
        if event_id in seen:
            errors.append(f"record {index}: duplicate event_id {event_id}")
        seen.add(event_id)
    return errors
