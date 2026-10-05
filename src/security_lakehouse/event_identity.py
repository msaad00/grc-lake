"""Versioned identities for connector-local provider event IDs."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def source_event_key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("connector_id") or ""), str(row.get("event_id") or "")


def event_identity(row: dict[str, Any]) -> str:
    """Keep legacy unscoped IDs; namespace connector IDs without changing raw data."""
    connector, source_id = source_event_key(row)
    if not connector:
        return source_id
    encoded = json.dumps([connector, source_id], separators=(",", ":")).encode("utf-8")
    return "trustops:connector-event:v1:" + hashlib.sha256(encoded).hexdigest()
