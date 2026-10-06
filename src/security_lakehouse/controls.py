"""Control mapping helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_lakehouse.catalog import _data_root
from security_lakehouse.io import read_json
from security_lakehouse.policy import PolicyError, validate_rule

ROOT = _data_root()
DEFAULT_MAPPING_PATH = ROOT / "mappings" / "control_map.json"
DEFAULT_CATALOG_PATH = ROOT / "controls" / "catalog.json"


def load_control_map(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    raw = read_json(path or DEFAULT_CATALOG_PATH)
    controls = raw.get("controls") if isinstance(raw, dict) else None
    if not isinstance(controls, list):
        raise ValueError("control map must contain a controls list")
    mapped: dict[str, dict[str, Any]] = {}
    for control in controls:
        if not isinstance(control, dict) or not str(control.get("control_id", "")).strip():
            raise ValueError("every control mapping must include control_id")
        control_id = str(control["control_id"])
        if control_id in mapped:
            raise ValueError(f"duplicate control mapping: {control_id}")
        problems = validate_rule(control.get("evaluation_rule"))
        if problems:
            raise PolicyError(f"control {control_id}: " + "; ".join(problems))
        mapped[control_id] = control
    return mapped


def expand_controls(control_ids: list[str], control_map: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for control_id in dict.fromkeys(control_ids):
        control = control_map.get(control_id)
        if control is None:
            expanded.append(
                {
                    "control_id": control_id,
                    "framework": "unmapped",
                    "title": "Unmapped control",
                    "risk_domain": "unknown",
                    "owner": "security",
                }
            )
        else:
            expanded.append(control)
    return expanded
