"""Framework registry and control catalog validation."""

from __future__ import annotations

import copy
import json
import os
import sys
import sysconfig
from functools import lru_cache
from pathlib import Path
from typing import Any

from security_lakehouse.policy import validate_rule


def _data_root() -> Path:
    """Return the directory holding ``frameworks/``, ``controls/``, ``mappings/``.

    Resolution order:
      1. ``TRUSTOPS_DATA_DIR`` environment variable — set by the Docker
         image and Helm chart so the wheel can find the JSON catalogs.
      2. The user-install data scheme, only when this module was installed there.
      3. Known install/check-out roots that contain the runtime catalogs.
         Editable installs keep them in the repository root; wheels install
         ``data-files`` under the environment prefix.
    """
    override = os.environ.get("TRUSTOPS_DATA_DIR")
    if override:
        return Path(override)
    module_path = Path(__file__).resolve()
    user_scheme = sysconfig.get_preferred_scheme("user")
    user_libraries = (Path(sysconfig.get_path(name, scheme=user_scheme)).resolve() for name in ("purelib", "platlib"))
    if any(module_path.is_relative_to(directory) for directory in user_libraries):
        # Only the active user-installed wheel may use user data. Do not borrow
        # catalogs from an unrelated system installation if these are missing.
        return Path(sysconfig.get_path("data", scheme=user_scheme))
    candidates = (
        module_path.parents[2],
        Path(sys.prefix),
        Path(sys.base_prefix),
    )
    for candidate in candidates:
        if (candidate / "connectors" / "catalog.json").is_file() and (
            candidate / "controls" / "catalog.json"
        ).is_file():
            return candidate
    return module_path.parents[2]


ROOT = _data_root()
DEFAULT_FRAMEWORK_REGISTRY = ROOT / "frameworks" / "registry.json"
DEFAULT_CONTROL_CATALOG = ROOT / "controls" / "catalog.json"

FRAMEWORK_IMPLEMENTATION_STATUSES = frozenset(
    {
        "implemented_full_pack",
        "implemented_limited_mapping",
        "referenced_only",
        "planned",
    }
)
CONTROL_IMPLEMENTATION_STATUSES = frozenset(
    {"implemented", "implemented_limited_mapping", "referenced_only", "planned"}
)


def load_framework_registry(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    payload = _read_json(path or DEFAULT_FRAMEWORK_REGISTRY)
    frameworks = payload.get("frameworks")
    if not isinstance(frameworks, list):
        raise ValueError("framework registry must contain a frameworks list")
    return {str(item["framework_id"]): item for item in frameworks}


def load_control_catalog(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    payload = _read_json(path or DEFAULT_CONTROL_CATALOG)
    controls = payload.get("controls")
    if not isinstance(controls, list):
        raise ValueError("control catalog must contain a controls list")
    return {str(item["control_id"]): item for item in controls}


def validate_catalog(
    *,
    registry_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
) -> list[str]:
    errors: list[str] = []
    registry = load_framework_registry(registry_path)
    catalog = load_control_catalog(catalog_path)
    for framework_id, framework in registry.items():
        for required in ("name", "version", "official_source_url", "implementation_status"):
            if not str(framework.get(required, "")).strip():
                errors.append(f"framework {framework_id} missing {required}")
        status = str(framework.get("implementation_status") or "")
        if status not in FRAMEWORK_IMPLEMENTATION_STATUSES:
            errors.append(
                f"framework {framework_id} implementation_status {status!r} "
                f"not in {sorted(FRAMEWORK_IMPLEMENTATION_STATUSES)}"
            )
        seeded = [cid for cid, control in catalog.items() if str(control.get("framework_id") or "") == framework_id]
        if status in {"planned", "referenced_only"} and seeded:
            errors.append(
                f"framework {framework_id} is {status} but catalog seeds {len(seeded)} control(s); "
                "planned/referenced frameworks must not ship controls"
            )
        if status.startswith("implemented") and not seeded:
            errors.append(f"framework {framework_id} is {status} but has no seeded controls")
    for control_id, control in catalog.items():
        framework_id = str(control.get("framework_id") or "")
        if framework_id not in registry:
            errors.append(f"control {control_id} references unknown framework_id {framework_id}")
        for required in (
            "framework",
            "title",
            "risk_domain",
            "owner",
            "evidence_requirement",
            "evaluation_rule",
            "frequency",
            "implementation_status",
            "official_source_ref",
            *PROVENANCE_FIELDS,
        ):
            if not str(control.get(required, "")).strip():
                errors.append(f"control {control_id} missing {required}")
        errors.extend(f"control {control_id}: {problem}" for problem in validate_rule(control.get("evaluation_rule")))
        control_status = str(control.get("implementation_status") or "")
        if control_status not in CONTROL_IMPLEMENTATION_STATUSES:
            errors.append(
                f"control {control_id} implementation_status {control_status!r} "
                f"not in {sorted(CONTROL_IMPLEMENTATION_STATUSES)}"
            )
        framework_status = str(registry.get(framework_id, {}).get("implementation_status") or "")
        if framework_status in {"planned", "referenced_only"}:
            errors.append(f"control {control_id} references {framework_status} framework {framework_id}")
        if control.get("official_source_ref") != framework_id:
            errors.append(f"control {control_id} official_source_ref must match framework_id")
        asset_types = control.get("asset_types")
        if not isinstance(asset_types, list) or not asset_types:
            errors.append(f"control {control_id} must declare a non-empty asset_types list")
        errors.extend(_validate_version_fields(control_id, control))
    return errors


_LIFECYCLE_STATES = {"active", "draft", "retired"}


def _coerce_date(value: Any) -> Any:
    """Return a date for an ISO date/datetime string, or None if unparseable."""
    if not value:
        return None
    from datetime import date, datetime

    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date() if ("T" in text or "+" in text) else date.fromisoformat(text)
    except ValueError:
        return None


def _validate_version_fields(control_id: str, control: dict[str, Any]) -> list[str]:
    """Validate the temporal/version fields on a v2 control (additive).

    A control with no version fields is a valid pre-v2 row (defaults apply), so
    only validate fields that are actually present.
    """
    errors: list[str] = []
    if "version" in control and not str(control.get("version", "")).strip():
        errors.append(f"control {control_id} version must not be empty when present")
    lifecycle = control.get("lifecycle_status")
    if lifecycle is not None and lifecycle not in _LIFECYCLE_STATES:
        errors.append(f"control {control_id} lifecycle_status {lifecycle!r} not in {sorted(_LIFECYCLE_STATES)}")
    valid_from_raw = control.get("valid_from")
    valid_to_raw = control.get("valid_to")
    valid_from = _coerce_date(valid_from_raw)
    valid_to = _coerce_date(valid_to_raw)
    if valid_from_raw and valid_from is None:
        errors.append(f"control {control_id} has unparseable valid_from {valid_from_raw!r}")
    if valid_to_raw and valid_to is None:
        errors.append(f"control {control_id} has unparseable valid_to {valid_to_raw!r}")
    if valid_from and valid_to and valid_to < valid_from:
        errors.append(f"control {control_id} valid_to precedes valid_from")
    if valid_to_raw and lifecycle == "active":
        errors.append(f"control {control_id} is active but has valid_to set (should be retired)")
    return errors


def controls_for_asset_type(asset_type: str, catalog_path: str | Path | None = None) -> list[str]:
    """Return the control ids that apply to ``asset_type``, sorted.

    Answers "which controls apply to this asset?" from the catalog's declared
    applicability, independent of whether evidence exists yet.
    """
    catalog = load_control_catalog(catalog_path)
    return sorted(
        control_id for control_id, control in catalog.items() if asset_type in (control.get("asset_types") or [])
    )


# Source-provenance every control must carry so mappings are auditable, not
# "vibes": where the control text came from, why the signal satisfies it, who
# reviewed it, and which signal feeds the test.
PROVENANCE_FIELDS = (
    "framework_ref",
    "source_url",
    "mapping_rationale",
    "reviewed_by",
    "reviewed_date",
    "signal_source",
)


def controls_missing_provenance(catalog_path: str | Path | None = None) -> dict[str, list[str]]:
    """Return ``{control_id: [missing provenance fields]}`` for any gaps."""
    catalog = load_control_catalog(catalog_path)
    out: dict[str, list[str]] = {}
    for control_id, control in catalog.items():
        missing = [f for f in PROVENANCE_FIELDS if not str(control.get(f, "")).strip()]
        if missing:
            out[control_id] = missing
    return out


def validate_evidence_controls(control_ids: set[str], catalog_path: str | Path | None = None) -> list[str]:
    catalog = load_control_catalog(catalog_path)
    return [f"evidence references unmapped control {control_id}" for control_id in sorted(control_ids - set(catalog))]


def _read_json(path: str | Path) -> dict[str, Any]:
    source = Path(path).resolve()
    stat = source.stat()
    fingerprint = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    return copy.deepcopy(_cached_json(str(source), fingerprint))


@lru_cache(maxsize=32)
def _cached_json(path: str, fingerprint: tuple[int, ...]) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload
