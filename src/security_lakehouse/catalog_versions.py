"""Versioned control catalog: latest, history, retire, as-of, and bundle hash.

Frameworks and controls are living artifacts. Regulations get revised, mappings
get re-reviewed, controls are retired and superseded. An audit must be able to
say *exactly* which control text and which framework version were in force
during its window, and reproduce that view later.

This module makes the control catalog **bivalent-temporal** without changing
the shape of the active set:

  * ``controls/catalog.json`` stays the *current* set — one row per
    ``control_id``, each carrying ``version`` + ``valid_from`` +
    ``valid_to`` (null = in force) + ``supersedes`` / ``superseded_by`` +
    ``lifecycle_status``.
  * ``controls/history.jsonl`` is an append-only ledger of every retired
    control version. Retiring never deletes — it closes ``valid_to`` and moves
    the row to history, optionally pointing ``superseded_by`` at its successor.

A **catalog bundle** is the content-addressed lockfile that ties an audit to a
point in catalog evolution: a sha256 over the framework registry + active
controls + crosswalk + safeguards, plus per-component digests and framework
versions. Snapshots embed this manifest to identify the evaluated catalog.
Re-execution also requires retaining the matching catalog bodies and evaluator
version; a digest alone cannot reconstruct them.

The module is pure/deterministic except :func:`retire_control` and
:func:`write_bundle_lock`, which are the only writers.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import (
    DEFAULT_CONTROL_CATALOG,
    load_control_catalog,
    load_framework_registry,
)
from security_lakehouse.io import append_jsonl, read_jsonl
from security_lakehouse.models import instant_sort_key
from security_lakehouse.safeguards import load_safeguards

CONTROL_SCHEMA_VERSION = "trustops.control.v2"
BUNDLE_SCHEMA_VERSION = "trustops.catalog_bundle.v1"

# Version fields every versioned control carries. Defaults keep pre-v2 catalogs
# loadable: a control with none of these is treated as version 1.0.0, active.
VERSION_FIELDS = (
    "version",
    "valid_from",
    "valid_to",
    "supersedes",
    "superseded_by",
    "change_reason",
    "lifecycle_status",
)

DEFAULT_HISTORY_PATH = DEFAULT_CONTROL_CATALOG.parent / "history.jsonl"
DEFAULT_CROSSWALK_PATH = DEFAULT_CONTROL_CATALOG.parent.parent / "mappings" / "control_articles.json"
DEFAULT_BUNDLE_LOCK_PATH = DEFAULT_CONTROL_CATALOG.parent / "bundle.lock.json"


def _utc_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_date(value: str | date | datetime | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).date() if value.tzinfo else value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        if "T" in text or "+" in text or " " in text:
            return datetime.fromisoformat(text).date()
        return date.fromisoformat(text)
    except ValueError as exc:  # surface as caller-handleable
        raise ValueError(f"unparseable date: {value!r}") from exc


def _with_version_defaults(control: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``control`` with version fields filled to defaults."""
    out = dict(control)
    out.setdefault("version", "1.0.0")
    out.setdefault("valid_from", out.get("reviewed_date"))
    out.setdefault("valid_to", None)
    out.setdefault("supersedes", None)
    out.setdefault("superseded_by", None)
    out.setdefault("change_reason", "Initial versioned catalog baseline")
    out.setdefault("lifecycle_status", "retired" if out.get("valid_to") else "active")
    return out


def active_controls(catalog_path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Return the current (in-force) controls keyed by ``control_id``.

    Version fields are normalized to defaults so callers never have to special
    case a pre-v2 catalog.
    """
    raw = load_control_catalog(catalog_path)
    return {cid: _with_version_defaults(control) for cid, control in raw.items()}


def load_history(history_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return all retired control versions, oldest-first by ``retired_at``."""
    rows = read_jsonl(Path(history_path or DEFAULT_HISTORY_PATH), missing_ok=True)
    return sorted(rows, key=lambda r: instant_sort_key(r.get("retired_at")))


def control_history(
    control_id: str,
    *,
    catalog_path: str | Path | None = None,
    history_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return every version of ``control_id`` (retired + active), oldest-first.

    Each row is a control body plus version fields. The active version (if the
    control still exists in the catalog) is last and has ``valid_to`` null.
    """
    versions = [row for row in load_history(history_path) if row.get("control_id") == control_id]
    active = active_controls(catalog_path).get(control_id)
    if active is not None:
        versions.append(active)
    versions.sort(key=lambda r: (instant_sort_key(r.get("valid_from")), str(r.get("version") or "")))
    return versions


def controls_as_of(
    as_of: str | date | datetime,
    *,
    catalog_path: str | Path | None = None,
    history_path: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Reconstruct the control versions in force on ``as_of``, keyed by id.

    A version is in force on ``D`` when ``valid_from <= D`` and
    (``valid_to`` is null or ``D < valid_to``). When more than one version of a
    control qualifies (overlapping windows in bad data), the latest
    ``valid_from`` wins. This is the query an audit pins to.
    """
    target = _parse_date(as_of)
    if target is None:
        raise ValueError("as_of must be a date")
    candidates: list[dict[str, Any]] = list(load_history(history_path))
    candidates.extend(active_controls(catalog_path).values())

    chosen: dict[str, dict[str, Any]] = {}
    chosen_from: dict[str, date] = {}
    for control in candidates:
        cid = str(control.get("control_id") or "")
        if not cid:
            continue
        start = _parse_date(control.get("valid_from"))
        end = _parse_date(control.get("valid_to"))
        if start is not None and start > target:
            continue
        if end is not None and target >= end:
            continue
        prior = chosen_from.get(cid)
        if prior is None or (start is not None and start >= prior):
            chosen[cid] = _with_version_defaults(control)
            chosen_from[cid] = start or date.min
    return chosen


def _bump_version(version: str) -> str:
    """Return the next minor version for a ``major.minor.patch`` string."""
    parts = str(version or "1.0.0").split(".")
    while len(parts) < 3:
        parts.append("0")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except ValueError:
        return "1.1.0"
    return f"{major}.{minor + 1}.0"


def retire_control(
    control_id: str,
    *,
    change_reason: str,
    superseded_by: str | None = None,
    catalog_path: str | Path | None = None,
    history_path: str | Path | None = None,
    successor: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Retire the active version of ``control_id`` and append it to history.

    Closes the active row's ``valid_to`` (= today), stamps
    ``lifecycle_status='retired'`` + ``superseded_by``, and appends it to
    ``controls/history.jsonl``. The active catalog is rewritten: the retired
    control is removed, and an optional ``successor`` (a new control body) is
    inserted as the next version with ``supersedes`` back-linked. History is
    never mutated — retiring only ever appends.

    Returns ``{"retired": <row>, "successor": <row or None>}``.
    """
    catalog_file = Path(catalog_path or DEFAULT_CONTROL_CATALOG)
    payload = json.loads(catalog_file.read_text(encoding="utf-8"))
    controls = payload.get("controls")
    if not isinstance(controls, list):
        raise ValueError("control catalog must contain a controls list")
    idx = next((i for i, c in enumerate(controls) if str(c.get("control_id")) == control_id), None)
    if idx is None:
        raise KeyError(f"control {control_id} is not in the active catalog")

    stamp = (now or datetime.now(UTC)).astimezone(UTC)
    today_iso = stamp.date().isoformat()
    retired = _with_version_defaults(controls[idx])
    retired["valid_to"] = today_iso
    retired["lifecycle_status"] = "retired"
    retired["change_reason"] = change_reason
    if superseded_by:
        retired["superseded_by"] = superseded_by

    history_row = OrderedDict(retired)
    history_row["retired_at"] = _utc_iso()
    append_jsonl(Path(history_path or DEFAULT_HISTORY_PATH), dict(history_row))

    successor_row: dict[str, Any] | None = None
    if successor is not None:
        successor_row = _with_version_defaults(successor)
        successor_row.setdefault("control_id", control_id)
        if successor_row.get("version") in (None, retired.get("version")):
            successor_row["version"] = _bump_version(retired.get("version", "1.0.0"))
        # The successor takes force when the predecessor is retired, unless the
        # caller pinned a later effective date explicitly.
        explicit_from = _parse_date(successor.get("valid_from"))
        retired_from = _parse_date(retired.get("valid_from"))
        if explicit_from is not None and (retired_from is None or explicit_from > retired_from):
            successor_row["valid_from"] = explicit_from.isoformat()
        else:
            successor_row["valid_from"] = today_iso
        successor_row["valid_to"] = None
        successor_row["supersedes"] = f"{control_id}@{retired.get('version')}"
        successor_row["lifecycle_status"] = "active"
        controls[idx] = successor_row
    else:
        controls.pop(idx)

    catalog_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {"retired": retired, "successor": successor_row}


# --------------------------------------------------------------------------- #
# Catalog bundle: content-addressed lockfile an audit pins to.
# --------------------------------------------------------------------------- #


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _framework_versions(registry: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        {
            "framework_id": fid,
            "version": fw.get("version"),
            "effective_date": fw.get("effective_date"),
            "superseded_by": fw.get("superseded_by"),
            "source_sha256": fw.get("source_sha256"),
        }
        for fid, fw in registry.items()
    ]
    return sorted(rows, key=lambda r: str(r["framework_id"]))


def _control_versions(controls: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        {
            "control_id": cid,
            "framework_id": c.get("framework_id"),
            "version": c.get("version"),
            "valid_from": c.get("valid_from"),
            "lifecycle_status": c.get("lifecycle_status"),
        }
        for cid, c in controls.items()
    ]
    return sorted(rows, key=lambda r: str(r["control_id"]))


def compute_bundle(
    *,
    registry_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    crosswalk_path: str | Path | None = None,
    safeguards_path: str | Path | None = None,
    as_of: str | date | datetime | None = None,
    history_path: str | Path | None = None,
) -> dict[str, Any]:
    """Compute the content-addressed catalog bundle.

    Deterministic: the same registry + controls + crosswalk + safeguards always yield the
    same ``bundle_sha256``. Pass ``as_of`` to bundle the historical control set
    in force on that date instead of the active set. Registry, crosswalk and
    safeguards remain the supplied/current versions; use a saved snapshot
    bundle for the original assessment manifest.
    """
    registry = load_framework_registry(registry_path)
    as_of_date = _parse_date(as_of)
    if as_of is not None:
        controls = controls_as_of(as_of, catalog_path=catalog_path, history_path=history_path)
    else:
        controls = active_controls(catalog_path)
    crosswalk = _load_crosswalk(crosswalk_path)

    framework_versions = _framework_versions(registry)
    control_versions = _control_versions(controls)
    # Component digests cover FULL bodies so any edit (even a title fix that
    # skipped a version bump) drifts the lock and forces human ratification.
    # The *_versions arrays below are the lean, human-readable manifest.
    full_frameworks = sorted((dict(fw) for fw in registry.values()), key=lambda r: str(r.get("framework_id")))
    full_controls = sorted((dict(c) for c in controls.values()), key=lambda r: str(r.get("control_id")))
    components = {
        "frameworks": _digest(full_frameworks),
        "controls": _digest(full_controls),
        "crosswalk": _digest(crosswalk),
        "safeguards": _digest(load_safeguards(safeguards_path)),
    }
    body = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "as_of": as_of_date.isoformat() if as_of_date is not None else None,
        "framework_count": len(framework_versions),
        "control_count": len(control_versions),
        "crosswalk_count": len(crosswalk),
        "components": components,
        "framework_versions": framework_versions,
        "control_versions": control_versions,
    }
    body["bundle_sha256"] = _digest(body)
    return body


def _load_crosswalk(crosswalk_path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(crosswalk_path or DEFAULT_CROSSWALK_PATH)
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    mappings = payload.get("mappings") if isinstance(payload, dict) else payload
    if not isinstance(mappings, list):
        return []
    return sorted(
        (dict(m) for m in mappings if isinstance(m, dict)),
        key=lambda r: (str(r.get("control_id")), str(r.get("article_id"))),
    )


def bundle_summary(**kwargs: Any) -> dict[str, Any]:
    """Compute the bundle and return only its header (no per-row arrays)."""
    bundle = compute_bundle(**kwargs)
    return {k: v for k, v in bundle.items() if k not in ("framework_versions", "control_versions")}


def write_bundle_lock(
    *,
    lock_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    crosswalk_path: str | Path | None = None,
    safeguards_path: str | Path | None = None,
) -> dict[str, Any]:
    """Recompute the active bundle and write it to the lockfile. Returns it."""
    bundle = compute_bundle(
        registry_path=registry_path,
        catalog_path=catalog_path,
        crosswalk_path=crosswalk_path,
        safeguards_path=safeguards_path,
    )
    path = Path(lock_path or DEFAULT_BUNDLE_LOCK_PATH)
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return bundle


def verify_bundle_lock(
    *,
    lock_path: str | Path | None = None,
    registry_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
    crosswalk_path: str | Path | None = None,
    safeguards_path: str | Path | None = None,
) -> dict[str, Any]:
    """Compare the recomputed active bundle to the committed lockfile.

    Returns ``{"ok", "expected", "actual", "drifted_components"}``. ``ok`` is
    False when the lockfile is missing or any component digest differs — the
    signal a CI guard or sync job uses to require human ratification.
    """
    path = Path(lock_path or DEFAULT_BUNDLE_LOCK_PATH)
    actual = compute_bundle(
        registry_path=registry_path,
        catalog_path=catalog_path,
        crosswalk_path=crosswalk_path,
        safeguards_path=safeguards_path,
    )
    if not path.exists():
        return {
            "ok": False,
            "expected": None,
            "actual": actual["bundle_sha256"],
            "drifted_components": ["<no lockfile>"],
        }
    locked = json.loads(path.read_text(encoding="utf-8"))
    drifted = [
        name
        for name, digest in actual.get("components", {}).items()
        if locked.get("components", {}).get(name) != digest
    ]
    ok = locked.get("bundle_sha256") == actual["bundle_sha256"] and not drifted
    return {
        "ok": ok,
        "expected": locked.get("bundle_sha256"),
        "actual": actual["bundle_sha256"],
        "drifted_components": drifted,
    }
