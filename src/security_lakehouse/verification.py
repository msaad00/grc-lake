"""Evidence integrity verification.

Checks published generation hashes and compares the bronze raw hash with its
silver reference. Unsealed legacy lakes retain the narrower bronze-hash check;
neither mode establishes external authenticity.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from security_lakehouse.event_identity import event_identity
from security_lakehouse.generations import ARTIFACTS, generation_reader, pin_generation, verify_generation
from security_lakehouse.io import canonical_sha256 as _canonical_sha256
from security_lakehouse.io import file_sha256, read_json, read_jsonl


def _bronze_paths(lake_dir: str | Path) -> list[Path]:
    bronze = Path(lake_dir) / "bronze"
    if not bronze.is_dir():
        return []
    return sorted(bronze.glob("*.jsonl"))


def _silver_record(lake_dir: str | Path, event_id: str) -> dict[str, Any] | None:
    silver = Path(lake_dir) / "silver" / "normalized_events.jsonl"
    if not silver.is_file():
        return None
    for row in read_jsonl(silver):
        if row.get("event_id") == event_id:
            return row
    return None


def _bronze_record(lake_dir: str | Path, event_id: str) -> dict[str, Any] | None:
    for path in _bronze_paths(lake_dir):
        for row in read_jsonl(path):
            raw = row.get("raw") or {}
            if row.get("event_id") == event_id or event_identity(raw) == event_id or raw.get("event_id") == event_id:
                return row
    return None


@generation_reader
def verify_event(lake_dir: str | Path, event_id: str) -> dict[str, Any]:
    """Verify a silver event's hash against its bronze source.

    Returns a payload of the form::

        {
            "event_id": str,
            "verified": bool,
            "expected_sha256": str | None,    # value stored on the silver row
            "computed_sha256": str | None,    # rehash of bronze raw bytes
            "source_layer": "bronze" | "missing",
            "reason": str | None,
        }
    """
    with pin_generation(lake_dir) as generation:
        if generation is None and (Path(lake_dir) / "generation.json").is_file():
            generation = Path(lake_dir)
        if generation is not None:
            try:
                verify_generation(generation)
            except (ValueError, OSError):
                return {
                    "event_id": event_id,
                    "verified": False,
                    "expected_sha256": None,
                    "computed_sha256": None,
                    "source_layer": "missing",
                    "reason": "assessment generation integrity verification failed",
                }
    silver = _silver_record(lake_dir, event_id)
    if silver is None:
        return {
            "event_id": event_id,
            "verified": False,
            "expected_sha256": None,
            "computed_sha256": None,
            "source_layer": "missing",
            "reason": "no silver record found for event_id",
        }
    expected = str(silver.get("raw_sha256") or "")
    bronze = _bronze_record(lake_dir, event_id)
    if bronze is None:
        return {
            "event_id": event_id,
            "verified": False,
            "expected_sha256": expected or None,
            "computed_sha256": None,
            "source_layer": "missing",
            "reason": "bronze source row missing",
        }
    raw_payload = bronze.get("raw") or bronze
    canonical = json.dumps(raw_payload, sort_keys=True, separators=(",", ":"), default=str)
    computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    verified = bool(expected) and computed == expected
    return {
        "event_id": event_id,
        "verified": verified,
        "expected_sha256": expected or None,
        "computed_sha256": computed,
        "source_layer": "bronze",
        "reason": None if verified else "computed hash does not match stored raw_sha256",
        "verification_scope": "generation_and_bronze_hash" if generation is not None else "bronze_hash_only",
    }


@generation_reader
def verify_lake_integrity(lake_dir: str | Path) -> dict[str, Any]:
    """Verify the generated evidence integrity manifest against lake files."""
    lake = Path(lake_dir)
    manifest_path = lake / "gold" / "evidence_integrity.json"
    issues: list[str] = []
    with pin_generation(lake) as generation:
        if generation is None and (lake / "generation.json").is_file():
            generation = lake
        if generation is not None:
            try:
                verify_generation(generation)
            except (ValueError, OSError) as exc:
                issues.append(str(exc))
    if not manifest_path.is_file():
        return {
            "ok": False,
            "issues": ["gold/evidence_integrity.json is missing"],
            "manifest_sha256": None,
            "evidence_set_sha256": None,
        }
    manifest = read_json(manifest_path)
    expected_fields = {
        "schema_version",
        "generated_at",
        "counts",
        "hash_linkage",
        "idempotency",
        "artifacts",
        "manifest_sha256",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_fields
        or manifest.get("schema_version") != "trustops.evidence_integrity.v1"
    ):
        return {
            "ok": False,
            "issues": ["invalid evidence integrity manifest fields"],
            "manifest_sha256": None,
            "evidence_set_sha256": None,
        }
    artifact_names = {
        "bronze_raw_events",
        "silver_normalized_events",
        "gold_control_posture",
        "gold_control_tests",
        "gold_evidence_freshness",
        "gold_asset_risk",
        "gold_metrics",
        "gold_dashboard_data",
    }
    if not isinstance(manifest.get("artifacts"), dict) or set(manifest["artifacts"]) != artifact_names:
        return {
            "ok": False,
            "issues": ["incomplete evidence integrity artifacts"],
            "manifest_sha256": None,
            "evidence_set_sha256": None,
        }
    manifest_hash = manifest.get("manifest_sha256")
    recomputed_manifest_hash = _canonical_sha256({k: v for k, v in manifest.items() if k != "manifest_sha256"})
    if manifest_hash != recomputed_manifest_hash:
        issues.append("evidence_integrity manifest hash does not match content")

    for name, artifact in (manifest.get("artifacts") or {}).items():
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "bytes"}:
            issues.append("invalid integrity artifact fields")
            continue
        path = Path(str(artifact.get("path") or ""))
        relative = "/".join(path.parts[-2:])
        if relative not in ARTIFACTS:
            issues.append(f"artifact {name}: unknown assessment artifact")
            continue
        path = (generation or lake) / relative
        if not path.is_file():
            issues.append(f"artifact {name}: file is missing")
            continue
        expected_sha = str(artifact.get("sha256") or "")
        actual_sha = file_sha256(path)
        if expected_sha != actual_sha:
            issues.append(f"artifact {name}: sha256 mismatch")

    bronze_rows = read_jsonl(lake / "bronze" / "raw_events.jsonl", missing_ok=True)
    silver_rows = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True)
    raw_hashes = []
    for index, row in enumerate(bronze_rows):
        raw = row.get("raw")
        if not isinstance(raw, dict):
            issues.append(f"bronze row {index}: raw payload is missing")
            continue
        computed = _canonical_sha256(raw)
        raw_hashes.append(computed)
        if row.get("raw_sha256") != computed:
            issues.append(f"bronze row {index}: raw_sha256 mismatch")

    bronze_hashes = {str(row.get("raw_sha256") or "") for row in bronze_rows}
    missing = sorted({str(row.get("raw_sha256") or "") for row in silver_rows} - bronze_hashes)
    if missing:
        issues.append(f"silver rows reference missing bronze hashes: {', '.join(missing[:5])}")

    event_ids = [str(row.get("event_id") or "") for row in silver_rows]
    if manifest.get("counts") != {
        "raw": len(bronze_rows),
        "bronze": len(bronze_rows),
        "silver": len(silver_rows),
        "unique_event_ids": len(set(event_ids)),
    }:
        issues.append("integrity manifest counts do not match evidence")
    duplicate_event_ids = sorted(event_id for event_id, count in Counter(event_ids).items() if event_id and count > 1)
    if duplicate_event_ids:
        issues.append(f"duplicate event_ids: {', '.join(duplicate_event_ids[:10])}")

    evidence_items = sorted(
        (
            {"event_id": str(row.get("event_id") or ""), "raw_sha256": str(row.get("raw_sha256") or "")}
            for row in silver_rows
        ),
        key=lambda item: (item["event_id"], item["raw_sha256"]),
    )
    expected_evidence_set = str((manifest.get("idempotency") or {}).get("evidence_set_sha256") or "")
    actual_evidence_set = _canonical_sha256(evidence_items)
    if expected_evidence_set != actual_evidence_set:
        issues.append("idempotency evidence_set_sha256 mismatch")

    return {
        "ok": not issues,
        "issues": issues,
        "manifest_sha256": manifest_hash,
        "evidence_set_sha256": expected_evidence_set,
        "recomputed_evidence_set_sha256": actual_evidence_set,
        "bronze_count": len(bronze_rows),
        "silver_count": len(silver_rows),
    }
