"""Explicit historical recovery and independently retained integrity checkpoints.

A checkpoint is only a trust anchor if the operator retained it independently
before a suspected change. This module neither signs it nor authenticates origin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_lakehouse.assessment import (
    _assessment_hash,
    _is_safe_snapshot_token,
    _ledger_path,
    _snapshot_chain_rows_unlocked,
)
from security_lakehouse.generations import generation_identity, generation_reader
from security_lakehouse.io import file_sha256, read_json, read_jsonl, write_json
from security_lakehouse.ledger import chain_lock
from security_lakehouse.verification import verify_lake_integrity


def restore_snapshot_files(lake: Path, source: Path) -> dict[str, Any]:
    """Restore missing ledger-named files from an operator-selected directory.

    Validate every record before copying. Never rewrite the historical ledger,
    existing local files, or the source. No discovery of arbitrary external paths.
    """
    lake = lake.resolve()
    if source.is_symlink() or not source.is_dir():
        raise ValueError("snapshot recovery requires a regular source directory")
    with chain_lock(_ledger_path(lake)):
        entries = read_jsonl(_ledger_path(lake))
        target = lake / "gold/snapshots"
        expected = None
        names: set[str] = set()
        missing = []
        for entry in entries:
            name = entry.get("snapshot")
            if (
                not isinstance(name, str)
                or not _is_safe_snapshot_token(name)
                or not name.endswith(".json")
                or name in names
            ):
                raise ValueError("invalid or duplicate snapshot name")
            names.add(name)
            local = target / name
            path = local if local.exists() else source / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("snapshot source missing or unsafe")
            payload = read_json(path)
            if (
                entry.get("prev_hash") != expected
                or payload.get("prev_hash") != expected
                or _assessment_hash(payload) != entry.get("assessment_hash")
                or payload.get("assessment_hash") != entry.get("assessment_hash")
                or payload.get("evaluated_at") != entry.get("evaluated_at")
            ):
                raise ValueError("snapshot does not match recorded history")
            if not local.exists():
                missing.append((local, payload))
            expected = entry["assessment_hash"]
        if {p.name for p in target.glob("*.json")} - names:
            raise ValueError("unledgered snapshots require reconciliation")
        for path, payload in missing:
            write_json(path, payload)
        result = _snapshot_chain_rows_unlocked(lake, metadata_only=True)[1]
        if not result["ok"]:
            raise ValueError("restored snapshot chain did not verify")
        return {"restored": len(missing), "length": len(entries), "authentication": "hash_consistency_only"}


def migrate_workpaper(source: Path, out: Path, *, content_path: Path | None = None) -> dict[str, Any]:
    """Re-render recovered JSON into a new export while retaining its origin.

    Old exports with no JSON require the original workpaper JSON explicitly;
    HTML is never treated as a source of structured assessment truth.
    """
    from security_lakehouse.audit_workpapers import export_workpaper

    if source.is_symlink() or not source.is_dir() or (source / "manifest.json").is_symlink():
        raise ValueError("workpaper migration requires a regular source directory and manifest, without symlinks")
    manifest = read_json(source / "manifest.json")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or not set(files) <= {"index.html", "workpaper.json"}:
        raise ValueError("unsupported legacy workpaper manifest")
    if source.is_symlink() or any(
        (source / name).is_symlink() or file_sha256(source / name) != digest for name, digest in files.items()
    ):
        raise ValueError("legacy workpaper file hashes do not verify")
    path = content_path or source / "workpaper.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("original workpaper JSON is required; HTML cannot recover evidence")
    content = read_json(path)
    from security_lakehouse.io import canonical_sha256

    if canonical_sha256(content) != manifest.get("content_sha256"):
        raise ValueError("workpaper JSON does not match the original recorded content hash")
    provenance = {
        "source_manifest_sha256": file_sha256(source / "manifest.json"),
        "source_content_sha256": manifest["content_sha256"],
        "authentication": "hash_consistency_only",
    }
    export_workpaper({**content, "migration": provenance}, out)
    return {"out": str(out), **provenance}


@generation_reader
def integrity_checkpoint(lake: Path) -> dict[str, Any]:
    if not verify_lake_integrity(lake)["ok"]:
        raise ValueError("cannot checkpoint invalid evidence")
    identity = generation_identity(lake)
    if identity is None:
        raise ValueError("checkpoint requires a sealed generation")
    # Each ledger digest records exact bytes. Retain the result outside the lake
    # in independently controlled storage to detect resealing or truncation.
    ledgers = {}
    for relative in ("gold/snapshots/_ledger.jsonl", "gold/mapping_reviews.jsonl", "gold/violation_tracking.jsonl"):
        path = lake / relative
        if path.is_symlink():
            raise ValueError("checkpoint ledger must not be a symlink")
        ledgers[relative] = file_sha256(path) if path.is_file() else None
    return {"schema_version": "trustops.integrity_checkpoint.v1", "generation": identity, "ledgers": ledgers}


def verify_checkpoint(lake: Path, expected: dict[str, Any]) -> dict[str, Any]:
    try:
        actual = integrity_checkpoint(lake)
        ok = actual == expected
    except (OSError, ValueError):
        ok = False
    return {
        "ok": ok,
        "authentication": "comparison_with_operator_supplied_checkpoint",
        "requires": "checkpoint retained independently before the suspected change",
    }
