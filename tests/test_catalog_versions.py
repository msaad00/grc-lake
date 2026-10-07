"""Versioned control catalog: history, retire, as-of, and bundle hashing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_lakehouse import catalog_versions as cv
from security_lakehouse.assessment import verify_snapshot_chain, write_assessment_snapshot
from security_lakehouse.catalog import (
    DEFAULT_CONTROL_CATALOG,
    DEFAULT_FRAMEWORK_REGISTRY,
    load_control_catalog,
    load_framework_registry,
    validate_catalog,
)


def _copy_catalog(tmp_path: Path) -> Path:
    dst = tmp_path / "catalog.json"
    dst.write_text(DEFAULT_CONTROL_CATALOG.read_text(encoding="utf-8"), encoding="utf-8")
    return dst


# --------------------------------------------------------------------------- #
# Bundle hashing
# --------------------------------------------------------------------------- #


def test_bundle_is_deterministic_and_covers_components() -> None:
    a = cv.compute_bundle()
    b = cv.compute_bundle()
    assert a["bundle_sha256"] == b["bundle_sha256"]
    assert a["framework_count"] == len(load_framework_registry())
    assert a["control_count"] == len(load_control_catalog())
    assert a["control_count"] >= 741
    assert set(a["components"]) == {"frameworks", "controls", "crosswalk", "safeguards"}


def test_bundle_detects_changed_safeguard_rule(tmp_path: Path) -> None:
    from security_lakehouse.safeguards import load_safeguards

    path = tmp_path / "safeguards.json"
    payload = load_safeguards()
    path.write_text(json.dumps(payload))
    lock = tmp_path / "bundle.lock.json"
    cv.write_bundle_lock(lock_path=lock, safeguards_path=path)
    payload["safeguards"][0]["evaluation_rule"] = "fail_when_missing_evidence"
    path.write_text(json.dumps(payload))
    result = cv.verify_bundle_lock(lock_path=lock, safeguards_path=path)
    assert result["ok"] is False
    assert result["drifted_components"] == ["safeguards"]


def test_bundle_sha_changes_when_a_control_changes(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    before = cv.compute_bundle(catalog_path=catalog)["bundle_sha256"]
    payload = json.loads(catalog.read_text())
    payload["controls"][0]["version"] = "9.9.9"
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    after = cv.compute_bundle(catalog_path=catalog)["bundle_sha256"]
    assert before != after


def test_write_and_verify_lock_roundtrip(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    lock = tmp_path / "bundle.lock.json"
    written = cv.write_bundle_lock(lock_path=lock, catalog_path=catalog)
    result = cv.verify_bundle_lock(lock_path=lock, catalog_path=catalog)
    assert result["ok"] is True
    assert result["actual"] == written["bundle_sha256"]


def test_verify_lock_detects_component_drift(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    lock = tmp_path / "bundle.lock.json"
    cv.write_bundle_lock(lock_path=lock, catalog_path=catalog)
    payload = json.loads(catalog.read_text())
    payload["controls"][0]["title"] = "mutated title"
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    result = cv.verify_bundle_lock(lock_path=lock, catalog_path=catalog)
    assert result["ok"] is False
    assert "controls" in result["drifted_components"]


def test_verify_lock_missing_file_is_not_ok(tmp_path: Path) -> None:
    result = cv.verify_bundle_lock(lock_path=tmp_path / "absent.json")
    assert result["ok"] is False


def test_repo_lockfile_matches_committed_catalog() -> None:
    # Guard: the committed bundle.lock.json must match the active catalog.
    assert cv.verify_bundle_lock()["ok"] is True


# --------------------------------------------------------------------------- #
# Retire / history / as-of
# --------------------------------------------------------------------------- #


def test_retire_moves_control_to_history_and_drops_from_active(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    history = tmp_path / "history.jsonl"
    target = json.loads(catalog.read_text())["controls"][0]["control_id"]

    out = cv.retire_control(
        target, change_reason="superseded by 2024 revision", catalog_path=catalog, history_path=history
    )
    assert out["retired"]["lifecycle_status"] == "retired"
    assert out["retired"]["valid_to"] is not None
    assert out["successor"] is None
    assert target not in cv.active_controls(catalog_path=catalog)

    rows = cv.load_history(history_path=history)
    assert [r["control_id"] for r in rows] == [target]
    assert rows[0]["change_reason"] == "superseded by 2024 revision"


def test_retire_with_successor_bumps_version_and_backlinks(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    history = tmp_path / "history.jsonl"
    original = json.loads(catalog.read_text())["controls"][0]
    cid = original["control_id"]

    successor = dict(original)
    successor["title"] = "Revised: " + original["title"]
    out = cv.retire_control(
        cid,
        change_reason="2024 revision",
        catalog_path=catalog,
        history_path=history,
        successor=successor,
    )
    new = out["successor"]
    assert new["version"] == "1.1.0"
    assert new["supersedes"] == f"{cid}@1.0.0"
    assert new["valid_to"] is None
    # Active catalog still has the control id, now at the new version.
    active = cv.active_controls(catalog_path=catalog)[cid]
    assert active["version"] == "1.1.0"
    # Full history: retired 1.0.0 then active 1.1.0, oldest-first.
    hist = cv.control_history(cid, catalog_path=catalog, history_path=history)
    assert [h["version"] for h in hist] == ["1.0.0", "1.1.0"]


def test_retire_unknown_control_raises(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    with pytest.raises(KeyError):
        cv.retire_control("DOES-NOT-EXIST", change_reason="x", catalog_path=catalog, history_path=tmp_path / "h.jsonl")


def test_as_of_reconstructs_the_in_force_version(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    history = tmp_path / "history.jsonl"
    controls = json.loads(catalog.read_text())["controls"]
    original = next(row for row in controls if row["control_id"] == "SOC2-CC6.1")
    cid = original["control_id"]
    # valid_from on the baseline is the reviewed_date for SOC2-CC6.1.
    baseline_from = cv.active_controls(catalog_path=catalog)[cid]["valid_from"]

    successor = dict(original)
    cv.retire_control(
        cid,
        change_reason="revision",
        catalog_path=catalog,
        history_path=history,
        successor=successor,
        now=__import__("datetime").datetime(2026, 6, 1, tzinfo=__import__("datetime").UTC),
    )

    # Before the retire date -> the original 1.0.0 version is in force.
    older = cv.controls_as_of("2026-05-25", catalog_path=catalog, history_path=history)
    assert older[cid]["version"] == "1.0.0"
    # After the retire date -> the successor 1.1.0 is in force.
    newer = cv.controls_as_of("2026-06-10", catalog_path=catalog, history_path=history)
    assert newer[cid]["version"] == "1.1.0"
    # Before any control existed -> empty.
    assert cv.controls_as_of("2000-01-01", catalog_path=catalog, history_path=history) == {}
    assert baseline_from in {"2026-05-23", "2026-06-30"}


def test_as_of_rejects_garbage_date() -> None:
    with pytest.raises(ValueError):
        cv.controls_as_of("not-a-date")


# --------------------------------------------------------------------------- #
# Validation of version fields
# --------------------------------------------------------------------------- #


def test_validate_flags_bad_lifecycle_and_dates(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    payload = json.loads(catalog.read_text())
    payload["controls"][0]["lifecycle_status"] = "zombie"
    payload["controls"][1]["valid_from"] = "2026-05-01"
    payload["controls"][1]["valid_to"] = "2026-04-01"  # before valid_from
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    errors = validate_catalog(registry_path=DEFAULT_FRAMEWORK_REGISTRY, catalog_path=catalog)
    assert any("lifecycle_status" in e for e in errors)
    assert any("valid_to precedes valid_from" in e for e in errors)


def test_committed_catalog_validates_clean() -> None:
    assert validate_catalog() == []


# --------------------------------------------------------------------------- #
# Snapshot pinning
# --------------------------------------------------------------------------- #


def test_snapshot_pins_catalog_bundle_and_chain_holds(tmp_path: Path) -> None:
    from test_api_v1 import _seed_lake

    _seed_lake(tmp_path)
    path = write_assessment_snapshot(tmp_path, reason="audit")
    payload = json.loads(path.read_text())
    bundle = payload["catalog_bundle"]
    assert bundle is not None
    assert bundle["bundle_sha256"] == cv.compute_bundle()["bundle_sha256"]
    # The pin is covered by the tamper-evident chain.
    assert verify_snapshot_chain(tmp_path)["ok"] is True


def test_validate_flags_duplicate_control_ids(tmp_path: Path) -> None:
    catalog = _copy_catalog(tmp_path)
    payload = json.loads(catalog.read_text())
    payload["controls"].append(dict(payload["controls"][0]))
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    errors = validate_catalog(registry_path=DEFAULT_FRAMEWORK_REGISTRY, catalog_path=catalog)
    assert any("duplicate control_id" in e for e in errors)
