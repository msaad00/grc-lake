"""Append-only hash-chaining for point-in-time assessment snapshots."""

from __future__ import annotations

import json
import threading
from http import HTTPStatus
from pathlib import Path

from security_lakehouse import api_v1
from security_lakehouse.assessment import (
    _ledger_path,
    verify_snapshot_chain,
    write_assessment_snapshot,
)


def _seeded_lake(tmp_path: Path) -> Path:
    from test_api_v1 import _seed_lake

    _seed_lake(tmp_path)
    return tmp_path


def _write_chain(lake: Path, count: int = 3) -> list[Path]:
    return [write_assessment_snapshot(lake, reason=f"snap-{i}") for i in range(count)]


def test_snapshots_chain_and_verify_clean(tmp_path: Path) -> None:
    lake = _seeded_lake(tmp_path)
    paths = _write_chain(lake, 3)
    assert len({p.name for p in paths}) == 3  # no filename collisions

    # The first snapshot is genesis (prev_hash None); each later snapshot links
    # to its predecessor's assessment_hash.
    payloads = [json.loads(p.read_text()) for p in paths]
    assert payloads[0]["prev_hash"] is None
    assert payloads[1]["prev_hash"] == payloads[0]["assessment_hash"]
    assert payloads[2]["prev_hash"] == payloads[1]["assessment_hash"]

    result = verify_snapshot_chain(lake)
    assert result == {"ok": True, "length": 3, "issues": []}


def test_concurrent_snapshots_do_not_fork_the_chain(tmp_path: Path) -> None:
    """Two writers reading the same chain tip must not both claim it."""
    lake = _seeded_lake(tmp_path)
    workers = 6
    barrier = threading.Barrier(workers)

    def submit(index: int) -> None:
        barrier.wait()
        write_assessment_snapshot(lake, reason=f"race-{index}")

    threads = [threading.Thread(target=submit, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    result = verify_snapshot_chain(lake)
    assert result["ok"] is True, result["issues"]
    assert result["length"] == workers


def test_verify_detects_mutated_snapshot(tmp_path: Path) -> None:
    lake = _seeded_lake(tmp_path)
    paths = _write_chain(lake, 3)
    # Tamper with the middle snapshot's content, keeping its recorded hash.
    payload = json.loads(paths[1].read_text())
    payload["posture"]["score"] = 0.1
    paths[1].write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    result = verify_snapshot_chain(lake)
    assert result["ok"] is False
    assert any("content hash" in issue for issue in result["issues"])


def test_verify_detects_deleted_snapshot(tmp_path: Path) -> None:
    lake = _seeded_lake(tmp_path)
    paths = _write_chain(lake, 3)
    paths[0].unlink()

    result = verify_snapshot_chain(lake)
    assert result["ok"] is False
    assert any("missing" in issue for issue in result["issues"])


def test_verify_detects_broken_ledger_chain(tmp_path: Path) -> None:
    lake = _seeded_lake(tmp_path)
    _write_chain(lake, 3)
    # Drop the genesis ledger entry: the next entry's prev_hash now dangles.
    ledger = _ledger_path(lake)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")

    result = verify_snapshot_chain(lake)
    assert result["ok"] is False
    assert any("prev_hash" in issue for issue in result["issues"])


def test_verify_empty_lake_is_ok(tmp_path: Path) -> None:
    assert verify_snapshot_chain(tmp_path) == {"ok": True, "length": 0, "issues": []}


def test_integrity_route_envelope(tmp_path: Path) -> None:
    lake = _seeded_lake(tmp_path)
    _write_chain(lake, 2)
    status, body = api_v1.handle_get("/api/v1/snapshots/integrity", {}, lake)
    assert status == HTTPStatus.OK
    assert body["meta"]["resource"] == "snapshots.integrity"
    assert body["errors"] == []
    assert body["data"]["ok"] is True
    assert body["data"]["length"] == 2


def test_integrity_route_in_catalog() -> None:
    catalog = api_v1.resource_catalog()
    row = next((r for r in catalog if r["path"] == "/api/v1/snapshots/integrity"), None)
    assert row is not None
    assert row["resource"] == "snapshots.integrity"
    assert row["methods"] == ["GET"]


def test_snapshot_integrity_diagnostics_do_not_expose_exception_text(tmp_path, monkeypatch):
    from security_lakehouse import assessment

    lake = _seeded_lake(tmp_path)
    _write_chain(lake, 1)

    def corrupt(*args, **kwargs):
        raise assessment.SnapshotIntegrityError("private-path/password=secret")

    monkeypatch.setattr(assessment, "_verified_snapshot_payload", corrupt)
    status, body = api_v1.handle_get("/api/v1/snapshots/integrity", {}, lake)
    assert status == HTTPStatus.OK
    assert body["data"]["ok"] is False
    assert "private-path" not in json.dumps(body)
    assert "secret" not in json.dumps(body)
