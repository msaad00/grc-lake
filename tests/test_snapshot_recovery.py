"""Explicit quarantine preserves bytes without promoting uncommitted history."""

import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from security_lakehouse import assessment, cli
from security_lakehouse.io import file_sha256
from test_api_v1 import _seed_lake


def reconcile(lake, **kwargs):
    from security_lakehouse.snapshot_recovery import reconcile_snapshots

    return reconcile_snapshots(lake, **kwargs)


def interrupted(lake):
    _seed_lake(lake)
    committed = assessment.write_assessment_snapshot(lake)
    with (
        patch.object(assessment, "append_jsonl", side_effect=OSError("interrupted")),
        pytest.raises(OSError, match="interrupted"),
    ):
        assessment.write_assessment_snapshot(lake)
    orphan = next(p for p in (lake / "gold/snapshots").glob("*.json") if p != committed)
    return committed, orphan


def test_preview_then_quarantine_preserves_bytes_and_history(tmp_path):
    committed, orphan = interrupted(tmp_path)
    original = orphan.read_bytes()
    ledger = assessment._ledger_path(tmp_path).read_bytes()
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    preview = reconcile(tmp_path)
    assert preview["applied"] is False
    assert preview["files"] == [{"snapshot": orphan.name, "sha256": file_sha256(orphan)}]
    assert before == {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(assessment.SnapshotIntegrityError):
        assessment.write_assessment_snapshot(tmp_path)
    result = reconcile(tmp_path, apply=True)
    assert result["integrity"] == {"ok": True, "length": 1, "issues": []}
    archive = tmp_path / result["archive"]
    assert (archive / "files" / orphan.name).read_bytes() == original
    manifest = json.loads((archive / "manifest.json").read_text())
    assert manifest["status"] == "completed"
    assert manifest["files"] == preview["files"]
    assert committed.exists() and not orphan.exists()
    assert assessment._ledger_path(tmp_path).read_bytes() == ledger
    assert reconcile(tmp_path, apply=True)["files"] == []
    assessment.write_assessment_snapshot(tmp_path)
    assert assessment.verify_snapshot_chain(tmp_path)["length"] == 2


def test_committed_tampering_is_never_repaired(tmp_path):
    committed, orphan = interrupted(tmp_path)
    committed.write_text("{}")
    with pytest.raises(assessment.SnapshotIntegrityError):
        reconcile(tmp_path, apply=True)
    assert orphan.exists()
    assert not (tmp_path / "gold/snapshot_recovery").exists()


def test_committed_predecessor_tampering_stays_blocked(tmp_path):
    interrupted(tmp_path)
    ledger = assessment._ledger_path(tmp_path)
    row = json.loads(ledger.read_text())
    row["prev_hash"] = "f" * 64
    ledger.write_text(json.dumps(row) + "\n")
    with pytest.raises(assessment.SnapshotIntegrityError):
        reconcile(tmp_path, apply=True)
    assert not assessment.verify_snapshot_chain(tmp_path)["ok"]


@pytest.mark.parametrize("kind", ["orphan", "archive", "lock"])
def test_recovery_rejects_symlinks(tmp_path, kind):
    _, orphan = interrupted(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind == "orphan":
        orphan.unlink()
        orphan.symlink_to(outside)
    elif kind == "archive":
        (tmp_path / "gold/snapshot_recovery").symlink_to(outside, target_is_directory=True)
    else:
        lock = assessment._ledger_path(tmp_path).with_name("_ledger.jsonl.lock")
        lock.unlink()
        lock.symlink_to(outside / "do-not-create")
    with pytest.raises((ValueError, assessment.SnapshotIntegrityError)):
        reconcile(tmp_path, apply=True)
    assert list(outside.iterdir()) == []


def test_interrupted_quarantine_resumes_without_duplicate_records(tmp_path, monkeypatch):
    from security_lakehouse import snapshot_recovery as recovery

    _, orphan = interrupted(tmp_path)
    digest = file_sha256(orphan)
    original = recovery._move_to_archive

    def crash(source, target):
        original(source, target)
        raise OSError("crash after rename")

    monkeypatch.setattr(recovery, "_move_to_archive", crash)
    with pytest.raises(OSError, match="crash after rename"):
        reconcile(tmp_path, apply=True)
    with pytest.raises(assessment.SnapshotIntegrityError, match="recovery"):
        assessment.write_assessment_snapshot(tmp_path)
    monkeypatch.setattr(recovery, "_move_to_archive", original)
    result = reconcile(tmp_path, apply=True)
    assert result["integrity"]["ok"]
    assert file_sha256(tmp_path / result["archive"] / "files" / orphan.name) == digest
    assert reconcile(tmp_path, apply=True)["files"] == []


def test_writer_and_recovery_serialize(tmp_path):
    interrupted(tmp_path)

    def write():
        try:
            return assessment.write_assessment_snapshot(tmp_path)
        except assessment.SnapshotIntegrityError:
            return None  # A writer that wins the lock sees the unresolved orphan.

    with ThreadPoolExecutor(max_workers=2) as pool:
        repair = pool.submit(reconcile, tmp_path, apply=True)
        writer = pool.submit(write)
        repair.result(timeout=10)
        written = writer.result(timeout=10)
    verified = assessment.verify_snapshot_chain(tmp_path)
    assert verified["ok"]
    assert verified["length"] == (2 if written else 1)


@pytest.mark.parametrize("boundary", ["journal", "before_move", "after_manifest"])
def test_recovery_retries_each_durable_boundary(tmp_path, monkeypatch, boundary):
    from security_lakehouse import snapshot_recovery as recovery

    _, orphan = interrupted(tmp_path)
    original = orphan.read_bytes()
    write = recovery._durable_json
    move = recovery._move_to_archive

    def interrupted_write(path, payload):
        write(path, payload)
        if (boundary == "journal" and path.name == "pending.json") or (
            boundary == "after_manifest" and path.name == "manifest.json"
        ):
            raise OSError("boundary interrupted")

    def interrupted_move(source, target):
        raise OSError("boundary interrupted")

    monkeypatch.setattr(recovery, "_durable_json", interrupted_write)
    if boundary == "before_move":
        monkeypatch.setattr(recovery, "_move_to_archive", interrupted_move)
    with pytest.raises(OSError, match="boundary interrupted"):
        reconcile(tmp_path, apply=True)
    monkeypatch.setattr(recovery, "_durable_json", write)
    monkeypatch.setattr(recovery, "_move_to_archive", move)
    result = reconcile(tmp_path, apply=True)
    assert (tmp_path / result["archive"] / "files" / orphan.name).read_bytes() == original
    assert result["integrity"]["ok"]


def test_tampered_pending_archive_cannot_be_overwritten(tmp_path, monkeypatch):
    from security_lakehouse import snapshot_recovery as recovery

    interrupted(tmp_path)
    move = recovery._move_to_archive

    def crash(source, target):
        move(source, target)
        target.write_text("tampered")
        raise OSError("crash")

    monkeypatch.setattr(recovery, "_move_to_archive", crash)
    with pytest.raises(OSError):
        reconcile(tmp_path, apply=True)
    with pytest.raises(assessment.SnapshotIntegrityError, match="content hash"):
        reconcile(tmp_path, apply=True)
    with pytest.raises(assessment.SnapshotIntegrityError, match="recovery"):
        assessment.write_assessment_snapshot(tmp_path)


def test_cli_preview_apply_and_missing_lake(tmp_path, capsys):
    _, orphan = interrupted(tmp_path)
    argv = ["assessment", "reconcile-snapshots", "--lake", str(tmp_path)]
    assert cli.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["applied"] is False
    assert orphan.exists()
    assert cli.main([*argv, "--apply"]) == 0
    assert json.loads(capsys.readouterr().out)["integrity"]["ok"]
    with pytest.raises((ValueError, FileNotFoundError)):
        reconcile(tmp_path / "typo", apply=True)
