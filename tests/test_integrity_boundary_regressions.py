"""Missing and unexpected integrity inputs cannot report trusted success."""

import pytest

from security_lakehouse import cli
from security_lakehouse.evidence_migration import migrate_workpaper
from security_lakehouse.generations import new_generation, seal_generation, verify_generation
from security_lakehouse.io import canonical_sha256, file_sha256, write_json, write_jsonl
from security_lakehouse.verification import verify_event


@pytest.mark.parametrize("command", ["verify-snapshots", "verify-tracking"])
def test_verify_missing_lake_does_not_create_it_or_report_success(tmp_path, command):
    lake = tmp_path / "missing"
    assert cli.main(["assessment", command, "--lake", str(lake)]) == 1
    assert not lake.exists()


@pytest.mark.parametrize("extra", ["gold/extra.json", "bronze/untracked.jsonl", "unlisted.txt"])
def test_generation_rejects_unlisted_regular_files(tmp_path, extra):
    generation = new_generation(tmp_path)
    write_jsonl(generation / "bronze/raw_events.jsonl", [])
    seal_generation(generation, legacy=True)
    verify_generation(generation)
    path = generation / extra
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("uncommitted")
    with pytest.raises(ValueError, match="unlisted"):
        verify_generation(generation)


def test_matching_legacy_event_hash_does_not_hide_missing_lake_integrity(tmp_path):
    raw = {"event_id": "event", "status": "pass"}
    write_jsonl(tmp_path / "bronze/raw_events.jsonl", [{"event_id": "event", "raw": raw}])
    write_jsonl(
        tmp_path / "silver/normalized_events.jsonl", [{"event_id": "event", "raw_sha256": canonical_sha256(raw)}]
    )
    assert verify_event(tmp_path, "event")["verified"] is False


def test_workpaper_migration_rejects_a_symlinked_source_manifest(tmp_path, monkeypatch):
    # Isolate validation from rendering; unsafe input must never reach export.
    monkeypatch.setattr("security_lakehouse.audit_workpapers.export_workpaper", lambda *args: None)
    source = tmp_path / "source"
    source.mkdir()
    content = {"title": "test"}
    write_json(source / "workpaper.json", content)
    manifest = tmp_path / "manifest.json"
    write_json(
        manifest,
        {
            "files": {"workpaper.json": file_sha256(source / "workpaper.json")},
            "content_sha256": canonical_sha256(content),
        },
    )
    (source / "manifest.json").symlink_to(manifest)
    with pytest.raises(ValueError, match="symlink|regular"):
        migrate_workpaper(source, tmp_path / "output")


def test_ledger_predecessor_is_checked_even_when_record_hash_is_valid(tmp_path):
    from security_lakehouse.io import read_jsonl, write_jsonl
    from security_lakehouse.ledger import append_chained_jsonl, canonical_record_hash, verify_chained_jsonl

    path = tmp_path / "ledger.jsonl"
    append_chained_jsonl(path, {"event": "first"})
    append_chained_jsonl(path, {"event": "second"})
    rows = read_jsonl(path)
    rows[1]["prev_hash"] = "0" * 64
    rows[1]["record_hash"] = canonical_record_hash(rows[1])
    write_jsonl(path, rows)
    result = verify_chained_jsonl(path)
    assert result["ok"] is False
    assert result["issues"] == ["entry 1: prev_hash breaks the chain"]
