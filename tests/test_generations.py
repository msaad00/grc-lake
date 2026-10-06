"""Publication crash boundaries and pinned assessment readers."""

from pathlib import Path

import pytest

from security_lakehouse import pipeline
from security_lakehouse.io import read_json, read_jsonl, write_jsonl

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"


@pytest.mark.parametrize("failure", ["write_jsonl", "_write_sqlite_mart", "write_current_posture"])
def test_interrupted_publication_retains_previous_generation(tmp_path, monkeypatch, failure):
    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    original_generations = set((lake / "generations").iterdir())
    before = {
        p: (lake / p).read_bytes()
        for p in [
            "bronze/raw_events.jsonl",
            "silver/normalized_events.jsonl",
            "gold/control_posture.jsonl",
            "gold/current_posture.json",
            "manifest.json",
            "mart/security_lakehouse.sqlite",
        ]
    }
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, read_jsonl(RAW)[:1])

    def crash(*args, **kwargs):
        raise OSError("injected publication failure")

    if failure == "write_current_posture":
        monkeypatch.setattr("security_lakehouse.assessment.write_current_posture", crash)
    else:
        monkeypatch.setattr(pipeline, failure, crash)
    with pytest.raises(OSError, match="injected"):
        pipeline.run_pipeline(changed, lake)
    assert {p: (lake / p).read_bytes() for p in before} == before
    assert set((lake / "generations").iterdir()) == original_generations


def test_result_paths_remain_pinned_after_next_publication(tmp_path):
    first = pipeline.run_pipeline(RAW, tmp_path / "lake")
    before = Path(first.metrics_path).read_bytes()
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, read_jsonl(RAW)[:1])
    second = pipeline.run_pipeline(changed, tmp_path / "lake")
    assert first.metrics_path != second.metrics_path
    assert Path(first.metrics_path).read_bytes() == before
    assert read_json(tmp_path / "lake/manifest.json")["row_counts"]["raw"] == 1


def test_multi_file_reader_stays_pinned_during_publication(tmp_path, monkeypatch):
    from security_lakehouse import assessment
    from security_lakehouse.connector_state import append_config_event, latest_config
    from security_lakehouse.generations import active_generation

    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    first_id = active_generation(lake).name
    append_config_event(lake, connector_id="github-security", state="enabled", actor="alice")
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, read_jsonl(RAW)[:1])
    original_read = assessment.read_jsonl
    switched = False

    def interleaved(path, **kwargs):
        nonlocal switched
        rows = original_read(path, **kwargs)
        if not switched:
            switched = True
            pipeline.run_pipeline(changed, lake)
        return rows

    monkeypatch.setattr(assessment, "read_jsonl", interleaved)
    posture = assessment.build_current_posture(lake)
    assert posture["posture"]["control_count"] == 34
    assert posture["generation"]["generation_id"] == first_id
    assert latest_config(lake, "github-security")["state"] == "enabled"
    assert assessment.build_current_posture(lake)["posture"]["control_count"] < 34


def test_failed_pointer_switch_preserves_view(tmp_path, monkeypatch):
    from security_lakehouse import generations

    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    before = (lake / "manifest.json").read_bytes()
    first = generations.active_generation(lake)

    def crash(*args):
        raise OSError("pointer switch failed")

    monkeypatch.setattr(generations, "_switch_pointer", crash)
    with pytest.raises(OSError):
        pipeline.run_pipeline(RAW, lake)
    assert generations.active_generation(lake) == first
    assert (lake / "manifest.json").read_bytes() == before


def test_legacy_migration_keeps_operational_files(tmp_path):
    from security_lakehouse.generations import active_generation
    from security_lakehouse.io import write_json

    lake = tmp_path / "lake"
    write_json(lake / "gold/metrics.json", {"legacy": True})
    write_json(lake / "gold/assignments.json", {"owner": "alice"})
    pipeline.run_pipeline(RAW, lake)
    assert active_generation(lake) is not None
    assert read_json(lake / "gold/assignments.json") == {"owner": "alice"}
    historical = list((lake / "generations").glob("*/gold/metrics.json"))
    assert any(read_json(p) == {"legacy": True} for p in historical)


def test_generation_rejects_corruption_and_cross_tenant_pointer(tmp_path):
    from security_lakehouse.generations import active_generation, verify_generation

    lake = tmp_path / "tenant-a"
    pipeline.run_pipeline(RAW, lake)
    generation = active_generation(lake)
    (generation / "gold/metrics.json").write_text("{}")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_generation(generation)
    other = tmp_path / "tenant-b"
    other.mkdir()
    (other / ".active-generation").symlink_to(generation)
    with pytest.raises(ValueError, match="pointer"):
        active_generation(other)


def test_invalid_catalog_stops_even_unused_rule_and_incremental_noop(tmp_path):
    from security_lakehouse.io import write_json
    from security_lakehouse.policy import PolicyError

    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    before = (lake / "manifest.json").read_bytes()
    mapping = tmp_path / "invalid.json"
    write_json(mapping, {"controls": [{"control_id": "unused", "evaluation_rule": "invalid"}]})
    for run in [pipeline.run_pipeline, pipeline.run_pipeline_incremental]:
        with pytest.raises(PolicyError):
            run(RAW, lake, mapping_path=mapping)
        assert (lake / "manifest.json").read_bytes() == before


def test_published_generation_rejects_shared_io_writes(tmp_path):
    from security_lakehouse.io import write_json

    result = pipeline.run_pipeline(RAW, tmp_path / "lake")
    with pytest.raises(ValueError, match="immutable"):
        write_json(result.metrics_path, {})
    with pytest.raises(ValueError, match="immutable"):
        write_json(tmp_path / "lake/gold/metrics.json", {})


def test_catalog_change_forces_incremental_reassessment(tmp_path):
    from security_lakehouse.controls import DEFAULT_CATALOG_PATH
    from security_lakehouse.io import write_json

    mapping = tmp_path / "catalog.json"
    catalog = read_json(DEFAULT_CATALOG_PATH)
    write_json(mapping, catalog)
    lake = tmp_path / "lake"
    first = pipeline.run_pipeline(RAW, lake, mapping_path=mapping)
    catalog["controls"][0]["title"] = "Changed requirement"
    write_json(mapping, catalog)
    second = pipeline.run_pipeline_incremental(RAW, lake, mapping_path=mapping)
    assert second.metrics_path != first.metrics_path
    assert read_json(lake / "catalog/control_map.json")["controls"][0]["title"] == "Changed requirement"


def test_cli_and_api_invalid_rule_report_error_and_preserve_export(tmp_path, monkeypatch, capsys):
    from security_lakehouse.api_v1 import handle_post
    from security_lakehouse.assessment import write_assessment_snapshot
    from security_lakehouse.cli import main
    from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE
    from security_lakehouse.io import write_json

    lake = tmp_path / "lake"
    write_jsonl(lake / CONNECTOR_RAW_FILE, read_jsonl(RAW))
    pipeline.run_pipeline(RAW, lake)
    mapping = tmp_path / "invalid.json"
    write_json(mapping, {"controls": [{"control_id": "unused", "evaluation_rule": "invalid"}]})
    before = (lake / "manifest.json").read_bytes()
    assert main(["pipeline", "run", "--raw", str(RAW), "--out", str(lake), "--mapping", str(mapping)]) == 1
    assert "unknown named rule" in capsys.readouterr().err
    monkeypatch.setattr("security_lakehouse.controls.DEFAULT_CATALOG_PATH", mapping)
    status, body = handle_post("/api/v1/ingestion/eval", {}, lake)
    assert body["data"]["result"] == "error"
    assert (lake / "manifest.json").read_bytes() == before
    exported = read_json(write_assessment_snapshot(lake))
    assert exported["generation"]["generation_id"] == read_json(lake / "manifest.json")["generation_id"]
    assert exported["catalog_bundle"] == read_json(lake / "catalog/bundle.json")


def test_missing_staged_posture_cannot_be_published(tmp_path, monkeypatch):
    from security_lakehouse.generations import active_generation

    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    previous = active_generation(lake)
    monkeypatch.setattr("security_lakehouse.assessment.write_current_posture", lambda *args: None)
    with pytest.raises(ValueError, match="missing required"):
        pipeline.run_pipeline(RAW, lake)
    assert active_generation(lake) == previous


def _paused_publisher(raw, lake, ready):
    from security_lakehouse import generations

    def pause_before_switch(*args):
        ready.set()
        # The parent kills this process at a real OS crash boundary.
        import time

        time.sleep(30)

    generations._switch_pointer = pause_before_switch
    pipeline.run_pipeline(raw, lake)


def test_killed_publisher_preserves_readers_and_releases_writer_lock(tmp_path):
    import multiprocessing

    from security_lakehouse.generations import active_generation, pin_generation, verify_generation

    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    original = active_generation(lake)
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, read_jsonl(RAW)[:1])
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    process = context.Process(target=_paused_publisher, args=(changed, lake, ready))
    process.start()
    try:
        assert ready.wait(20), "publisher did not reach the pre-switch crash boundary"
        with pin_generation(lake):
            assert len(read_jsonl(lake / "silver/normalized_events.jsonl")) == len(read_jsonl(RAW))
            assert active_generation(lake) == original
            verify_generation(original)
        process.kill()
        process.join(10)
        assert not process.is_alive()
        assert active_generation(lake) == original
        # A dead writer must not leave a lock that blocks the next publication.
        replacement = context.Process(target=pipeline.run_pipeline, args=(changed, lake))
        replacement.start()
        try:
            replacement.join(20)
            assert replacement.exitcode == 0
        finally:
            if replacement.is_alive():
                replacement.kill()
                replacement.join(10)
        assert active_generation(lake) != original
        assert len(read_jsonl(lake / "silver/normalized_events.jsonl")) == 1
        verify_generation(active_generation(lake))
        verify_generation(original)
    finally:
        if process.is_alive():
            process.kill()
        process.join(10)
