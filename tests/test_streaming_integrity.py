"""Artifact hashing stays bounded without weakening publication integrity."""

import hashlib
from pathlib import Path

import pytest

from security_lakehouse import generations, pipeline
from security_lakehouse.io import read_json
from security_lakehouse.verification import verify_lake_integrity

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"


def test_assessment_hashes_without_whole_file_reads(tmp_path, monkeypatch):
    original = Path.read_bytes

    def reject_artifact_read(path):
        if tmp_path in path.parents:
            pytest.fail("assessment artifact hashing must not read the whole file")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", reject_artifact_read)
    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    generation = generations.active_generation(lake)
    generations.verify_generation(generation)
    assert verify_lake_integrity(lake)["ok"]
    manifest = read_json(generation / "generation.json")
    for relative, expected in manifest["artifacts"].items():
        assert hashlib.sha256(original(generation / relative)).hexdigest() == expected
    assert (
        generations.generation_identity(lake)["manifest_sha256"]
        == hashlib.sha256(original(generation / "generation.json")).hexdigest()
    )


@pytest.mark.parametrize("size", [0, 23, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1, 3 * 1024 * 1024 + 51])
def test_file_hash_matches_reference_across_chunk_boundaries(tmp_path, size):
    from security_lakehouse.io import file_sha256

    payload = (bytes(range(256)) * (size // 256 + 1))[:size]
    path = tmp_path / "binary"
    path.write_bytes(payload)
    assert file_sha256(path) == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("read_error", [False, True])
def test_file_hash_bounds_reads_and_handles_short_reads(tmp_path, monkeypatch, read_error):
    import io

    from security_lakehouse.io import file_sha256

    payload = bytes(range(256)) * 9000
    calls = []

    class ShortReader(io.BytesIO):
        def readinto(self, buffer):
            assert 0 < len(buffer) <= 1024 * 1024
            calls.append(len(buffer))
            if read_error and len(calls) == 3:
                raise OSError("injected partial read failure")
            return super().readinto(memoryview(buffer)[:4093])

        def read(self, size=-1):
            pytest.fail("hashing must use the bounded buffer")

    stream = ShortReader(payload)
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: stream)
    if read_error:
        with pytest.raises(OSError, match="partial read failure"):
            file_sha256(tmp_path / "binary")
    else:
        assert file_sha256(tmp_path / "binary") == hashlib.sha256(payload).hexdigest()
    assert len(calls) >= 3
    assert stream.closed


@pytest.mark.parametrize("mutation", ["tail", "truncate", "append"])
def test_generation_hash_detects_changes_after_first_chunk(tmp_path, mutation):
    generation = generations.new_generation(tmp_path / "lake")
    artifact = generation / "bronze/raw_events.jsonl"
    artifact.parent.mkdir()
    payload = b"x" * (2 * 1024 * 1024 + 17)
    artifact.write_bytes(payload)
    generations.seal_generation(generation, legacy=True)
    expected = read_json(generation / "generation.json")["artifacts"]["bronze/raw_events.jsonl"]
    assert expected == hashlib.sha256(payload).hexdigest()
    with artifact.open("r+b") as stream:
        if mutation == "truncate":
            stream.truncate(len(payload) - 1)
        elif mutation == "tail":
            stream.seek(-1, 2)
            stream.write(b"y")
        else:
            stream.seek(0, 2)
            stream.write(b"y")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        generations.verify_generation(generation)


def test_failed_generation_hash_retains_previous_assessment(tmp_path, monkeypatch):
    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    before = generations.active_generation(lake)
    identity = generations.generation_identity(lake)
    original = generations.file_sha256

    def unreadable(path):
        if before not in path.parents and path.name == "raw_events.jsonl":
            raise OSError("injected artifact read failure")
        return original(path)

    monkeypatch.setattr(generations, "file_sha256", unreadable)
    with pytest.raises(OSError, match="artifact read failure"):
        pipeline.run_pipeline(RAW, lake)
    assert generations.active_generation(lake) == before
    assert generations.generation_identity(lake) == identity
    assert verify_lake_integrity(lake)["ok"]


def test_integrity_verification_does_not_retain_raw_payloads(tmp_path):
    import tracemalloc

    from security_lakehouse.io import write_jsonl_from_iterable
    from security_lakehouse.scale_synthesis import iter_synthesize_audit_events

    def events():
        for row in iter_synthesize_audit_events(64, seed=42):
            row["attributes"]["large_source_payload"] = "x" * (256 * 1024)
            yield row

    raw = tmp_path / "raw.jsonl"
    write_jsonl_from_iterable(raw, events())
    lake = tmp_path / "lake"
    pipeline.run_pipeline(raw, lake)
    # Measure only verification allocations, not fixture construction or pipeline
    # evaluation. Sixteen MiB of raw payload must not be resident as parsed rows.
    tracemalloc.start()
    try:
        result = verify_lake_integrity(lake)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result["ok"], result["issues"]
    assert result["bronze_count"] == result["silver_count"] == 64
    assert peak < 5 * 1024 * 1024, f"verification allocated {peak / 2**20:.1f} MiB"


@pytest.mark.parametrize(
    ("mutation", "issue"),
    [
        ("raw", "raw_sha256 mismatch"),
        ("missing_raw", "raw payload is missing"),
        ("orphan", "silver rows reference missing bronze hashes"),
        ("duplicate", "duplicate event_ids"),
        ("truncate", "integrity manifest counts do not match evidence"),
    ],
)
def test_streamed_integrity_checks_reach_evidence_tail(tmp_path, mutation, issue):
    import json

    from security_lakehouse.io import read_jsonl

    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    generation = generations.active_generation(lake)
    relative = "bronze/raw_events.jsonl" if mutation in {"raw", "missing_raw"} else "silver/normalized_events.jsonl"
    path = generation / relative
    rows = read_jsonl(path)
    if mutation == "raw":
        rows[-1]["raw"]["status"] = "tampered"
    elif mutation == "missing_raw":
        rows[-1].pop("raw")
    elif mutation == "orphan":
        rows[-1]["raw_sha256"] = "0" * 64
    elif mutation == "duplicate":
        rows[-1]["event_id"] = rows[0]["event_id"]
    else:
        rows.pop()
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = verify_lake_integrity(lake)
    assert not result["ok"]
    assert any(issue in message for message in result["issues"]), result["issues"]
