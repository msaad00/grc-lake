"""Bounded history decoding must retain whole-chain tamper detection."""

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from security_lakehouse import assessment, strict_json
from security_lakehouse.db.metrics import framework_readiness_trends


def history(lake, count=4):
    directory = lake / "gold/snapshots"
    directory.mkdir(parents=True)
    entries, paths = [], []
    previous = None
    for index in range(count):
        payload = {
            "evaluated_at": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=index)).isoformat(),
            "prev_hash": previous,
            "posture": {"score": 70 + index},
            "frameworks": [{"framework": "SOC 2", "score": 70 + index}],
            "cache_probe": "payload",
        }
        payload["assessment_hash"] = assessment._assessment_hash(payload)
        path = directory / f"assessment-{index}.json"
        path.write_text(json.dumps(payload, sort_keys=True))
        entries.append(
            {key: payload[key] for key in ("evaluated_at", "prev_hash", "assessment_hash")} | {"snapshot": path.name}
        )
        previous = payload["assessment_hash"]
        paths.append(path)
    ledger = directory / "_ledger.jsonl"
    ledger.write_text("".join(json.dumps(row) + "\n" for row in entries))
    return paths, ledger


def test_warm_snapshot_and_limited_trends_do_not_reverify_unchanged_payloads(tmp_path, monkeypatch):
    paths, _ = history(tmp_path)
    assert assessment.verify_snapshot_chain(tmp_path)["ok"]
    hashed = []
    original = assessment._assessment_hash

    def counted(payload):
        hashed.append(payload["evaluated_at"])
        return original(payload)

    monkeypatch.setattr(assessment, "_assessment_hash", counted)
    loaded = assessment.load_snapshot(tmp_path, paths[-1].stem)
    loaded["posture"]["score"] = 0
    again = assessment.load_snapshot(tmp_path, paths[-1].stem)
    assert again["posture"]["score"] == 73
    trends = framework_readiness_trends(tmp_path, limit=2, include_current=False)
    assert len(trends["points"]) == 2
    assert hashed == []


@pytest.mark.parametrize("change", ["rewrite", "replace", "delete", "symlink", "ledger", "extra"])
def test_warm_verification_still_rejects_historical_tampering(tmp_path, change):
    paths, ledger = history(tmp_path)
    assert assessment.verify_snapshot_chain(tmp_path)["ok"]
    target = paths[0]  # outside the requested latest-one result
    if change in {"rewrite", "replace"}:
        before = target.stat()
        raw = target.read_bytes().replace(b'"score": 70', b'"score": 99')
        if change == "replace":
            other = target.with_suffix(".new")
            other.write_bytes(raw)
            other.replace(target)
        else:
            target.write_bytes(raw)
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert target.stat().st_size == before.st_size
    elif change == "delete":
        target.unlink()
    elif change == "symlink":
        other = tmp_path / "outside.json"
        target.rename(other)
        target.symlink_to(other)
    elif change == "ledger":
        ledger.write_text(
            ledger.read_text().replace('"snapshot": "assessment-0.json"', '"snapshot": "assessment-x.json"')
        )
    else:
        (target.parent / "extra.json").write_bytes(target.read_bytes())
    before = ledger.read_bytes()
    with pytest.raises(assessment.SnapshotIntegrityError):
        assessment.load_snapshot(tmp_path, paths[-1].stem)
    with pytest.raises(assessment.SnapshotIntegrityError):
        framework_readiness_trends(tmp_path, limit=1, include_current=False)
    assert ledger.read_bytes() == before


def test_snapshot_readers_can_verify_concurrently(tmp_path, monkeypatch):
    history(tmp_path)
    barrier = threading.Barrier(2)
    verify = assessment._snapshot_chain_rows_unlocked

    def rendezvous(*args, **kwargs):
        barrier.wait(timeout=2)
        return verify(*args, **kwargs)

    monkeypatch.setattr(assessment, "_snapshot_chain_rows_unlocked", rendezvous)
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(assessment.verify_snapshot_chain, tmp_path) for _ in range(2)]
        results = [future.result(timeout=5) for future in futures]
    assert all(result["ok"] for result in results)


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1000])
def test_strict_depth_boundary_preserves_strings_and_rejects_excess_depth(size):
    raw = "[" * size + '"brackets []{} and \\"quotes\\""' + "]" * size
    if size > strict_json.MAX_DEPTH:
        with pytest.raises(strict_json.InvalidJSON):
            strict_json.loads(raw)
    else:
        assert strict_json.loads(raw) == json.loads(raw)


def test_limited_history_decodes_only_requested_payloads_after_verification(tmp_path, monkeypatch):
    history(tmp_path)
    assert assessment.verify_snapshot_chain(tmp_path)["ok"]
    decoded = []
    original = json.loads

    def observed(raw, *args, **kwargs):
        if (b"cache_probe" if isinstance(raw, bytes) else "cache_probe") in raw:
            decoded.append(True)
        return original(raw, *args, **kwargs)

    monkeypatch.setattr(json, "loads", observed)
    result = framework_readiness_trends(tmp_path, limit=2, include_current=False)
    assert len(result["points"]) == len(decoded) == 2


def test_verification_cache_is_bounded_and_eviction_remains_correct(tmp_path, monkeypatch):
    paths, _ = history(tmp_path)
    monkeypatch.setattr(assessment, "_SNAPSHOT_CACHE_LIMIT", 2)
    assessment._verified_snapshot_bytes.clear()
    assert assessment.verify_snapshot_chain(tmp_path)["ok"]
    assert len(assessment._verified_snapshot_bytes) == 2
    loaded = assessment.load_snapshot(tmp_path, paths[0].stem)
    assert loaded["posture"]["score"] == 70
    assert len(assessment._verified_snapshot_bytes) == 2


def test_reader_lock_excludes_writer_until_verification_finishes(tmp_path, monkeypatch):
    from security_lakehouse.ledger import chain_lock

    _, ledger = history(tmp_path)
    reading, release, attempted, writing = (threading.Event() for _ in range(4))
    verify = assessment._snapshot_chain_rows_unlocked

    def held_read(*args, **kwargs):
        reading.set()
        released = release.wait(5)
        assert released
        return verify(*args, **kwargs)

    def writer():
        attempted.set()
        with chain_lock(ledger):
            writing.set()

    monkeypatch.setattr(assessment, "_snapshot_chain_rows_unlocked", held_read)
    with ThreadPoolExecutor(max_workers=2) as workers:
        reader = workers.submit(assessment.verify_snapshot_chain, tmp_path)
        try:
            started = reading.wait(5)
            assert started
            pending = workers.submit(writer)
            tried = attempted.wait(5)
            assert tried
            entered = writing.wait(0.1)
            assert not entered
        finally:
            release.set()
        result = reader.result(timeout=5)
        assert result["ok"]
        pending.result(timeout=5)
    assert writing.is_set()


@pytest.mark.parametrize("suffix", ["", "\\", "\n"])
def test_unterminated_escaped_string_is_rejected(suffix):
    raw = '"' + '\\"' * 10_000 + suffix
    with pytest.raises(strict_json.InvalidJSON):
        strict_json.loads(raw)


def test_repeated_escape_pattern_is_rejected():
    # Pattern reported by CodeQL for the former string-token expression.
    raw = '"\\a' + '\\\\"\\a' * 100_000
    with pytest.raises(strict_json.InvalidJSON):
        strict_json.loads(raw)


def test_long_escaped_string_does_not_count_as_structure():
    value = {"nested": ['\\"[]{}' * 100_000, {"after": "the string"}]}
    decoded = strict_json.loads(json.dumps(value))
    assert decoded == value


@pytest.mark.parametrize(
    ("field", "value"),
    [("evaluated_at", "2026-01-02T00:00:00+00:00"), ("prev_hash", "a" * 64), ("assessment_hash", "b" * 64)],
)
def test_cached_bytes_cannot_validate_changed_ledger_metadata(tmp_path, field, value):
    paths, ledger = history(tmp_path)
    verified = assessment.verify_snapshot_chain(tmp_path)
    assert verified["ok"]
    entries = [json.loads(line) for line in ledger.read_text().splitlines()]
    entries[0][field] = value
    ledger.write_text("".join(json.dumps(row) + "\n" for row in entries))
    with pytest.raises(assessment.SnapshotIntegrityError):
        assessment.load_snapshot(tmp_path, paths[-1].stem)


def test_selected_snapshot_preserves_hash_prefix_and_exact_name_priority(tmp_path):
    paths, ledger = history(tmp_path, count=17)
    entries = [json.loads(line) for line in ledger.read_text().splitlines()]
    first = entries[0]["assessment_hash"]
    loaded = assessment.load_snapshot(tmp_path, first[:16])
    assert loaded["assessment_hash"] == first
    prefixes = [entry["assessment_hash"][0] for entry in entries]
    ambiguous = next(prefix for prefix in prefixes if prefixes.count(prefix) > 1)
    with pytest.raises(ValueError, match="ambiguous"):
        assessment.load_snapshot(tmp_path, ambiguous)
    renamed = paths[0].with_name(ambiguous + ".json")
    paths[0].rename(renamed)
    entries[0]["snapshot"] = renamed.name
    ledger.write_text("".join(json.dumps(row) + "\n" for row in entries))
    loaded = assessment.load_snapshot(tmp_path, ambiguous)
    assert loaded["assessment_hash"] == first


@pytest.mark.parametrize("limit", [-1, 0, 1, 2, 10])
def test_trend_limit_preserves_history_order_and_unlimited_semantics(tmp_path, limit):
    paths, _ = history(tmp_path)
    result = framework_readiness_trends(tmp_path, limit=limit, include_current=False)
    selected = paths[-limit:] if limit > 0 else paths
    assert [point["snapshot_id"] for point in result["points"]] == [path.stem for path in selected]


@pytest.mark.parametrize("warm", [False, True])
def test_snapshot_read_rejects_self_consistent_payload_with_wrong_previous_hash(tmp_path, warm):
    paths, ledger = history(tmp_path, count=1)
    if warm:
        assessment.load_snapshot(tmp_path, paths[0].stem)
    payload = json.loads(paths[0].read_text())
    payload["prev_hash"] = "f" * 64
    payload["assessment_hash"] = assessment._assessment_hash(payload)
    paths[0].write_text(json.dumps(payload, sort_keys=True))
    entry = json.loads(ledger.read_text())
    entry["assessment_hash"] = payload["assessment_hash"]
    # Ledger remains a valid genesis, while payload hashes are internally valid.
    # Only the read-time payload/ledger prev_hash comparison detects this mismatch.
    ledger.write_text(json.dumps(entry) + "\n")
    with pytest.raises(assessment.SnapshotIntegrityError, match="snapshot integrity verification failed"):
        assessment.load_snapshot(tmp_path, paths[0].stem)
