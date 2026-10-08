"""Compact display projections must never hide changed source bytes."""

import os

import pytest

from security_lakehouse import asset_names, graph, io, projected_reads, strict_json


def test_repeated_projection_validates_once_and_returns_detached_rows(tmp_path, monkeypatch):
    path = tmp_path / "rows.jsonl"
    io.write_jsonl(path, [{"asset_id": "one", "controls": ["A"], "detail": {"large": "unused"}}])
    original = strict_json.loads
    calls = []

    def counted(raw):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(strict_json, "loads", counted)
    first = projected_reads.read_projection(path, ("asset_id", "controls"))
    first[0]["controls"].append("modified")
    assert projected_reads.read_projection(path, ("asset_id", "controls")) == [{"asset_id": "one", "controls": ["A"]}]
    assert len(calls) == 1


def test_same_size_same_mtime_rewrite_cannot_reuse_projection(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text('{"asset_id":"one"}\n')
    stamp = path.stat()
    assert projected_reads.read_projection(path, ("asset_id",))[0]["asset_id"] == "one"
    path.write_text('{"asset_id":"two"}\n')
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert projected_reads.read_projection(path, ("asset_id",))[0]["asset_id"] == "two"
    path.write_text('{"asset_id":NaN}\n')
    with pytest.raises(ValueError):
        projected_reads.read_projection(path, ("asset_id",))


def test_unselected_invalid_data_still_fails_validation(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text('{"asset_id":"one","ignored":NaN}\n')
    with pytest.raises(ValueError):
        projected_reads.read_projection(path, ("asset_id",))


def test_paths_field_selections_and_missing_files_stay_separate(tmp_path):
    first = tmp_path / "tenant-a" / "rows.jsonl"
    second = tmp_path / "tenant-b" / "rows.jsonl"
    io.write_jsonl(first, [{"asset_id": "a", "asset_name": "A"}])
    io.write_jsonl(second, [{"asset_id": "b", "asset_name": "B"}])
    assert projected_reads.read_projection(first, ("asset_id",)) == [{"asset_id": "a"}]
    assert projected_reads.read_projection(first, ("asset_name",)) == [{"asset_name": "A"}]
    assert projected_reads.read_projection(second, ("asset_id",)) == [{"asset_id": "b"}]
    first.unlink()
    with pytest.raises(FileNotFoundError):
        projected_reads.read_projection(first, ("asset_id",))
    assert projected_reads.read_projection(first, ("asset_id",), missing_ok=True) == []
    with pytest.raises(ValueError, match="outside allowed root"):
        projected_reads.read_projection(second, ("asset_id",), base_dir=first.parent)


def test_cache_budget_and_oversized_input_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(projected_reads, "MAX_CACHE_BYTES", 64)
    monkeypatch.setattr(projected_reads, "MAX_SOURCE_BYTES", 32)
    path = tmp_path / "rows.jsonl"
    io.write_jsonl(path, [{"asset_id": "a" * 100}, {"asset_id": "b"}])
    assert projected_reads.read_projection(path, ("asset_id",)) == [{"asset_id": "a" * 100}, {"asset_id": "b"}]
    assert sum(len(value) for value in projected_reads._cache.values()) <= 64


def test_asset_names_and_graph_reuse_compact_projections(tmp_path, monkeypatch):
    io.write_jsonl(
        tmp_path / "gold/asset_risk.jsonl", [{"asset_id": "one", "asset_name": "First", "huge_unused": "x" * 1000}]
    )
    io.write_jsonl(
        tmp_path / "silver/normalized_events.jsonl", [{"asset_id": "one", "event_type": "sample", "control_ids": []}]
    )
    original = strict_json.loads
    calls = []

    def counted(raw):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(strict_json, "loads", counted)
    assert asset_names.load_asset_names(tmp_path) == {"one": "First"}
    assert asset_names.load_asset_names(tmp_path) == {"one": "First"}
    graph._gold_asset_rows(tmp_path)
    graph._gold_asset_rows(tmp_path)
    graph._silver_event_rows(tmp_path)
    graph._silver_event_rows(tmp_path)
    assert len(calls) == 3


def test_projection_cache_is_bounded_by_entries_and_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(projected_reads, "MAX_CACHE_BYTES", 100)
    monkeypatch.setattr(projected_reads, "MAX_CACHE_ENTRIES", 2)
    for index in range(5):
        path = tmp_path / f"{index}.jsonl"
        io.write_jsonl(path, [{"asset_id": str(index) * 20}])
        projected_reads.read_projection(path, ("asset_id",))
        assert len(projected_reads._cache) <= 2
        assert sum(len(value) for value in projected_reads._cache.values()) <= 100


def test_generation_switch_selects_new_bytes_while_pinned_read_stays_consistent(tmp_path):
    from security_lakehouse.generations import pin_generation, seal_generation

    for identity, value in [("first", "one"), ("second", "two")]:
        generation = tmp_path / "generations" / identity
        io.write_jsonl(generation / "gold/asset_risk.jsonl", [{"asset_id": "a", "asset_name": value}])
        seal_generation(generation, legacy=True)
    pointer = tmp_path / ".active-generation"
    pointer.symlink_to("generations/first")
    with pin_generation(tmp_path):
        assert asset_names.load_asset_names(tmp_path) == {"a": "one"}
        pointer.unlink()
        pointer.symlink_to("generations/second")
        assert asset_names.load_asset_names(tmp_path) == {"a": "one"}
    with pin_generation(tmp_path):
        assert asset_names.load_asset_names(tmp_path) == {"a": "two"}


def test_full_rows_reuse_validation_without_dropping_evidence_fields(tmp_path, monkeypatch):
    path = tmp_path / "rows.jsonl"
    row = {"event_id": "one", "evidence": {"source": "source-id"}, "control_ids": ["A"]}
    io.write_jsonl(path, [row])
    original = strict_json.loads
    calls = []

    def counted(raw):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(strict_json, "loads", counted)
    first = projected_reads.read_projection(path, None)
    assert first == [row]
    first[0]["evidence"]["source"] = "changed"
    assert projected_reads.read_projection(path, None) == [row]
    assert len(calls) == 1


def test_evidence_page_refreshes_changed_rows_and_rejects_invalid_unpaged_rows(tmp_path):
    from security_lakehouse import api_v1

    path = tmp_path / "silver/normalized_events.jsonl"
    io.write_jsonl(path, [{"event_id": "first", "status": "pass"}, {"event_id": "second", "status": "fail"}])
    status, body = api_v1.handle_get("/api/v1/evidence", {"limit": ["1"]}, tmp_path)
    assert status == 200
    assert body["data"] == [{"event_id": "first", "status": "pass"}]
    assert body["meta"]["count"] == 2
    path.write_text('{"event_id":"first","status":"fail"}\n{"event_id":"second","status":"fail"}\n')
    status, body = api_v1.handle_get("/api/v1/evidence", {"limit": ["1"]}, tmp_path)
    assert status == 200
    assert body["data"][0]["status"] == "fail"
    with path.open("a") as stream:
        stream.write('{"event_id":"third","invalid":NaN}\n')
    status, body = api_v1.handle_get("/api/v1/evidence", {"limit": ["1"]}, tmp_path)
    assert status == 400
    assert body["errors"][0]["code"] == "bad_request"


def _settled_clock(monkeypatch):
    """Make every file look older than the racy-timestamp window."""
    import time

    real = time.time_ns
    monkeypatch.setattr(time, "time_ns", lambda: real() + 60 * 10**9)


def _count_opens(monkeypatch, target):
    import builtins
    import pathlib

    opened = []
    path_open, builtin_open = pathlib.Path.open, builtins.open

    def counted_path_open(self, *args, **kwargs):
        if os.path.realpath(self) == os.path.realpath(target):
            opened.append(str(self))
        return path_open(self, *args, **kwargs)

    def counted_builtin_open(file, *args, **kwargs):
        if isinstance(file, str | os.PathLike) and os.path.realpath(file) == os.path.realpath(target):
            opened.append(str(file))
        return builtin_open(file, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", counted_path_open)
    monkeypatch.setattr(builtins, "open", counted_builtin_open)
    return opened


def test_unchanged_settled_file_is_validated_with_a_stat_not_a_read(tmp_path, monkeypatch):
    path = tmp_path / "silver/normalized_events.jsonl"
    io.write_jsonl(path, [{"event_id": "first"}, {"event_id": "second"}])
    _settled_clock(monkeypatch)
    assert io.validated_jsonl_count(path) == 2
    opened = _count_opens(monkeypatch, path)

    assert io.validated_jsonl_count(path) == 2
    assert io.validated_jsonl_count(path) == 2
    assert opened == []


def test_settled_same_size_rewrite_with_restored_mtime_is_revalidated(tmp_path, monkeypatch):
    path = tmp_path / "rows.jsonl"
    path.write_text('{"event_id":"one1"}\n')
    stamp = path.stat()
    _settled_clock(monkeypatch)
    assert io.validated_jsonl_count(path) == 1
    path.write_text('{"event_id":NaN   }\n')
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    after = path.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (stamp.st_ino, stamp.st_size, stamp.st_mtime_ns)
    with pytest.raises(ValueError):
        io.validated_jsonl_count(path)


def test_fresh_same_size_in_place_rewrite_falls_back_to_content_hash(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text('{"event_id":"one1"}\n')
    stamp = path.stat()
    assert io.validated_jsonl_count(path) == 1
    path.write_text('{"event_id":NaN   }\n')
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    with pytest.raises(ValueError):
        io.validated_jsonl_count(path)


def test_same_source_misses_coalesce_without_blocking_other_tenants(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    first_path = tmp_path / "tenant-a" / "rows.jsonl"
    second_path = tmp_path / "tenant-b" / "rows.jsonl"
    io.write_jsonl(first_path, [{"asset_id": "first"}])
    io.write_jsonl(second_path, [{"asset_id": "other"}])
    entered, duplicate, release = Event(), Event(), Event()
    mutex = Lock()
    calls = 0
    original = strict_json.loads

    def blocked(raw):
        nonlocal calls
        if b"first" in raw:
            with mutex:
                calls += 1
                if calls > 1:
                    duplicate.set()
            entered.set()
            assert release.wait(5)
        return original(raw)

    monkeypatch.setattr(strict_json, "loads", blocked)
    with ThreadPoolExecutor(max_workers=3) as executor:
        first = executor.submit(projected_reads.read_projection, first_path, ("asset_id",))
        assert entered.wait(2)
        second = executor.submit(projected_reads.read_projection, first_path, ("asset_id",))
        other = executor.submit(projected_reads.read_projection, second_path, ("asset_id",))
        try:
            assert other.result(timeout=2) == [{"asset_id": "other"}]
            assert not duplicate.wait(0.2)
        finally:
            release.set()
        assert first.result(timeout=2) == second.result(timeout=2) == [{"asset_id": "first"}]
    assert calls == 1


def test_failed_projection_build_releases_waiters(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    path = tmp_path / "rows.jsonl"
    io.write_jsonl(path, [{"asset_id": "first"}])
    entered, release = Event(), Event()
    calls = 0
    original = strict_json.loads

    def fails_once(raw):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(5)
            raise ValueError("injected parse interruption")
        return original(raw)

    monkeypatch.setattr(strict_json, "loads", fails_once)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(projected_reads.read_projection, path, ("asset_id",))
        assert entered.wait(2)
        second = executor.submit(projected_reads.read_projection, path, ("asset_id",))
        release.set()
        with pytest.raises(ValueError, match="injected parse interruption"):
            first.result(timeout=2)
        assert second.result(timeout=2) == [{"asset_id": "first"}]
    assert calls == 2
    assert all(not lock.locked() for lock in projected_reads._build_locks.values())
