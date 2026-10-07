"""Archival bounds active operational storage without enabling job replay."""

import time

from sqlalchemy import update

from security_lakehouse.auth.dependencies import _INSECURE_IDENTITY
from security_lakehouse.auth.request_audit import append_request_audit
from security_lakehouse.db.models import OperationJob
from security_lakehouse.server_app import create_app


def _completed(lake):
    queue = create_app(lake, require_auth=False).state.operation_queue
    job = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "retained-key")
    row = queue.claim()
    queue.finish(row, 200, {"data": {"receipt": "original-result"}})
    with queue.factory.begin() as session:
        session.execute(
            update(OperationJob).where(OperationJob.id == row.id).values(finished_at=time.time() - 100 * 86400)
        )
    return queue, job


def test_preview_then_archive_preserves_idempotency_and_original_results(tmp_path):
    from security_lakehouse.operational_retention import archive_operational_history

    lake, archive = tmp_path / "lake", tmp_path / "archive"
    queue, job = _completed(lake)
    assert archive_operational_history(lake)["eligible_jobs"] == 1
    assert not archive.exists()
    report = archive_operational_history(lake, archive_to=archive)
    assert report["archived_jobs"] == 1
    replay = queue.enqueue(_INSECURE_IDENTITY, "/api/v1/ingestion/eval", {}, "retained-key")
    assert replay["id"] == job["id"] and replay["result_archived"] is True
    assert replay["response"] is None
    assert queue.claim() is None
    retained = list(archive.rglob("*.json"))
    assert len(retained) == 1 and "original-result" in retained[0].read_text()
    assert archive_operational_history(lake, archive_to=archive)["archived_jobs"] == 0


def test_old_request_rows_are_archived_exactly_and_recent_rows_remain(tmp_path):
    from security_lakehouse.operational_retention import archive_operational_history

    lake, archive = tmp_path / "lake", tmp_path / "archive"
    _completed(lake)
    path = lake / "gold/request_audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    old = b'{"occurred_at":"2020-01-01T00:00:00Z","event_id":"original"}\n'
    path.write_bytes(old)
    append_request_audit(
        lake, method="GET", route="/api/v1/controls", status_code=200, decision="allow", correlation_id="recent"
    )
    assert archive_operational_history(lake)["eligible_request_rows"] == 1
    archive_operational_history(lake, archive_to=archive)
    assert b"original" not in path.read_bytes()
    assert b"recent" in path.read_bytes()
    assert old in [p.read_bytes() for p in archive.rglob("*.jsonl")]
    assert archive_operational_history(lake, archive_to=archive)["archived_request_rows"] == 0


def test_archive_failure_leaves_active_history_intact(tmp_path, monkeypatch):
    from security_lakehouse import operational_retention as retention

    lake, archive = tmp_path / "lake", tmp_path / "archive"
    queue, job = _completed(lake)

    def unavailable(*args, **kwargs):
        raise OSError("archive unavailable")

    monkeypatch.setattr(retention, "_persist_archive", unavailable)
    import pytest

    with pytest.raises(OSError, match="archive unavailable"):
        retention.archive_operational_history(lake, archive_to=archive)
    assert queue.get("insecure", job["id"])["response"]["data"]["receipt"] == "original-result"


def test_interrupted_compaction_reuses_verified_archive(tmp_path, monkeypatch):
    import pytest

    from security_lakehouse import operational_retention as retention

    lake, archive = tmp_path / "lake", tmp_path / "archive"
    queue, job = _completed(lake)
    original = retention.update

    def unavailable(*args, **kwargs):
        raise RuntimeError("database interrupted")

    monkeypatch.setattr(retention, "update", unavailable)
    with pytest.raises(RuntimeError, match="database interrupted"):
        retention.archive_operational_history(lake, archive_to=archive)
    assert queue.get("insecure", job["id"])["response"]["data"]["receipt"] == "original-result"
    assert len(list(archive.rglob("*.json"))) == 1
    monkeypatch.setattr(retention, "update", original)
    retention.archive_operational_history(lake, archive_to=archive)
    assert queue.get("insecure", job["id"])["result_archived"] is True
    assert len(list(archive.rglob("*.json"))) == 1


def test_request_append_waits_for_archive_and_is_not_lost(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from security_lakehouse import operational_retention as retention

    lake, archive = tmp_path / "lake", tmp_path / "archive"
    path = lake / "gold/request_audit.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text('{"occurred_at":"2020-01-01T00:00:00Z"}\n')
    entered, release = threading.Event(), threading.Event()
    original = retention.os.link

    def pause(source, target):
        entered.set()
        assert release.wait(5)
        return original(source, target)

    monkeypatch.setattr(retention.os, "link", pause)
    with ThreadPoolExecutor(max_workers=2) as pool:
        archiving = pool.submit(retention.archive_operational_history, lake, archive_to=archive)
        try:
            assert entered.wait(2)
            writing = pool.submit(
                append_request_audit,
                lake,
                method="GET",
                route="/api/v1/controls",
                status_code=200,
                decision="allow",
                correlation_id="racing",
            )
            time.sleep(0.05)
            assert not writing.done()
        finally:
            release.set()
        archiving.result()
        writing.result()
    assert "racing" in path.read_text()
    assert "2020-01-01" not in path.read_text()


def test_symlink_archive_is_rejected_without_compaction(tmp_path):
    import pytest

    from security_lakehouse import operational_retention as retention

    lake, archive = tmp_path / "lake", tmp_path / "archive"
    queue, job = _completed(lake)
    target = tmp_path / "external"
    target.mkdir()
    archive.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        retention.archive_operational_history(lake, archive_to=archive)
    assert queue.get("insecure", job["id"])["response"]["data"]["receipt"] == "original-result"
    assert not list(target.iterdir())


def test_symlink_archive_parent_is_rejected_without_compaction(tmp_path):
    import pytest

    from security_lakehouse import operational_retention as retention

    lake = tmp_path / "lake"
    queue, job = _completed(lake)
    target = tmp_path / "external"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        retention.archive_operational_history(lake, archive_to=alias / "archive")
    assert queue.get("insecure", job["id"])["response"]["data"]["receipt"] == "original-result"
    assert not list(target.iterdir())


def test_archive_ancestors_are_durable_before_compacting_originals(tmp_path, monkeypatch):
    from security_lakehouse import operational_retention as retention

    lake, archive = tmp_path / "lake", tmp_path / "new" / "archive"
    _completed(lake)
    audit = lake / "gold/request_audit.jsonl"
    audit.parent.mkdir(exist_ok=True)
    audit.write_text('{"occurred_at":"2020-01-01T00:00:00Z"}\n')
    synced = set()
    original_sync, original_update, original_replace = retention._fsync_dir, retention.update, retention.os.replace

    def sync(path):
        original_sync(path)
        synced.add(path)

    def assert_ancestors(folder):
        for parent in folder.parents:
            if parent == tmp_path:
                assert parent in synced
                break
            assert parent in synced

    def update(*args, **kwargs):
        assert_ancestors(archive / retention.root_key(lake) / "jobs")
        return original_update(*args, **kwargs)

    def replace(source, target):
        if target == audit:
            namespaces = list((archive / retention.root_key(lake) / "requests").iterdir())
            assert len(namespaces) == 1
            assert_ancestors(namespaces[0])
        return original_replace(source, target)

    monkeypatch.setattr(retention, "_fsync_dir", sync)
    monkeypatch.setattr(retention, "update", update)
    monkeypatch.setattr(retention.os, "replace", replace)
    retention.archive_operational_history(lake, archive_to=archive)
