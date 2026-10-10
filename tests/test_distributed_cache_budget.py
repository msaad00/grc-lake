"""Materialization reuse is tenant-isolated, bounded, and publication-aware."""

from dataclasses import replace

from security_lakehouse.distributed.objects import ObjectStore
from security_lakehouse.distributed.workspace import Runtime
from test_distributed_objects import MemoryObjects


def _runtime(catalog, tmp_path, monkeypatch, *, entries=2, budget=20):
    catalog.config = replace(
        catalog.config, workspace_limit=budget, read_cache_entries=entries, read_cache_limit=budget
    )
    store = ObjectStore(catalog.config, client=MemoryObjects())
    runtime = Runtime(catalog, store, tmp_path)
    for tenant in ("a", "b", "c"):
        with runtime.write(tenant) as path:
            (path / "facts").write_text(tenant * 4)
    calls = []
    original = store.restore

    def restore(tenant, manifest, path):
        calls.append(tenant)
        return original(tenant, manifest, path)

    monkeypatch.setattr(store, "restore", restore)
    return runtime, calls


def test_alternating_tenants_download_once_per_revision(catalog, tmp_path, monkeypatch):
    runtime, calls = _runtime(catalog, tmp_path, monkeypatch)
    for tenant in ("a", "b") * 3:
        with runtime.read(tenant) as path:
            assert (path / "facts").read_text() == tenant * 4
            (path / "facts").write_text("private mutation")
    assert calls == ["a", "b"]


def test_entry_eviction_is_lru_and_retains_active_private_readers(catalog, tmp_path, monkeypatch):
    runtime, calls = _runtime(catalog, tmp_path, monkeypatch)
    with runtime.read("a") as pinned:
        for tenant in ("b", "a", "c", "b"):
            with runtime.read(tenant):
                pass
        assert (pinned / "facts").read_text() == "aaaa"
    assert calls == ["a", "b", "c", "b"]
    assert len(list((tmp_path / "read-cache").glob("*/*/.distributed-ready"))) == 2


def test_byte_budget_evicts_even_below_entry_limit(catalog, tmp_path, monkeypatch):
    runtime, calls = _runtime(catalog, tmp_path, monkeypatch, entries=4, budget=7)
    for tenant in ("a", "b", "a"):
        with runtime.read(tenant):
            pass
    assert calls == ["a", "b", "a"]
    assert len(list((tmp_path / "read-cache").glob("*/*/.distributed-ready"))) == 1


def test_new_publication_replaces_only_its_tenant(catalog, tmp_path, monkeypatch):
    runtime, calls = _runtime(catalog, tmp_path, monkeypatch)
    for tenant in ("a", "b"):
        with runtime.read(tenant):
            pass
    with runtime.write("a") as path:
        (path / "facts").write_text("new")
    calls.clear()
    with runtime.read("a") as path:
        assert (path / "facts").read_text() == "new"
    with runtime.read("b") as path:
        assert (path / "facts").read_text() == "bbbb"
    assert calls == ["a"]
    assert len(list((tmp_path / "read-cache/a").iterdir())) == 1


def test_cache_configuration_rejects_unbounded_or_too_small_limits():
    import pytest

    from security_lakehouse.distributed.config import ClusterConfig

    for entries in (0, 65, True):
        with pytest.raises(ValueError, match="read cache entries"):
            ClusterConfig("cluster", "test-bucket", read_cache_entries=entries)
    with pytest.raises(ValueError, match="workspace limit"):
        ClusterConfig("cluster", "test-bucket", workspace_limit=10, read_cache_limit=9)


def test_incomplete_download_is_reclaimed_after_restart(catalog, tmp_path, monkeypatch):
    runtime, _ = _runtime(catalog, tmp_path, monkeypatch)
    abandoned = tmp_path / "read-cache/z/download-interrupted"
    abandoned.mkdir(parents=True)
    (abandoned / "partial").write_text("incomplete")
    with runtime.read("a") as path:
        assert (path / "facts").read_text() == "aaaa"
    assert not abandoned.exists()


def test_failed_download_preserves_other_tenant_and_recovers(catalog, tmp_path, monkeypatch):
    import pytest

    runtime, calls = _runtime(catalog, tmp_path, monkeypatch)
    with runtime.read("a"):
        pass
    original = runtime.objects.restore

    def fail(tenant, manifest, path):
        if tenant == "b":
            raise OSError("object store unavailable")
        return original(tenant, manifest, path)

    monkeypatch.setattr(runtime.objects, "restore", fail)
    with pytest.raises(OSError, match="unavailable"), runtime.read("b"):
        pass
    with runtime.read("a") as path:
        assert (path / "facts").read_text() == "aaaa"
    assert calls == ["a"]
    monkeypatch.setattr(runtime.objects, "restore", original)
    restarted = Runtime(catalog, runtime.objects, tmp_path)
    for tenant in ("a", "b"):
        with restarted.read(tenant) as path:
            assert (path / "facts").read_text() == tenant * 4
    assert calls == ["a", "b"]
    assert not list((tmp_path / "read-cache").glob("*/download-*"))
