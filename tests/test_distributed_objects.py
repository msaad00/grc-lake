"""Immutable S3 objects and confined, verified worker workspaces."""

from __future__ import annotations

import pytest

from security_lakehouse.distributed.config import ClusterConfig
from security_lakehouse.distributed.objects import IntegrityError, ObjectStore


class MemoryObjects:
    def __init__(self):
        self.data = {}

    def put_object(self, *, Bucket, Key, Body, IfNoneMatch, **kwargs):
        assert IfNoneMatch == "*"
        from botocore.exceptions import ClientError

        if Key in self.data:
            raise ClientError(
                {"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject"
            )
        self.data[Key] = Body.read() if hasattr(Body, "read") else Body
        return {}

    def get_object(self, *, Bucket, Key):
        import io

        return {"Body": io.BytesIO(self.data[Key]), "ContentLength": len(self.data[Key])}


@pytest.fixture
def objects():
    return ObjectStore(ClusterConfig("cluster", "test-bucket"), client=MemoryObjects())


def test_roundtrip_includes_relative_generation_links_and_deleted_files(objects, tmp_path):
    source = tmp_path / "writer"
    artifact = source / "generations" / "first" / "gold" / "metrics.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"count":3}')
    (source / ".active-generation").symlink_to("generations/first")
    manifest = objects.snapshot("tenant-a", source)
    restored = tmp_path / "reader"
    objects.restore("tenant-a", manifest, restored)
    assert (restored / ".active-generation/gold/metrics.json").read_text() == '{"count":3}'
    assert not any(str(tmp_path) in key for key in objects.client.data)
    artifact.unlink()
    newer = objects.snapshot("tenant-a", source)
    assert "generations/first/gold/metrics.json" not in newer["files"]
    # Published old generations remain addressable by pinned manifests.
    objects.restore("tenant-a", manifest, tmp_path / "historical")


def test_cross_tenant_object_reference_and_path_traversal_fail_closed(objects, tmp_path):
    source = tmp_path / "a"
    source.mkdir()
    (source / "evidence").write_text("tenant A secret")
    manifest = objects.snapshot("tenant-a", source)
    with pytest.raises(IntegrityError):
        objects.restore("tenant-b", manifest, tmp_path / "b")
    entry = manifest["files"]["evidence"]
    with pytest.raises(IntegrityError):
        objects.restore("tenant-a", {**manifest, "files": {"../escape": entry}}, tmp_path / "c")
    assert not (tmp_path / "escape").exists()


def test_corrupt_object_never_reaches_a_reader(objects, tmp_path):
    (tmp_path / "source").mkdir()
    (tmp_path / "source/evidence").write_bytes(b"right")
    manifest = objects.snapshot("tenant-a", tmp_path / "source")
    key = next(iter(objects.client.data))
    objects.client.data[key] = b"wrong"
    with pytest.raises(IntegrityError):
        objects.restore("tenant-a", manifest, tmp_path / "reader")
    assert not (tmp_path / "reader/evidence").exists()


def test_symlink_escape_and_workspace_size_are_rejected(objects, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "escape").symlink_to("../private")
    with pytest.raises(IntegrityError):
        objects.snapshot("tenant-a", root)
    (root / "escape").unlink()
    (root / "large").write_bytes(b"123456")
    limited = ObjectStore(ClusterConfig("cluster", "test-bucket", workspace_limit=5), client=objects.client)
    with pytest.raises(IntegrityError):
        limited.snapshot("tenant-a", root)


def test_publishing_identical_bytes_never_overwrites_existing_objects(objects, tmp_path):
    (tmp_path / "evidence").write_bytes(b"stable")
    first = objects.snapshot("tenant-a", tmp_path)
    second = objects.snapshot("tenant-a", tmp_path)
    assert first == second
    assert len(objects.client.data) == 1


def test_restore_preserves_artifacts_whose_names_match_download_temporaries(objects, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "evidence.download").write_bytes(b"independent evidence")
    (source / "evidence").write_bytes(b"primary evidence")
    manifest = objects.snapshot("tenant-a", source)
    manifest["files"] = {name: manifest["files"][name] for name in ("evidence.download", "evidence")}
    target = tmp_path / "restored"
    objects.restore("tenant-a", manifest, target)
    assert (target / "evidence").read_bytes() == b"primary evidence"
    assert (target / "evidence.download").read_bytes() == b"independent evidence"


def test_failed_download_preserves_adjacent_artifacts(objects, tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"right")
    entry = objects.put("tenant-a", source)
    objects.client.data[objects.key("tenant-a", entry["sha256"])] = b"wrong"
    target = tmp_path / "evidence"
    adjacent = tmp_path / "evidence.download"
    adjacent.write_bytes(b"must survive failed download")
    with pytest.raises(IntegrityError):
        objects.get("tenant-a", entry, target)
    assert adjacent.read_bytes() == b"must survive failed download"
    assert not target.exists()
    assert not list(tmp_path.glob(".grc-download-*"))
