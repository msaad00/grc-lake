"""Immutable S3 objects and confined, verified worker workspaces."""

from __future__ import annotations

import pytest

from security_lakehouse.distributed.config import ClusterConfig
from security_lakehouse.distributed.objects import IntegrityError, ObjectStore


def _b64_sha256(data: bytes) -> str:
    import base64
    import hashlib

    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _bad_digest(operation: str):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": "BadDigest"}, "ResponseMetadata": {"HTTPStatusCode": 400}}, operation)


class MemoryObjects:
    """In-memory S3 that, like S3, rejects a body whose supplied SHA-256 checksum differs."""

    def __init__(self):
        self.data = {}
        self.uploads: dict[str, dict] = {}
        self.aborted: list[str] = []

    def put_object(self, *, Bucket, Key, Body, IfNoneMatch, **kwargs):
        assert IfNoneMatch == "*"
        from botocore.exceptions import ClientError

        if Key in self.data:
            raise ClientError(
                {"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject"
            )
        data = Body.read() if hasattr(Body, "read") else Body
        if "ChecksumSHA256" in kwargs and kwargs["ChecksumSHA256"] != _b64_sha256(data):
            raise _bad_digest("PutObject")
        self.data[Key] = data
        return {}

    def create_multipart_upload(self, *, Bucket, Key, **kwargs):
        upload = f"upload-{len(self.uploads)}"
        self.uploads[upload] = {"key": Key, "parts": {}, "algorithm": kwargs.get("ChecksumAlgorithm")}
        return {"UploadId": upload}

    def upload_part(self, *, Bucket, Key, UploadId, PartNumber, Body, **kwargs):
        if "ChecksumSHA256" in kwargs and kwargs["ChecksumSHA256"] != _b64_sha256(Body):
            raise _bad_digest("UploadPart")
        self.uploads[UploadId]["parts"][PartNumber] = (Body, kwargs.get("ChecksumSHA256"))
        return {"ETag": f'"{PartNumber}"'}

    def complete_multipart_upload(self, *, Bucket, Key, UploadId, MultipartUpload, IfNoneMatch, **kwargs):
        upload = self.uploads.pop(UploadId)
        for part in MultipartUpload["Parts"]:
            if upload["algorithm"] == "SHA256" and part.get("ChecksumSHA256") != upload["parts"][part["PartNumber"]][1]:
                raise _bad_digest("CompleteMultipartUpload")
        self.data[Key] = b"".join(upload["parts"][part["PartNumber"]][0] for part in MultipartUpload["Parts"])
        return {}

    def abort_multipart_upload(self, *, Bucket, Key, UploadId):
        self.uploads.pop(UploadId, None)
        self.aborted.append(UploadId)

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


def test_bytes_changed_after_hashing_are_never_stored_under_the_digest(objects, tmp_path, monkeypatch):
    from security_lakehouse.distributed import objects as objects_module

    source = tmp_path / "evidence"
    source.write_bytes(b"right")
    real = objects_module.file_sha256
    calls = []

    def hash_then_change(path):
        digest = real(path)
        if not calls:
            source.write_bytes(b"wrong")
        calls.append(path)
        return digest

    monkeypatch.setattr(objects_module, "file_sha256", hash_then_change)
    with pytest.raises(IntegrityError, match="changed during upload"):
        objects.put("tenant-a", source)
    assert objects.client.data == {}

    monkeypatch.setattr(objects_module, "file_sha256", real)
    source.write_bytes(b"right")
    entry = objects.put("tenant-a", source)
    assert objects.client.data[objects.key("tenant-a", entry["sha256"])] == b"right"


def test_body_corrupted_in_transit_is_rejected_by_its_checksum(objects, tmp_path, monkeypatch):
    source = tmp_path / "evidence"
    source.write_bytes(b"right")
    original = objects.client.put_object

    def corrupt_in_transit(**kwargs):
        return original(**{**kwargs, "Body": b"wrong"})

    monkeypatch.setattr(objects.client, "put_object", corrupt_in_transit)
    with pytest.raises(IntegrityError, match="changed during upload"):
        objects.put("tenant-a", source)
    assert objects.client.data == {}


def test_multipart_upload_sends_part_checksums_and_refuses_changed_bytes(objects, tmp_path):
    import hashlib

    source = tmp_path / "evidence"
    source.write_bytes(b"multipart evidence")
    digest = hashlib.sha256(b"multipart evidence").hexdigest()
    key = objects.key("tenant-a", digest)
    objects._multipart(key, source, digest)
    assert objects.client.data[key] == b"multipart evidence"

    other = objects.key("tenant-a", hashlib.sha256(b"expected bytes").hexdigest())
    with pytest.raises(IntegrityError, match="changed during upload"):
        objects._multipart(other, source, hashlib.sha256(b"expected bytes").hexdigest())
    assert other not in objects.client.data
    assert objects.client.aborted


def test_part_checksum_mismatch_aborts_the_upload(objects, tmp_path, monkeypatch):
    import hashlib

    source = tmp_path / "evidence"
    source.write_bytes(b"part bytes")
    digest = hashlib.sha256(b"part bytes").hexdigest()
    original = objects.client.upload_part

    def corrupt_in_transit(**kwargs):
        return original(**{**kwargs, "Body": b"flipped bit"})

    monkeypatch.setattr(objects.client, "upload_part", corrupt_in_transit)
    from botocore.exceptions import ClientError

    with pytest.raises(ClientError):
        objects._multipart(objects.key("tenant-a", digest), source, digest)
    assert objects.client.data == {}
    assert objects.client.aborted


@pytest.mark.parametrize(
    "links",
    [
        {"a": "b/../z", "b": "."},
        {"b": ".", "a": "b/../z"},
        {"a": "b/c/../../z", "b": "d", "d": "."},
        {"a": "b/../escape", "b": "c", "c": "."},
    ],
)
def test_restore_rejects_links_that_escape_once_other_links_exist(objects, tmp_path, links):
    root = tmp_path / "reader"
    with pytest.raises(IntegrityError, match="escapes the workspace"):
        objects.restore("tenant-a", {"tenant_id": "tenant-a", "files": {}, "links": links}, root)
    assert not [path for path in root.rglob("*") if path.is_symlink()]


def test_restore_keeps_contained_links_that_traverse_other_links(objects, tmp_path):
    source = tmp_path / "source"
    (source / "generations/first").mkdir(parents=True)
    (source / "generations/first/evidence").write_text("kept")
    (source / ".active-generation").symlink_to("generations/first")
    (source / "current").symlink_to(".active-generation/evidence")
    manifest = objects.snapshot("tenant-a", source)
    root = tmp_path / "reader"
    objects.restore("tenant-a", manifest, root)
    assert (root / "current").read_text() == "kept"
