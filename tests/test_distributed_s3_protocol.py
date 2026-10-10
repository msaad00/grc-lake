"""Real boto3 HTTP requests against an S3 emulator, not provider qualification."""

import hashlib
import uuid

import pytest

from security_lakehouse.distributed.config import ClusterConfig
from security_lakehouse.distributed.objects import ObjectStore


def test_s3_http_conditional_put_multipart_and_verified_restore(tmp_path, monkeypatch):
    pytest.importorskip("moto.server")
    from moto.server import ThreadedMotoServer

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    try:
        host, port = server.get_host_and_port()
        config = ClusterConfig("protocol-test", "grc-protocol-" + uuid.uuid4().hex, endpoint=f"http://{host}:{port}")
        store = ObjectStore(config)
        store.client.create_bucket(Bucket=config.bucket)
        store.verify_conditional_writes()
        for size in (1024, 33 * 1024**2):
            source = tmp_path / f"source-{size}"
            with source.open("wb") as output:
                for _ in range(size // 1024):
                    output.write(b"x" * 1024)
            entry = store.put("tenant-a", source)
            assert store.put("tenant-a", source) == entry
            target = tmp_path / f"restored-{size}"
            store.get("tenant-a", entry, target)
            assert target.stat().st_size == size
            assert hashlib.sha256(target.read_bytes()).hexdigest() == entry["sha256"]

        from security_lakehouse.distributed import objects as objects_module
        from security_lakehouse.distributed.objects import IntegrityError

        for size in (1024, 33 * 1024**2):
            source = tmp_path / f"changing-{size}"
            source.write_bytes(b"y" * size)
            expected = objects_module.file_sha256(source)
            source.write_bytes(b"z" * size)
            with monkeypatch.context() as patch:
                patch.setattr(objects_module, "file_sha256", lambda _path, value=expected: value)
                with pytest.raises(IntegrityError, match="changed during upload"):
                    store.put("tenant-a", source)
            key = store.key("tenant-a", expected)
            listed = store.client.list_objects_v2(Bucket=config.bucket, Prefix=key)
            assert listed.get("KeyCount", 0) == 0
            assert not store.client.list_multipart_uploads(Bucket=config.bucket).get("Uploads")
    finally:
        server.stop()
