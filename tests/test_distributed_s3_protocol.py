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
    finally:
        server.stop()
