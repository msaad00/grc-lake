"""Two API roots and a spawned worker share real PostgreSQL and S3 HTTP state."""

from functools import partial
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def test_spawned_worker_publishes_evidence_visible_to_another_replica(catalog, tmp_path, monkeypatch):
    pytest.importorskip("moto.server")
    from moto.server import ThreadedMotoServer

    from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
    from security_lakehouse.distributed.commands import download_partitions
    from security_lakehouse.operation_execution import execute_operation, execute_stored_operation
    from security_lakehouse.operation_jobs import JobWorker
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.server_app import create_app

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    apps = []
    try:
        host, port = server.get_host_and_port()
        # This fixture's catalog identity is already registered without an
        # endpoint; use another cluster identity for the HTTP-backed deployment.
        for key, value in {
            "GRC_LAKE_DEPLOYMENT_MODE": "distributed",
            "GRC_LAKE_CLUSTER_ID": "protocol-cluster",
            "GRC_LAKE_OBJECT_BUCKET": "protocol-bucket",
            "GRC_LAKE_OBJECT_ENDPOINT": f"http://{host}:{port}",
            "GRC_LAKE_OBJECT_ALLOW_HTTP": "1",
            "GRC_LAKE_DATABASE_URL": catalog.engine.url.render_as_string(hide_password=False),
            "GRC_LAKE_COOKIE_SIGNING_KEY": "x" * 48,
            "GRC_LAKE_API_RATE_LIMIT_RPS": "0",
        }.items():
            monkeypatch.setenv(key, value)
        from sqlalchemy import delete

        from security_lakehouse.db.models import DistributedCluster

        with catalog.engine.begin() as connection:
            connection.execute(delete(DistributedCluster))
        apps = [create_app(tmp_path / f"api-{i}") for i in range(2)]
        runtime = apps[0].state.distributed_runtime
        runtime.objects.client.create_bucket(Bucket="protocol-bucket")
        with apps[0].state.sessionmaker.begin() as session:
            tenant = create_tenant(session, slug="protocol", name="Protocol")
            user = create_user(session, tenant_id=tenant.id, email="protocol@example.test", role="security_admin")
            _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        source = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
        with runtime.write(tenant.id) as lake:
            run_pipeline(source, lake, tenant_id=tenant.id)
        before = runtime.catalog.head(tenant.id).version
        headers = {"Authorization": f"Bearer {token}", "Prefer": "respond-async", "Idempotency-Key": "protocol-eval"}
        response = TestClient(apps[0]).post("/api/v1/ingestion/eval", json={}, headers=headers)
        assert response.status_code == 202, response.text
        job = response.json()["data"]
        queue = apps[1].state.operation_queue
        worker = JobWorker(
            queue,
            partial(execute_operation, queue.root, factory=queue.factory, require_auth=True),
            subprocess_execute=partial(execute_stored_operation, require_auth=True),
            timeout_seconds=60,
        )
        assert worker.run_once(isolated=True)
        observed = TestClient(apps[0]).get(job["status_url"], headers=headers).json()["data"]
        assert observed["status"] == "succeeded", observed
        assert runtime.catalog.head(tenant.id).version > before
        downloaded = download_partitions(
            apps[1].state.distributed_runtime, tenant.id, tmp_path / "analytics", source="cloud-cspm"
        )
        assert downloaded["row_count"] > 0
        assert all(part["source"] == "cloud-cspm" for part in downloaded["partitions"])
        # Local scratch disappears without losing publication visibility.
        import shutil

        shutil.rmtree(apps[1].state.distributed_runtime.scratch / "read-cache", ignore_errors=True)
        with apps[1].state.distributed_runtime.read(tenant.id) as lake:
            assert (lake / "silver/normalized_events.jsonl").exists()
    finally:
        for app in apps:
            app.state.sessionmaker.kw["bind"].dispose()
        server.stop()
