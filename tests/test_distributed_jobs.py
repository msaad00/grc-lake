"""Worker routing and claims are coordinated by PostgreSQL across local roots."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from security_lakehouse.operation_jobs import JobQueue


def test_cross_replica_claims_never_run_two_jobs_for_one_tenant(replicas, tmp_path):
    apps, credentials = replicas
    from fastapi.testclient import TestClient

    client = TestClient(apps[0])
    for index, (_, headers) in enumerate(credentials):
        for job in range(2):
            response = client.post(
                "/api/v1/ingestion/eval",
                headers={**headers, "Prefer": "respond-async", "Idempotency-Key": f"{index}-{job}"},
                json={},
            )
            assert response.status_code == 202
    queues = [JobQueue(app.state.sessionmaker, tmp_path / str(i)) for i, app in enumerate(apps)]
    with ThreadPoolExecutor(2) as pool:
        claimed = list(pool.map(lambda q: q.claim(), queues))
    assert all(row is not None for row in claimed)
    assert len({row.tenant_id for row in claimed}) == 2
    assert queues[0].claim() is None


def test_shard_assignment_limits_claims_and_execution_lock_is_cross_replica(replicas, tmp_path):
    apps, credentials = replicas
    from fastapi.testclient import TestClient

    tenant, headers = credentials[0]
    response = TestClient(apps[0]).post(
        "/api/v1/ingestion/eval", headers={**headers, "Prefer": "respond-async", "Idempotency-Key": "sharded"}, json={}
    )
    assert response.status_code == 202
    shard = apps[0].state.distributed_runtime.catalog.config.shard_for(tenant)
    wrong = JobQueue(apps[1].state.sessionmaker, tmp_path / "wrong", shards={(shard + 1) % 64})
    assert wrong.claim() is None
    owner = JobQueue(apps[0].state.sessionmaker, tmp_path / "owner", shards={shard})
    row = owner.claim()
    assert row is not None
    other = JobQueue(apps[1].state.sessionmaker, tmp_path / "other")
    with owner.execution_lock(row), pytest.raises(BlockingIOError), other.execution_lock(row):
        pytest.fail("two processes own the job")
    with other.execution_lock(row):
        assert other.owns_claim(row)
