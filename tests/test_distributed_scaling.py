"""Physical history partitioning and independent PostgreSQL worker admission."""

from concurrent.futures import ThreadPoolExecutor

from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import text

from security_lakehouse.db.migrate import _config
from security_lakehouse.distributed.locks import transaction_lock
from security_lakehouse.operation_jobs import JobQueue


def test_history_is_physically_partitioned_and_tenant_queries_prune(catalog):
    with catalog.engine.begin() as connection:
        kind = connection.scalar(text("SELECT relkind FROM pg_class WHERE oid = 'distributed_revisions'::regclass"))
        assert kind == "p", "retained publication history must use physical PostgreSQL partitions"
        children = connection.scalar(
            text("SELECT count(*) FROM pg_inherits WHERE inhparent = 'distributed_revisions'::regclass")
        )
        assert children == 32
        connection.execute(
            text(
                "INSERT INTO distributed_revisions (cluster_id, tenant_id, version, manifest_json) VALUES ('test-cluster', 'tenant-a', 1, '{}')"
            )
        )
        plan = connection.scalar(
            text(
                "EXPLAIN (FORMAT JSON) SELECT manifest_json FROM distributed_revisions WHERE cluster_id='test-cluster' AND tenant_id='tenant-a' AND version=1"
            )
        )
        node = plan[0]["Plan"]
        assert node["Relation Name"].startswith("distributed_revisions_p")
        assert "Plans" not in node, "a point lookup should visit only one history partition"


def test_history_partition_migration_preserves_rows_both_directions(catalog):
    cfg = _config(catalog.engine.url.render_as_string(hide_password=False))
    command.downgrade(cfg, "0028_distributed_lake")
    expected = [("tenant-" + str(index), '{"proof":' + str(index) + "}") for index in range(80)]
    with catalog.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO distributed_revisions (cluster_id, tenant_id, version, manifest_json) VALUES ('test-cluster', :tenant, 1, :manifest)"
            ),
            [{"tenant": tenant, "manifest": manifest} for tenant, manifest in expected],
        )
    for target in ("head", "0028_distributed_lake", "head"):
        (command.upgrade if target == "head" else command.downgrade)(cfg, target)
        with catalog.engine.connect() as connection:
            actual = list(connection.execute(text("SELECT tenant_id, manifest_json FROM distributed_revisions")))
        assert sorted(actual) == sorted(expected)
    command.check(cfg)


def test_one_tenant_claim_lock_does_not_block_another_tenant(replicas, tmp_path):
    apps, credentials = replicas
    for index, (_, headers) in enumerate(credentials):
        response = TestClient(apps[0]).post(
            "/api/v1/ingestion/eval",
            headers={**headers, "Prefer": "respond-async", "Idempotency-Key": f"claim-{index}"},
            json={},
        )
        assert response.status_code == 202
    queue = JobQueue(apps[1].state.sessionmaker, tmp_path / "worker")
    with apps[0].state.sessionmaker.begin() as session:
        # The old cluster-wide lock must no longer serialize unrelated claims.
        transaction_lock(session, "claim", queue.root_key)
        transaction_lock(session, "tenant-claim", queue.root_key + credentials[0][0])
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(queue.claim)
            try:
                row = pending.result(timeout=2)
            finally:
                # Release before joining the thread, including on the old code.
                session.rollback()
    assert row is not None and row.tenant_id == credentials[1][0]


def test_claim_does_not_resurrect_a_concurrently_cancelled_job(replicas, tmp_path, monkeypatch):
    from sqlalchemy import select, update
    from sqlalchemy.orm import Session

    from security_lakehouse.db.models import OperationJob

    apps, credentials = replicas
    tenant, headers = credentials[0]
    response = TestClient(apps[0]).post(
        "/api/v1/ingestion/eval",
        headers={**headers, "Prefer": "respond-async", "Idempotency-Key": "cancel-race"},
        json={},
    )
    assert response.status_code == 202
    factory = apps[0].state.sessionmaker
    original = Session.scalar
    cancelled = []

    def scalar(session, *args, **kwargs):
        result = original(session, *args, **kwargs)
        if isinstance(result, OperationJob) and result.status == "queued" and not cancelled:
            with factory.kw["bind"].begin() as connection:
                connection.execute(update(OperationJob).where(OperationJob.id == result.id).values(status="cancelled"))
            cancelled.append(result.id)
        return result

    monkeypatch.setattr(Session, "scalar", scalar)
    queue = JobQueue(factory, tmp_path / "worker")
    assert queue.claim() is None
    assert cancelled
    with factory() as session:
        assert session.scalar(select(OperationJob.status).where(OperationJob.tenant_id == tenant)) == "cancelled"


def test_distributed_claim_uses_database_time_for_fairness(replicas, tmp_path, monkeypatch):
    import time

    from sqlalchemy import select

    from security_lakehouse.db.models import DistributedTenantHead

    apps, credentials = replicas
    tenant, headers = credentials[0]
    response = TestClient(apps[0]).post(
        "/api/v1/ingestion/eval",
        headers={**headers, "Prefer": "respond-async", "Idempotency-Key": "clock-fairness"},
        json={},
    )
    assert response.status_code == 202
    before = time.time()
    monkeypatch.setattr("security_lakehouse.operation_jobs.time.time", lambda: before + 100000)
    queue = JobQueue(apps[0].state.sessionmaker, tmp_path / "worker")
    row = queue.claim()
    assert before <= row.started_at < before + 10
    with apps[0].state.sessionmaker() as session:
        recorded = session.scalar(
            select(DistributedTenantHead.last_job_started_at).where(DistributedTenantHead.tenant_id == tenant)
        )
        assert recorded == row.started_at


def test_distributed_renewal_and_recovery_ignore_worker_clock_skew(replicas, tmp_path, monkeypatch):
    import time

    from sqlalchemy import select

    from security_lakehouse.db.models import OperationJob

    apps, credentials = replicas
    _, headers = credentials[0]
    response = TestClient(apps[0]).post(
        "/api/v1/ingestion/eval",
        headers={**headers, "Prefer": "respond-async", "Idempotency-Key": "clock-recovery"},
        json={},
    )
    assert response.status_code == 202
    queue = JobQueue(apps[0].state.sessionmaker, tmp_path / "worker")
    row = queue.claim()
    assert row is not None
    before = time.time()
    monkeypatch.setattr("security_lakehouse.operation_jobs.time.time", lambda: before + 100000)
    queue.recover()
    assert queue.owns_claim(row), "a fast host must not interrupt a fresh claim before execution starts"
    assert queue.renew(row)
    with queue.factory() as session:
        heartbeat = session.scalar(select(OperationJob.heartbeat_at).where(OperationJob.id == row.id))
        assert before <= heartbeat < before + 10
    with queue.factory.begin() as session:
        session.execute(
            text("UPDATE operation_jobs SET heartbeat_at=EXTRACT(EPOCH FROM clock_timestamp()) - 1000 WHERE id=:id"),
            {"id": row.id},
        )
    monkeypatch.setattr("security_lakehouse.operation_jobs.time.time", lambda: before - 100000)
    queue.recover()
    with queue.factory() as session:
        recovered = session.get(OperationJob, row.id)
        assert recovered.status == "interrupted", "a slow host must still recover an expired unowned claim"
        assert before <= recovered.finished_at < before + 10


def test_partition_migration_preserves_column_grants_and_does_not_broaden_child_access(catalog):
    import uuid

    cfg = _config(catalog.engine.url.render_as_string(hide_password=False))
    command.downgrade(cfg, "0028_distributed_lake")
    role = "grc_partition_test_" + uuid.uuid4().hex
    with catalog.engine.begin() as connection:
        connection.execute(text(f"CREATE ROLE {role}"))
        connection.execute(text(f"GRANT SELECT (manifest_json) ON distributed_revisions TO {role}"))
        connection.execute(text("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC"))
    try:
        command.upgrade(cfg, "head")
        with catalog.engine.connect() as connection:
            assert connection.scalar(
                text("SELECT has_column_privilege(:role, 'distributed_revisions', 'manifest_json', 'SELECT')"),
                {"role": role},
            )
            assert not connection.scalar(
                text("SELECT has_table_privilege(:role, 'distributed_revisions', 'SELECT')"), {"role": role}
            )
            exposed = connection.scalar(
                text("""
                SELECT count(*) FROM pg_class c, LATERAL aclexplode(c.relacl) a
                WHERE (c.oid='distributed_revisions'::regclass OR c.oid IN (
                    SELECT inhrelid FROM pg_inherits WHERE inhparent='distributed_revisions'::regclass
                )) AND a.grantee=0
            """)
            )
            assert exposed == 0, "default grants must not expose replacement tables"
    finally:
        with catalog.engine.begin() as connection:
            connection.execute(text(f"DROP OWNED BY {role}"))
            connection.execute(text(f"DROP ROLE {role}"))


def test_partition_migration_refuses_to_discard_operator_rls(catalog):
    import pytest

    cfg = _config(catalog.engine.url.render_as_string(hide_password=False))
    command.downgrade(cfg, "0028_distributed_lake")
    with catalog.engine.begin() as connection:
        connection.execute(text("ALTER TABLE distributed_revisions ENABLE ROW LEVEL SECURITY"))
        connection.execute(text("CREATE POLICY tenant_policy ON distributed_revisions USING (tenant_id='tenant-a')"))
    with pytest.raises(RuntimeError, match="custom RLS"):
        command.upgrade(cfg, "head")
    with catalog.engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0028_distributed_lake"
        assert connection.scalar(
            text("SELECT relrowsecurity FROM pg_class WHERE oid='distributed_revisions'::regclass")
        )
        assert (
            connection.scalar(text("SELECT count(*) FROM pg_policy WHERE polrelid='distributed_revisions'::regclass"))
            == 1
        )


def test_partition_downgrade_refuses_to_discard_child_security_policy(catalog):
    import pytest

    cfg = _config(catalog.engine.url.render_as_string(hide_password=False))
    with catalog.engine.begin() as connection:
        connection.execute(text("ALTER TABLE distributed_revisions_p00 ENABLE ROW LEVEL SECURITY"))
        connection.execute(text("CREATE POLICY local_policy ON distributed_revisions_p00 USING (tenant_id='tenant-a')"))
    with pytest.raises(RuntimeError, match="custom RLS"):
        command.downgrade(cfg, "0028_distributed_lake")
    with catalog.engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0029_distributed_scaling"
        assert connection.scalar(
            text("SELECT relrowsecurity FROM pg_class WHERE oid='distributed_revisions_p00'::regclass")
        )
