"""Lazy fixture factories for distributed contracts."""

import pytest


def _create_distributed_catalog():
    import os
    import uuid

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from security_lakehouse.distributed.catalog import Catalog
    from security_lakehouse.distributed.config import ClusterConfig

    url = os.environ.get("TEST_POSTGRES_URL")
    if not url:
        pytest.skip("requires TEST_POSTGRES_URL")
    name = "grc_distributed_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    engine = create_engine(make_url(url).set(database=name))
    from security_lakehouse.db.migrate import upgrade

    upgrade(".", url=engine.url.render_as_string(hide_password=False))
    result = Catalog(engine, ClusterConfig("test-cluster", "test-bucket", shards=64))
    result.initialize()
    try:
        yield result
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def _create_distributed_replicas(catalog, tmp_path, monkeypatch):
    from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
    from security_lakehouse.distributed import objects as module
    from security_lakehouse.server_app import create_app
    from test_distributed_objects import MemoryObjects

    monkeypatch.setenv("GRC_LAKE_DEPLOYMENT_MODE", "distributed")
    monkeypatch.setenv("GRC_LAKE_CLUSTER_ID", "test-cluster")
    monkeypatch.setenv("GRC_LAKE_OBJECT_BUCKET", "test-bucket")
    monkeypatch.setenv("GRC_LAKE_DATABASE_URL", catalog.engine.url.render_as_string(hide_password=False))
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "x" * 48)
    monkeypatch.setenv("GRC_LAKE_API_RATE_LIMIT_RPS", "0")
    objects = MemoryObjects()
    object_store = module.ObjectStore

    monkeypatch.setattr(module, "ObjectStore", lambda config: object_store(config, client=objects))
    apps = [create_app(tmp_path / str(i)) for i in range(2)]
    credentials = []
    with apps[0].state.sessionmaker.begin() as session:
        for name in ("a", "b"):
            tenant = create_tenant(session, slug=name, name=name)
            user = create_user(session, tenant_id=tenant.id, email=f"{name}@example.test", role="security_admin")
            _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            credentials.append((tenant.id, {"Authorization": f"Bearer {token}"}))
    try:
        yield apps, credentials
    finally:
        for app in apps:
            app.state.sessionmaker.kw["bind"].dispose()
