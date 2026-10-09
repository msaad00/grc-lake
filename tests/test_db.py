"""Application-state database tests (server mode, SQLite-backed).

These run the real Alembic migration against a throwaway SQLite database, so a
green run proves the migration, the models, and the repository agree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from sqlalchemy import inspect

from security_lakehouse.db import migrate
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import (
    create_tenant,
    create_user,
    get_tenant_by_slug,
    get_user_by_email,
)


@pytest.fixture
def factory(tmp_path: Path):
    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    return session_factory(engine), engine


def test_migration_creates_expected_schema(tmp_path: Path) -> None:
    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    tables = set(inspect(engine).get_table_names())
    assert {"tenants", "users", "alembic_version"} <= tables


def test_db_current_reports_head_after_upgrade(tmp_path: Path) -> None:
    migrate.upgrade(tmp_path)
    assert "(head)" in migrate.current(tmp_path)


def test_tenant_and_user_round_trip(factory) -> None:
    sessionmaker_, _engine = factory
    with session_scope(sessionmaker_) as session:
        tenant = create_tenant(session, slug="acme", name="Acme Inc")
        create_user(session, tenant_id=tenant.id, email="sec@acme.test", display_name="Sec", role="admin")

    with session_scope(sessionmaker_) as session:
        tenant = get_tenant_by_slug(session, slug="acme")
        assert tenant is not None
        user = get_user_by_email(session, tenant_id=tenant.id, email="sec@acme.test")
        assert user is not None
        assert user.role == "admin"
        assert user.is_active is True


def test_invalid_role_is_rejected(factory) -> None:
    sessionmaker_, _engine = factory
    with session_scope(sessionmaker_) as session:
        tenant = create_tenant(session, slug="acme", name="Acme Inc")
        with pytest.raises(ValueError, match="role must be one of"):
            create_user(session, tenant_id=tenant.id, email="x@acme.test", role="superuser")


def test_email_unique_within_tenant(factory) -> None:
    from sqlalchemy.exc import IntegrityError

    sessionmaker_, _engine = factory
    with session_scope(sessionmaker_) as session:
        tenant = create_tenant(session, slug="acme", name="Acme Inc")
        create_user(session, tenant_id=tenant.id, email="dup@acme.test")

    with pytest.raises(IntegrityError), session_scope(sessionmaker_) as session:
        tenant = get_tenant_by_slug(session, slug="acme")
        assert tenant is not None
        create_user(session, tenant_id=tenant.id, email="dup@acme.test")


def test_same_email_allowed_across_tenants(factory) -> None:
    sessionmaker_, _engine = factory
    with session_scope(sessionmaker_) as session:
        acme = create_tenant(session, slug="acme", name="Acme Inc")
        beta = create_tenant(session, slug="beta", name="Beta LLC")
        create_user(session, tenant_id=acme.id, email="shared@example.test")
        create_user(session, tenant_id=beta.id, email="shared@example.test")
