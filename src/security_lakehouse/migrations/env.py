"""Alembic environment for the application-state database."""

from __future__ import annotations

from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool, text

from security_lakehouse.db.models import Tenant

config = context.config
target_metadata = Tenant.metadata


def _ensure_sqlite_parent(url: str) -> None:
    """Create the parent directory for a file-based SQLite URL if absent."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return
    db_path = url[len(prefix) :]
    if db_path and db_path != ":memory:":
        Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("alembic sqlalchemy.url is not configured")
    _ensure_sqlite_parent(url)
    connectable = create_engine(url, poolclass=pool.NullPool, future=True)
    with connectable.begin() as connection:
        if connection.dialect.name == "postgresql":
            # All replicas use the same transaction lock before inspecting the
            # Alembic version. Concurrent fresh starts cannot race DDL.
            connection.execute(text("SELECT pg_advisory_xact_lock(7147289521360321)"))
        partitions = set()
        if connection.dialect.name == "postgresql":
            partitions = set(
                connection.scalars(
                    text("""
                SELECT child.relname FROM pg_inherits i
                JOIN pg_class child ON child.oid=i.inhrelid
                WHERE i.inhparent=to_regclass('distributed_revisions')
            """)
                )
            )

        def include_object(obj, name, type_, reflected, compare_to):
            return not (reflected and type_ == "table" and name in partitions)

        context.configure(
            connection=connection, target_metadata=target_metadata, render_as_batch=True, include_object=include_object
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
