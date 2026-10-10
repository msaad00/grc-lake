"""Server-mode application-state database (SQLAlchemy 2.0).

Local mode never touches this module: posture, evidence, and snapshots stay
file-based and deterministic. The application-state database holds the
*operational* records server mode needs — tenants, users, and (in later
work) remediation tasks, SLAs, and connector state — where transactions and
row-level tenant isolation matter.

Connection URL resolution (first match wins):

1. ``GRC_LAKE_DATABASE_URL`` environment variable (e.g. a Postgres DSN)
2. ``sqlite:///<lake>/server/app.db`` (zero-config default for a single node)
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Select, create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from security_lakehouse.runtime_environment import runtime_env

ENV_DATABASE_URL = "GRC_LAKE_DATABASE_URL"

# Pagination bounds for list endpoints. ``DEFAULT_PAGE_LIMIT`` is the page size
# the HTTP layer applies when a caller does not ask for one; ``MAX_PAGE_LIMIT``
# is the hard ceiling so a hostile ``?limit=10000000`` cannot exhaust memory.
DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 500


def clamp_limit(limit: int | None, *, default: int = DEFAULT_PAGE_LIMIT, maximum: int = MAX_PAGE_LIMIT) -> int:
    """Clamp a caller-supplied page size into ``[1, maximum]`` (``default`` when unset/invalid)."""
    if limit is None:
        return default
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def count_rows(session: Session, stmt: Select) -> int:
    """Total rows ``stmt`` matches, ignoring its ordering and any page window."""
    return int(session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0)


def apply_pagination(stmt: Select, *, limit: int | None = None, offset: int | None = None) -> Select:
    """Apply ``LIMIT``/``OFFSET`` to a select.

    ``limit=None`` leaves the statement unbounded so internal callers (SDK/CLI
    aggregations that need every row) keep their current behaviour. The HTTP
    layer always passes an explicit, clamped limit so API responses are bounded.
    """
    if limit is not None:
        stmt = stmt.limit(clamp_limit(limit))
    if offset:
        stmt = stmt.offset(max(0, int(offset)))
    return stmt


class Base(DeclarativeBase):
    """Declarative base for all application-state tables."""


def database_url(lake_dir: str | Path) -> str:
    """Resolve the application-state database URL for a lake directory."""
    override = runtime_env().get(ENV_DATABASE_URL)
    if override:
        return override
    db_path = Path(lake_dir) / "server" / "app.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


def create_engine_for(lake_dir: str | Path, *, url: str | None = None, echo: bool = False) -> Engine:
    """Build an engine for the application-state database."""
    resolved = url or database_url(lake_dir)
    connect_args = {"check_same_thread": False} if resolved.startswith("sqlite") else {}
    return create_engine(resolved, echo=echo, future=True, connect_args=connect_args)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, class_=_WorkspaceSession, expire_on_commit=False, future=True)


class _WorkspaceSession(Session):
    """Domain commits join a distributed publication's outer transaction."""

    def __init__(self, **kwargs):
        from security_lakehouse.distributed.context import binding

        workspace = binding.get()
        if workspace is not None and workspace.connection is not None:
            engine = kwargs.get("bind")
            if engine is None or engine.url != workspace.connection.engine.url:
                raise ValueError("distributed transaction cannot span different databases")
            kwargs["bind"] = workspace.connection
            kwargs["join_transaction_mode"] = "create_savepoint"
        super().__init__(**kwargs)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional session scope: commit on success, roll back on error."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
