"""Programmatic Alembic driver so migrations ship inside the package.

``alembic upgrade head`` works from a checkout via the repo-root ``alembic.ini``;
this module makes the same migrations runnable from an installed wheel and from
the ``grc-lake db`` CLI, without depending on the ini file.
"""

from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

import security_lakehouse
from security_lakehouse.db.base import database_url


def _config(url: str):
    from alembic.config import Config

    package_dir = Path(security_lakehouse.__file__).resolve().parent
    cfg = Config(stdout=sys.stdout)
    cfg.set_main_option("script_location", str(package_dir / "migrations"))
    # Alembic stores options in ConfigParser: escape interpolation markers,
    # preserving the original URL (including percent-encoded credentials) on read.
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(lake_dir: str | Path, *, url: str | None = None, revision: str = "head") -> str:
    """Upgrade the application-state database to ``revision`` (default head)."""
    from alembic import command

    target_url = url or database_url(lake_dir)
    command.upgrade(_config(target_url), revision)
    return target_url


def require_head(lake_dir: str | Path, *, url: str | None = None) -> None:
    """Raise ``ValueError`` unless the application database is at the packaged head.

    Commands that only read or reconcile application state call this instead
    of migrating: upgrading the schema stays an explicit operator step.
    """
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    from security_lakehouse.db.base import create_engine_for

    target_url = url or database_url(lake_dir)
    expected = set(ScriptDirectory.from_config(_config(target_url)).get_heads())
    engine = create_engine_for(lake_dir, url=target_url)
    try:
        with engine.connect() as connection:
            found = set(MigrationContext.configure(connection).get_current_heads())
    finally:
        engine.dispose()
    if found == expected:
        return
    state = f"is at revision {', '.join(sorted(found))}" if found else "has no schema revision"
    raise ValueError(
        f"the application database {state}; this release expects {', '.join(sorted(expected))}. "
        f"Run `grc-lake db upgrade --lake {lake_dir}` and retry."
    )


def current(lake_dir: str | Path, *, url: str | None = None) -> str:
    """Return the current revision string of the application-state database."""
    from alembic import command

    target_url = url or database_url(lake_dir)
    cfg = _config(target_url)
    buffer = StringIO()
    cfg.print_stdout = buffer.write
    command.current(cfg)
    return buffer.getvalue().strip()
