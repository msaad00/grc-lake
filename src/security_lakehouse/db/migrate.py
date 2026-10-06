"""Programmatic Alembic driver so migrations ship inside the package.

``alembic upgrade head`` works from a checkout via the repo-root ``alembic.ini``;
this module makes the same migrations runnable from an installed wheel and from
the ``security-lakehouse db`` CLI, without depending on the ini file.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import security_lakehouse
from security_lakehouse.db.base import database_url


def _config(url: str):
    from alembic.config import Config

    package_dir = Path(security_lakehouse.__file__).resolve().parent
    cfg = Config()
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


def current(lake_dir: str | Path, *, url: str | None = None) -> str:
    """Return the current revision string of the application-state database."""
    from alembic import command

    target_url = url or database_url(lake_dir)
    cfg = _config(target_url)
    buffer = StringIO()
    cfg.print_stdout = buffer.write
    command.current(cfg)
    return buffer.getvalue().strip()
