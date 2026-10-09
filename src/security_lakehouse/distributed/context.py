"""Request-local workspace and transaction; copied into FastAPI worker threads."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection


@dataclass(frozen=True)
class WorkspaceBinding:
    tenant_id: str
    path: Path
    connection: Connection | None = None
    owner: str | None = None
    fence: int | None = None


binding: ContextVar[WorkspaceBinding | None] = ContextVar("distributed_workspace", default=None)
