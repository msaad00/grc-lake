"""Retain the stable creator identity for independent agent-run review."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_agent_creator_identity"
down_revision: str | None = "0023_session_key_origin"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.add_column("agent_runs", sa.Column("created_by_id", sa.String(36), nullable=True))


def downgrade() -> None:
    _alembic_revision_markers()
    with op.batch_alter_table("agent_runs") as batch:
        batch.drop_column("created_by_id")
