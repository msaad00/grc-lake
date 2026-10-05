"""Retain API-key provenance for exchanged browser sessions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_session_key_origin"
down_revision: str | None = "0022_audit_workpapers"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    with op.batch_alter_table("user_sessions") as batch:
        batch.add_column(sa.Column("source_api_key_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_user_sessions_source_api_key", "api_keys", ["source_api_key_id"], ["id"], ondelete="SET NULL"
        )


def downgrade() -> None:
    _alembic_revision_markers()
    with op.batch_alter_table("user_sessions") as batch:
        batch.drop_constraint("fk_user_sessions_source_api_key", type_="foreignkey")
        batch.drop_column("source_api_key_id")
