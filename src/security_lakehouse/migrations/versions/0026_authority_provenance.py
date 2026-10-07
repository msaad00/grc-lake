"""Retain remediation actors and the session authorizing queued work."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026_authority_provenance"
down_revision: str | None = "0025_operation_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    # Repair the already-installed SQLite default as well as fresh installs.
    with op.batch_alter_table("policy_acknowledgments") as batch:
        batch.alter_column(
            "acknowledged_at",
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=False,
            server_default=sa.func.now(),
        )
    # Do not manufacture unknown historical ownership or session provenance.
    op.add_column("remediation_tasks", sa.Column("authority_history", sa.Text, nullable=True))
    op.add_column("operation_jobs", sa.Column("session_id", sa.String(36), nullable=True))


def downgrade() -> None:
    _alembic_revision_markers()
    connection = op.get_bind()
    if (
        connection.execute(
            sa.text("SELECT count(*) FROM remediation_tasks WHERE authority_history IS NOT NULL")
        ).scalar()
        or connection.execute(sa.text("SELECT count(*) FROM operation_jobs WHERE session_id IS NOT NULL")).scalar()
    ):
        raise RuntimeError(
            "downgrade would erase retained authority provenance; retain this schema and restore a verified backup for an older application"
        )
    with op.batch_alter_table("operation_jobs") as batch:
        batch.drop_column("session_id")
    with op.batch_alter_table("remediation_tasks") as batch:
        batch.drop_column("authority_history")
