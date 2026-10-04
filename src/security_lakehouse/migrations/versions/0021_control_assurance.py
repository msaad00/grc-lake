"""Independent exception approval and retained remediation verification receipts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_control_assurance"
down_revision: str | None = "0020_saml_assertion_replays"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.add_column(
        "remediation_tasks", sa.Column("verification_history", sa.Text(), nullable=False, server_default="[]")
    )
    for name in ("requested_by_id", "approved_by_id"):
        op.add_column("control_exceptions", sa.Column(name, sa.String(36), nullable=True))
    op.add_column("control_exceptions", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    # Retain historical claimed approver and dates, but never treat them as
    # independently authenticated approval. Legacy records can be revoked and re-requested.
    op.execute("UPDATE control_exceptions SET status = 'pending' WHERE status = 'active'")


def downgrade() -> None:
    _alembic_revision_markers()
    with op.batch_alter_table("control_exceptions") as batch:
        batch.drop_column("approved_at")
        batch.drop_column("approved_by_id")
        batch.drop_column("requested_by_id")
    with op.batch_alter_table("remediation_tasks") as batch:
        batch.drop_column("verification_history")
