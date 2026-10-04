"""Immutable auditor workpapers and independent review metadata."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_audit_workpapers"
down_revision: str | None = "0021_control_assurance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.create_table(
        "audit_workpapers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("content_json", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("created_by_id", sa.String(36), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("status", sa.String(16), server_default="draft", nullable=False),
        sa.Column("reviewed_by_id", sa.String(36)),
        sa.Column("reviewed_by", sa.String(320)),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("review_rationale", sa.Text()),
    )
    op.create_index("ix_audit_workpapers_tenant_id", "audit_workpapers", ["tenant_id"])


def downgrade() -> None:
    _alembic_revision_markers()
    op.drop_table("audit_workpapers")
