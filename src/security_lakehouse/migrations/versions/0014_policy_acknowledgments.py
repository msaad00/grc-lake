"""policy employee acknowledgments (GRC attestation)

Revision ID: 0014_policy_acknowledgments
Revises: 0013_tenant_plan_tier
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_policy_acknowledgments"
down_revision: str | None = "0013_tenant_plan_tier"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.create_table(
        "policy_acknowledgments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("policy_document_id", sa.String(length=36), nullable=False),
        sa.Column("user_email", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), server_default="", nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["policy_document_id"], ["policy_documents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "policy_document_id",
            "user_email",
            name="uq_policy_ack_tenant_document_email",
        ),
    )
    op.create_index("ix_policy_ack_tenant_id", "policy_acknowledgments", ["tenant_id"])
    op.create_index(
        "ix_policy_ack_tenant_policy",
        "policy_acknowledgments",
        ["tenant_id", "policy_document_id"],
    )


def downgrade() -> None:
    _alembic_revision_markers()
    op.drop_index("ix_policy_ack_tenant_policy", table_name="policy_acknowledgments")
    op.drop_index("ix_policy_ack_tenant_id", table_name="policy_acknowledgments")
    op.drop_table("policy_acknowledgments")
