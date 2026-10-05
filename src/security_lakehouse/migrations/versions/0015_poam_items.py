"""poam_items table for gov/defense POA&M tracking

Revision ID: 0015_poam_items
Revises: 0014_policy_acknowledgments
Create Date: 2026-07-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_poam_items"
down_revision: str | None = "0014_policy_acknowledgments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.create_table(
        "poam_items",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("framework_id", sa.String(length=64), server_default="cmmc-2-level2", nullable=False),
        sa.Column("requirement_id", sa.String(length=32), nullable=False),
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("weakness", sa.Text(), server_default="", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="open", nullable=False),
        sa.Column("owner", sa.String(length=255), server_default="", nullable=False),
        sa.Column("milestone", sa.Text(), server_default="", nullable=False),
        sa.Column("sprs_points", sa.Integer(), server_default="1", nullable=False),
        sa.Column("poam_eligible", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediation_task_id", sa.String(length=36), nullable=True),
        sa.Column("created_by", sa.String(length=255), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_poam_items_tenant_id", "poam_items", ["tenant_id"])
    op.create_index("ix_poam_items_requirement_id", "poam_items", ["requirement_id"])
    op.create_index("ix_poam_items_control_id", "poam_items", ["control_id"])
    op.create_index(
        "ix_poam_items_tenant_framework_status",
        "poam_items",
        ["tenant_id", "framework_id", "status"],
    )


def downgrade() -> None:
    _alembic_revision_markers()
    op.drop_index("ix_poam_items_tenant_framework_status", table_name="poam_items")
    op.drop_index("ix_poam_items_control_id", table_name="poam_items")
    op.drop_index("ix_poam_items_requirement_id", table_name="poam_items")
    op.drop_index("ix_poam_items_tenant_id", table_name="poam_items")
    op.drop_table("poam_items")
