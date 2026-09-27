"""saml_assertion_replays (SAML replay cache shared across replicas)

Revision ID: 0020_saml_assertion_replays
Revises: 0019_task_resolution_note
Create Date: 2026-09-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_saml_assertion_replays"
down_revision: str | None = "0019_task_resolution_note"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.create_table(
        "saml_assertion_replays",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("assertion_id", sa.String(length=512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "assertion_id", name="uq_saml_assertion_replays_issuer_assertion"),
    )
    op.create_index("ix_saml_assertion_replays_expires_at", "saml_assertion_replays", ["expires_at"])


def downgrade() -> None:
    _alembic_revision_markers()
    op.drop_index("ix_saml_assertion_replays_expires_at", table_name="saml_assertion_replays")
    op.drop_table("saml_assertion_replays")
