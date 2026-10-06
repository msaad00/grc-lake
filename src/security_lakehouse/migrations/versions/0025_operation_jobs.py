"""Durable tenant-scoped HTTP operations."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_operation_jobs"
down_revision: str | None = "0024_agent_creator_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.create_table(
        "operation_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("root_key", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("api_key_id", sa.String(36), nullable=True),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("path", sa.String(255), nullable=False),
        sa.Column("payload_json", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("worker_token", sa.String(36), nullable=True),
        sa.Column("created_at", sa.Float, nullable=False),
        sa.Column("started_at", sa.Float, nullable=True),
        sa.Column("heartbeat_at", sa.Float, nullable=True),
        sa.Column("finished_at", sa.Float, nullable=True),
        sa.Column("result_json", sa.Text, nullable=True),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.UniqueConstraint("root_key", "tenant_id", "user_id", "idempotency_key", name="uq_operation_job_request"),
    )
    op.create_index("ix_operation_jobs_queue", "operation_jobs", ["root_key", "status", "created_at"])
    op.create_index("ix_operation_jobs_tenant", "operation_jobs", ["root_key", "tenant_id", "created_at"])


def downgrade() -> None:
    _alembic_revision_markers()
    op.drop_table("operation_jobs")
