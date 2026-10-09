"""Distributed publication, ownership, audit and share routing."""

import sqlalchemy as sa
from alembic import op

revision = "0028_distributed_lake"
down_revision = "0027_api_key_hash_version"
branch_labels = None
depends_on = None


def _alembic_revision_markers():
    return revision, down_revision, branch_labels, depends_on


def upgrade():
    _alembic_revision_markers()
    op.create_table(
        "distributed_clusters",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("config_json", sa.Text, nullable=False),
    )
    op.create_table(
        "distributed_tenant_heads",
        sa.Column("cluster_id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("shard_id", sa.Integer, nullable=False),
        sa.Column("version", sa.BigInteger, nullable=False),
        sa.Column("manifest_json", sa.Text, nullable=False),
        sa.Column("fence", sa.BigInteger, nullable=False),
        sa.Column("owner", sa.String(128)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_distributed_tenant_heads_shard_id", "distributed_tenant_heads", ["shard_id"])
    op.create_table(
        "distributed_revisions",
        sa.Column("cluster_id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("version", sa.BigInteger, primary_key=True),
        sa.Column("manifest_json", sa.Text, nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "distributed_request_audit",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("cluster_id", sa.String(128), nullable=False),
        sa.Column("tenant_id", sa.String(128)),
        sa.Column("event_json", sa.Text, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for col in ("cluster_id", "tenant_id", "occurred_at"):
        op.create_index(f"ix_distributed_request_audit_{col}", "distributed_request_audit", [col])
    op.create_table(
        "distributed_share_index",
        sa.Column("cluster_id", sa.String(128), primary_key=True),
        sa.Column("token_sha256", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
    )

    op.create_table(
        "distributed_schedule_state",
        sa.Column("cluster_id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("target_kind", sa.String(32), primary_key=True),
        sa.Column("target_id", sa.String(256), primary_key=True),
        sa.Column("last_fired_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    _alembic_revision_markers()
    for name in (
        "distributed_schedule_state",
        "distributed_share_index",
        "distributed_request_audit",
        "distributed_revisions",
        "distributed_tenant_heads",
        "distributed_clusters",
    ):
        op.drop_table(name)
