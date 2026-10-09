"""Mark API key digests by hashing scheme so legacy rows upgrade on use."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027_api_key_hash_version"
down_revision: str | None = "0026_authority_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alembic_revision_markers() -> tuple[str, str | None, str | Sequence[str] | None, str | Sequence[str] | None]:
    return revision, down_revision, branch_labels, depends_on


def upgrade() -> None:
    _alembic_revision_markers()
    op.add_column("api_keys", sa.Column("hash_version", sa.Integer, nullable=False, server_default="1"))


def downgrade() -> None:
    _alembic_revision_markers()
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT count(*) FROM api_keys WHERE hash_version <> 1")).scalar():
        raise RuntimeError(
            "downgrade would orphan API keys already rehashed to the keyed digest; "
            "retain this schema or reissue those keys after restoring a verified backup"
        )
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("hash_version")
