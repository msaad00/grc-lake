"""Partition retained history and index bounded tenant worker/audit queries."""

import sqlalchemy as sa
from alembic import op

revision = "0029_distributed_scaling"
down_revision = "0028_distributed_lake"
branch_labels = None
depends_on = None


def _revision_markers():
    return revision, down_revision, branch_labels, depends_on


def _rebuild_history(partitioned):
    connection = op.get_bind()
    connection.execute(sa.text("LOCK TABLE distributed_revisions IN ACCESS EXCLUSIVE MODE"))
    # Preserve explicit application-role grants when replacing the parent. RLS
    # and custom triggers need an operator-planned migration, not silent removal.
    custom = connection.scalar(
        sa.text("""
        SELECT relrowsecurity OR relforcerowsecurity OR EXISTS (SELECT 1 FROM pg_policy WHERE polrelid=c.oid) OR EXISTS (
            SELECT 1 FROM pg_trigger WHERE tgrelid=c.oid AND NOT tgisinternal
        ) OR EXISTS (
            SELECT 1 FROM pg_index WHERE indrelid=c.oid AND NOT indisprimary
        ) OR EXISTS (
            SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype IN ('f', 'u', 'x')
        ) FROM pg_class c WHERE c.oid='distributed_revisions'::regclass
    """)
    )
    if custom:
        raise RuntimeError(
            "history partition migration requires reconciliation of custom RLS, triggers, indexes or constraints"
        )
    owner = connection.scalar(
        sa.text("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='distributed_revisions'::regclass")
    )
    grants = list(
        connection.execute(
            sa.text("""
        SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type, a.is_grantable
        FROM pg_class c, LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
        WHERE c.oid='distributed_revisions'::regclass
    """)
        )
    )
    column_grants = list(
        connection.execute(
            sa.text("""
        SELECT col.attname,
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type, a.is_grantable
        FROM pg_attribute col, LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='distributed_revisions'::regclass AND NOT col.attisdropped
    """)
        )
    )
    suffix = " PARTITION BY HASH (tenant_id)" if partitioned else ""
    connection.execute(
        sa.text(
            "CREATE TABLE distributed_revisions_next (LIKE distributed_revisions INCLUDING DEFAULTS INCLUDING CONSTRAINTS)"
            + suffix
        )
    )
    connection.execute(
        sa.text("ALTER TABLE distributed_revisions_next ADD PRIMARY KEY (cluster_id, tenant_id, version)")
    )
    if partitioned:
        for index in range(32):
            connection.execute(
                sa.text(
                    f"CREATE TABLE distributed_revisions_p{index:02d} PARTITION OF distributed_revisions_next FOR VALUES WITH (MODULUS 32, REMAINDER {index})"
                )
            )
    connection.execute(sa.text("INSERT INTO distributed_revisions_next SELECT * FROM distributed_revisions"))
    connection.execute(sa.text("DROP TABLE distributed_revisions"))
    connection.execute(sa.text("ALTER TABLE distributed_revisions_next RENAME TO distributed_revisions"))
    connection.execute(sa.text("ALTER INDEX distributed_revisions_next_pkey RENAME TO distributed_revisions_pkey"))
    quote = connection.dialect.identifier_preparer.quote
    tables = ["distributed_revisions"]
    if partitioned:
        tables += [f"distributed_revisions_p{index:02d}" for index in range(32)]
    for table in tables:
        connection.execute(sa.text(f"ALTER TABLE {table} OWNER TO {quote(owner)}"))
        # Default grants on child tables could bypass the parent ACL through
        # direct SQL access. Child tables remain accessible only to the owner.
        defaults = list(
            connection.execute(
                sa.text("""
            SELECT DISTINCT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
            FROM pg_class c, LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
            WHERE c.oid=to_regclass(:table)
        """),
                {"table": table},
            )
        )
        for (role,) in defaults:
            target = "PUBLIC" if role == "PUBLIC" else quote(role)
            connection.execute(sa.text(f"REVOKE ALL ON {table} FROM {target}"))
    for role, privilege, grantable in grants:
        if privilege not in {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"}:
            raise RuntimeError("unknown table privilege requires operator reconciliation")
        target = "PUBLIC" if role == "PUBLIC" else quote(role)
        option = " WITH GRANT OPTION" if grantable else ""
        connection.execute(sa.text(f"GRANT {privilege} ON distributed_revisions TO {target}{option}"))
    for column, role, privilege, grantable in column_grants:
        if privilege not in {"SELECT", "INSERT", "UPDATE", "REFERENCES"}:
            raise RuntimeError("unknown column privilege requires operator reconciliation")
        target = "PUBLIC" if role == "PUBLIC" else quote(role)
        option = " WITH GRANT OPTION" if grantable else ""
        connection.execute(sa.text(f"GRANT {privilege} ({quote(column)}) ON distributed_revisions TO {target}{option}"))


def upgrade():
    _revision_markers()
    op.add_column(
        "distributed_tenant_heads", sa.Column("last_job_started_at", sa.Float, nullable=False, server_default="0")
    )
    op.create_index(
        "ix_distributed_heads_dispatch", "distributed_tenant_heads", ["cluster_id", "shard_id", "last_job_started_at"]
    )
    op.create_index(
        "ix_operation_jobs_tenant_status", "operation_jobs", ["root_key", "tenant_id", "status", "created_at", "id"]
    )
    op.create_index(
        "ix_distributed_audit_tenant_time",
        "distributed_request_audit",
        ["cluster_id", "tenant_id", "occurred_at", "event_id"],
    )
    if op.get_bind().dialect.name == "postgresql":
        _rebuild_history(True)


def downgrade():
    _revision_markers()
    if op.get_bind().dialect.name == "postgresql":
        _rebuild_history(False)
    op.drop_index("ix_distributed_audit_tenant_time", table_name="distributed_request_audit")
    op.drop_index("ix_operation_jobs_tenant_status", table_name="operation_jobs")
    op.drop_index("ix_distributed_heads_dispatch", table_name="distributed_tenant_heads")
    op.drop_column("distributed_tenant_heads", "last_job_started_at")
