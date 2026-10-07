"""Migration defaults and rollback retain actual authority evidence."""

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from security_lakehouse.db.migrate import _config
from security_lakehouse.db.models import PolicyDocument, RemediationTask
from security_lakehouse.db.repository import create_tenant
from test_migration_portability import migration_url as _migration_url_fixture

migration_url = _migration_url_fixture


def test_policy_acknowledgment_database_default_is_portable(migration_url):
    cfg = _config(migration_url)
    command.upgrade(cfg, "head")
    engine = create_engine(migration_url)
    try:
        with Session(engine) as session:
            tenant = create_tenant(session, slug="policy", name="Policy")
            document = PolicyDocument(tenant_id=tenant.id, template_id="fixture", title="Fixture")
            session.add(document)
            session.flush()
            session.execute(
                text(
                    "INSERT INTO policy_acknowledgments (id, tenant_id, policy_document_id, user_email) VALUES ('ack', :tenant, :document, 'reader@example.test')"
                ),
                {"tenant": tenant.id, "document": document.id},
            )
            session.commit()
            assert (
                session.execute(
                    text("SELECT acknowledged_at FROM policy_acknowledgments WHERE id = 'ack'")
                ).scalar_one()
                is not None
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "revision,field",
    [("0025_operation_jobs", "authority_history"), ("0020_saml_assertion_replays", "verification_history")],
)
def test_downgrade_refuses_to_erase_retained_review_evidence(migration_url, revision, field):
    cfg = _config(migration_url)
    command.upgrade(cfg, "head")
    engine = create_engine(migration_url)
    try:
        with Session(engine) as session:
            tenant = create_tenant(session, slug="review", name="Review")
            task = RemediationTask(tenant_id=tenant.id, title="Retained task", **{field: '["review evidence"]'})
            session.add(task)
            session.commit()
        with pytest.raises(RuntimeError, match="retain|evidence|provenance"):
            command.downgrade(cfg, revision)
        with engine.connect() as connection:
            assert (
                connection.execute(text(f"SELECT {field} FROM remediation_tasks")).scalar_one() == '["review evidence"]'
            )
    finally:
        engine.dispose()
