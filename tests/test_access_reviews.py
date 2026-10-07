"""Access-review campaigns + items: migration, repository, tenant isolation.

The data-layer foundation for the access-review pillar (periodic user-access
certification). API + evidence-seeding land in follow-up PRs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from sqlalchemy import inspect  # noqa: E402

from security_lakehouse.db import access_reviews as ar  # noqa: E402
from security_lakehouse.db import migrate  # noqa: E402
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope  # noqa: E402
from security_lakehouse.db.repository import create_tenant  # noqa: E402


def _session_scope(tmp_path: Path):
    migrate.upgrade(tmp_path)
    factory = session_factory(create_engine_for(tmp_path))
    return session_scope(factory)


# --- migration ---------------------------------------------------------------


def test_migration_creates_access_review_tables(tmp_path: Path) -> None:
    migrate.upgrade(tmp_path)
    inspector = inspect(create_engine_for(tmp_path))
    names = set(inspector.get_table_names())
    assert {"access_review_campaigns", "access_review_items"} <= names
    indexes = {ix["name"] for ix in inspector.get_indexes("access_review_items")}
    assert "ix_access_review_items_campaign_decision" in indexes


# --- repository lifecycle ----------------------------------------------------


def test_campaign_and_item_lifecycle(tmp_path: Path) -> None:
    with _session_scope(tmp_path) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        campaign = ar.create_campaign(
            session, tenant_id=tenant.id, name="Q3 access review", scope="okta-identity", created_by="alice"
        )
        assert campaign.status == "draft"

        ar.set_campaign_status(session, tenant_id=tenant.id, campaign_id=campaign.id, status="active")
        item = ar.add_item(
            session,
            tenant_id=tenant.id,
            campaign_id=campaign.id,
            subject_id="okta:user:1",
            subject_name="Dana Dev",
            source="okta",
            access_summary="admin on prod-app",
        )
        assert item.decision == "pending"
        assert item.decided_at is None

        decided = ar.record_decision(
            session, tenant_id=tenant.id, item_id=item.id, decision="revoked", reviewer="bob", note="left team"
        )
        assert decided is not None
        assert decided.decision == "revoked"
        assert decided.decided_at is not None

        progress = ar.campaign_progress(session, tenant_id=tenant.id, campaign_id=campaign.id)
        assert progress["total"] == 1
        assert progress["revoked"] == 1
        assert progress["reviewed"] == 1
        assert progress["pending"] == 0

        completed = ar.set_campaign_status(session, tenant_id=tenant.id, campaign_id=campaign.id, status="completed")
        assert completed is not None
        assert completed.completed_at is not None


def test_invalid_status_and_decision_rejected(tmp_path: Path) -> None:
    with _session_scope(tmp_path) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        campaign = ar.create_campaign(session, tenant_id=tenant.id, name="review")
        item = ar.add_item(session, tenant_id=tenant.id, campaign_id=campaign.id, subject_id="okta:user:1")
        with pytest.raises(ValueError, match="status"):
            ar.set_campaign_status(session, tenant_id=tenant.id, campaign_id=campaign.id, status="bogus")
        with pytest.raises(ValueError, match="decision"):
            ar.record_decision(session, tenant_id=tenant.id, item_id=item.id, decision="approve")
        with pytest.raises(ValueError, match="name"):
            ar.create_campaign(session, tenant_id=tenant.id, name="  ")


def test_tenant_isolation(tmp_path: Path) -> None:
    with _session_scope(tmp_path) as session:
        acme = create_tenant(session, slug="acme", name="Acme")
        globex = create_tenant(session, slug="globex", name="Globex")
        campaign = ar.create_campaign(session, tenant_id=acme.id, name="acme review")
        # Another tenant can neither read nor add to it.
        assert ar.get_campaign(session, tenant_id=globex.id, campaign_id=campaign.id) is None
        assert ar.list_campaigns(session, tenant_id=globex.id) == []
        with pytest.raises(ValueError, match="not found"):
            ar.add_item(session, tenant_id=globex.id, campaign_id=campaign.id, subject_id="x")


def test_list_pagination_and_filter(tmp_path: Path) -> None:
    with _session_scope(tmp_path) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        campaign = ar.create_campaign(session, tenant_id=tenant.id, name="review")
        for i in range(5):
            ar.add_item(session, tenant_id=tenant.id, campaign_id=campaign.id, subject_id=f"okta:user:{i}")
        # Page the items.
        page = ar.list_items(session, tenant_id=tenant.id, campaign_id=campaign.id, limit=2, offset=0)
        assert len(page) == 2
        # Filter by decision.
        first = ar.list_items(session, tenant_id=tenant.id, campaign_id=campaign.id)[0]
        ar.set_campaign_status(session, tenant_id=tenant.id, campaign_id=campaign.id, status="active")
        ar.record_decision(session, tenant_id=tenant.id, item_id=first.id, decision="certified", reviewer="reviewer")
        certified = ar.list_items(session, tenant_id=tenant.id, campaign_id=campaign.id, decision="certified")
        assert len(certified) == 1
