"""Access-review evidence has one durable decision under an active campaign."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy.orm import Session

from security_lakehouse.db import access_reviews as ar
from security_lakehouse.db import migrate
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import create_tenant, create_user
from test_migration_portability import migration_url as _migration_url_fixture

migration_url = _migration_url_fixture


@pytest.fixture
def review(tmp_path, migration_url):
    from alembic import command

    command.upgrade(migrate._config(migration_url), "head")
    engine = create_engine_for(tmp_path, url=migration_url)
    factory = session_factory(engine)
    with session_scope(factory) as session:
        tenant = create_tenant(session, slug="review", name="Review")
        user = create_user(session, tenant_id=tenant.id, email="reviewer@example.test", role="security_admin")
        user.scim_external_id = "provider-user-123"
        campaign = ar.create_campaign(session, tenant_id=tenant.id, name="Review")
        item = ar.add_item(session, tenant_id=tenant.id, campaign_id=campaign.id, subject_id="other-user")
        ar.set_campaign_status(session, tenant_id=tenant.id, campaign_id=campaign.id, status="active")
        ids = tenant.id, user.id, campaign.id, item.id
    yield factory, ids
    engine.dispose()


@pytest.mark.parametrize("alias", ["id", "email", "mailto", "external"])
def test_registered_identity_alias_cannot_self_certify(review, alias):
    factory, (tenant, user, campaign, _) = review
    subject = {
        "id": user,
        "email": "REVIEWER@example.test",
        "mailto": "mailto:reviewer@example.test",
        "external": "provider-user-123",
    }[alias]
    with session_scope(factory) as session:
        item = ar.add_item(session, tenant_id=tenant, campaign_id=campaign, subject_id=subject)
        with pytest.raises(ValueError, match="independent"):
            ar.record_decision(
                session, tenant_id=tenant, item_id=item.id, decision="certified", reviewer="reviewer@example.test"
            )


@pytest.mark.parametrize("status", ["completed", "cancelled"])
@pytest.mark.parametrize("operation", ["add", "decide", "reopen"])
def test_terminal_campaign_cannot_be_mutated(review, status, operation):
    factory, (tenant, _, campaign, item) = review
    with session_scope(factory) as session:
        ar.record_decision(
            session, tenant_id=tenant, item_id=item, decision="certified", reviewer="reviewer@example.test"
        )
        ar.set_campaign_status(session, tenant_id=tenant, campaign_id=campaign, status=status)
        with pytest.raises(ValueError, match="campaign"):
            if operation == "add":
                ar.add_item(session, tenant_id=tenant, campaign_id=campaign, subject_id="new-user")
            elif operation == "decide":
                ar.record_decision(
                    session, tenant_id=tenant, item_id=item, decision="pending", reviewer="reviewer@example.test"
                )
            else:
                ar.set_campaign_status(session, tenant_id=tenant, campaign_id=campaign, status="draft")


def test_completion_requires_nonempty_fully_reviewed_population(review):
    factory, (tenant, _, campaign, _) = review
    with session_scope(factory) as session:
        with pytest.raises(ValueError, match="pending"):
            ar.set_campaign_status(session, tenant_id=tenant, campaign_id=campaign, status="completed")
        empty = ar.create_campaign(session, tenant_id=tenant, name="Empty")
        ar.set_campaign_status(session, tenant_id=tenant, campaign_id=empty.id, status="active")
        with pytest.raises(ValueError, match="empty"):
            ar.set_campaign_status(session, tenant_id=tenant, campaign_id=empty.id, status="completed")


def test_repeated_completion_preserves_original_evidence_time(review):
    factory, (tenant, _, campaign, item) = review
    now = datetime.now(UTC)
    with session_scope(factory) as session:
        ar.record_decision(
            session, tenant_id=tenant, item_id=item, decision="certified", reviewer="reviewer@example.test"
        )
        ar.set_campaign_status(session, tenant_id=tenant, campaign_id=campaign, status="completed", now=now)
        repeated = ar.set_campaign_status(
            session, tenant_id=tenant, campaign_id=campaign, status="completed", now=now + timedelta(days=500)
        )
        from security_lakehouse.db.models import _as_aware

        assert _as_aware(repeated.completed_at) == now


def test_decisions_require_active_campaign_and_named_reviewer(review):
    factory, (tenant, _, _, item) = review
    with session_scope(factory) as session:
        with pytest.raises(ValueError, match="reviewer"):
            ar.record_decision(session, tenant_id=tenant, item_id=item, decision="certified")
        draft = ar.create_campaign(session, tenant_id=tenant, name="Draft")
        draft_item = ar.add_item(session, tenant_id=tenant, campaign_id=draft.id, subject_id="another")
        with pytest.raises(ValueError, match="active"):
            ar.record_decision(
                session, tenant_id=tenant, item_id=draft_item.id, decision="certified", reviewer="reviewer@example.test"
            )


def test_concurrent_decisions_have_one_winner_and_cannot_be_reset(review):
    factory, (tenant, _, _, item) = review
    barrier = Barrier(4)

    def decide(index):
        with Session(factory.kw["bind"]) as session:
            barrier.wait(timeout=10)
            try:
                row = ar.record_decision(
                    session,
                    tenant_id=tenant,
                    item_id=item,
                    decision="certified" if index % 2 else "revoked",
                    reviewer=f"reviewer-{index}",
                )
                session.commit()
                return row.reviewer
            except ValueError:
                session.rollback()
                return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(decide, range(4)))
    winners = [value for value in results if value]
    assert len(winners) == 1
    with session_scope(factory) as session:
        stored = ar.get_item(session, tenant_id=tenant, item_id=item)
        assert stored.reviewer == winners[0]
        original = stored.decided_at
        repeated = ar.record_decision(
            session, tenant_id=tenant, item_id=item, decision=stored.decision, reviewer=stored.reviewer
        )
        assert repeated.decided_at == original
        with pytest.raises(ValueError, match="decision"):
            ar.record_decision(session, tenant_id=tenant, item_id=item, decision="pending", reviewer=stored.reviewer)


def test_completion_racing_membership_never_seals_pending_items(review):
    factory, (tenant, _, campaign, item) = review
    with session_scope(factory) as session:
        ar.record_decision(session, tenant_id=tenant, item_id=item, decision="certified", reviewer="reviewer")
    barrier = Barrier(2)

    def mutate(action):
        with factory() as session:
            barrier.wait(timeout=10)
            try:
                if action == "complete":
                    ar.set_campaign_status(session, tenant_id=tenant, campaign_id=campaign, status="completed")
                else:
                    ar.add_item(session, tenant_id=tenant, campaign_id=campaign, subject_id="late-subject")
                session.commit()
                return True
            except ValueError:
                session.rollback()
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(mutate, ["complete", "add"])) == 1
    with session_scope(factory) as session:
        stored = ar.get_campaign(session, tenant_id=tenant, campaign_id=campaign)
        progress = ar.campaign_progress(session, tenant_id=tenant, campaign_id=campaign)
        assert stored.status != "completed" or progress["pending"] == 0


def test_reviewer_alias_lookup_never_uses_another_tenants_binding(review):
    factory, (tenant, _, campaign, _) = review
    with session_scope(factory) as session:
        other = create_tenant(session, slug="other", name="Other")
        user = create_user(session, tenant_id=other.id, email="reviewer@example.test", role="security_admin")
        user.scim_external_id = "unrelated-subject"
        item = ar.add_item(session, tenant_id=tenant, campaign_id=campaign, subject_id="unrelated-subject")
        assert (
            ar.record_decision(
                session, tenant_id=tenant, item_id=item.id, decision="certified", reviewer="reviewer@example.test"
            ).decision
            == "certified"
        )
        assert (
            ar.record_decision(
                session, tenant_id=other.id, item_id=item.id, decision="revoked", reviewer="reviewer@example.test"
            )
            is None
        )
