"""Access-review control coverage: map completed campaigns to access controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from security_lakehouse.db import access_reviews as ar
from security_lakehouse.db import migrate
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.services import access_reviews as ars

CONTROL = "SOC2-CC6.1"  # exists in the shipped control catalog


def _completed_campaign_with_decisions(session, tenant_id: str) -> None:
    campaign = ars.create_campaign(session, tenant_id, name="Q3 access", control_id=CONTROL)
    cid = campaign["id"]
    ars.set_campaign_status(session, tenant_id, cid, status="active")
    for subject, decision in (("okta:user:1", "certified"), ("okta:user:2", "revoked")):
        item = ar.add_item(session, tenant_id=tenant_id, campaign_id=cid, subject_id=subject)
        ar.record_decision(session, tenant_id=tenant_id, item_id=item.id, decision=decision, reviewer="reviewer")
    ars.set_campaign_status(session, tenant_id, cid, status="completed")


def _scope(tmp_path: Path):
    migrate.upgrade(tmp_path)
    return session_scope(session_factory(create_engine_for(tmp_path)))


def test_coverage_maps_to_catalog_and_marks_current(tmp_path: Path) -> None:
    with _scope(tmp_path) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        _completed_campaign_with_decisions(session, tenant.id)

        coverage = ars.control_coverage(session, tenant.id)
        assert len(coverage) == 1
        row = coverage[0]
        assert row["control_id"] == CONTROL
        assert row["framework"] == "SOC 2"  # joined from the catalog
        assert row["title"]
        assert row["completed_campaigns"] == 1
        assert row["current"] is True
        assert row["decisions"]["certified"] == 1
        assert row["decisions"]["revoked"] == 1


def test_coverage_goes_stale_past_the_freshness_window(tmp_path: Path) -> None:
    with _scope(tmp_path) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        _completed_campaign_with_decisions(session, tenant.id)
        # Evaluate well past the freshness window.
        future = datetime.now(UTC) + timedelta(days=ars.COVERAGE_FRESHNESS_DAYS + 30)
        coverage = ars.control_coverage(session, tenant.id, now=future)
        assert coverage[0]["current"] is False


def test_incomplete_campaign_is_not_current(tmp_path: Path) -> None:
    with _scope(tmp_path) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        ars.create_campaign(session, tenant.id, name="draft", control_id=CONTROL)
        row = ars.control_coverage(session, tenant.id)[0]
        assert row["campaigns"] == 1
        assert row["completed_campaigns"] == 0
        assert row["current"] is False


def test_coverage_endpoint(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from security_lakehouse.db.repository import create_api_key, create_user
    from security_lakehouse.server_app import create_app
    from test_api_v1 import _seed_lake

    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="sec@acme.test", role="security_admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        _completed_campaign_with_decisions(session, tenant.id)
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/access-reviews/coverage", headers=headers)
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert body["meta"]["count"] == 1
    assert body["data"][0]["control_id"] == CONTROL
    # The static /coverage segment is not swallowed by the /{campaign_id} route.
    assert client.get("/api/v1/access-reviews/coverage", headers=headers).status_code != HTTPStatus.NOT_FOUND
