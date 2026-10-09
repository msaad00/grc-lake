"""Seed access-review items from the lake's identity evidence."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from security_lakehouse.db import migrate
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.services import access_reviews as ars


def _ev(asset_id: str, asset_type: str, source: str, event_type: str, status: str) -> dict:
    # A minimally-valid silver row (control_ids/severity are read by the posture
    # engine that create_app renders at startup).
    return {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "source": source,
        "event_type": event_type,
        "status": status,
        "severity": "low",
        "control_ids": [],
    }


_EVENTS = [
    _ev("okta:user:1", "identity_account", "okta", "user_access", "observed"),
    _ev("okta:user:1", "identity_account", "okta", "mfa_enrollment", "open"),
    _ev("aws:iam:user/dana", "identity_account", "aws", "access_key_hygiene", "open"),
    # Non-identity rows are ignored.
    _ev("aws:account:1", "account_config", "aws", "password_policy", "open"),
]


def _write_silver(lake: Path, events: list[dict]) -> None:
    (lake / "silver").mkdir(parents=True, exist_ok=True)
    (lake / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )


# --- pure reader -------------------------------------------------------------


def test_identity_subjects_dedupe_and_summarize(tmp_path: Path) -> None:
    _write_silver(tmp_path, _EVENTS)
    subjects = ars.identity_subjects_from_silver(tmp_path)
    by_id = {s["subject_id"]: s for s in subjects}
    assert set(by_id) == {"okta:user:1", "aws:iam:user/dana"}  # account_config dropped
    # okta:user:1 collapses its two signals into one subject, name from the tail.
    assert by_id["okta:user:1"]["subject_name"] == "1"
    assert "mfa_enrollment" in by_id["okta:user:1"]["access_summary"]
    assert "1 open finding" in by_id["okta:user:1"]["access_summary"]
    assert by_id["aws:iam:user/dana"]["subject_name"] == "dana"


def test_scope_filters_by_source(tmp_path: Path) -> None:
    _write_silver(tmp_path, _EVENTS)
    okta_only = ars.identity_subjects_from_silver(tmp_path, scope="okta-identity")
    assert {s["subject_id"] for s in okta_only} == {"okta:user:1"}


def test_missing_silver_is_empty(tmp_path: Path) -> None:
    assert ars.identity_subjects_from_silver(tmp_path) == []


# --- service seeding (idempotent) --------------------------------------------


def test_seed_campaign_is_idempotent(tmp_path: Path) -> None:
    _write_silver(tmp_path, _EVENTS)
    migrate.upgrade(tmp_path)
    factory = session_factory(create_engine_for(tmp_path))
    with session_scope(factory) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        campaign = ars.create_campaign(session, tenant.id, name="review", scope="all")
        cid = campaign["id"]

        first = ars.seed_campaign_from_evidence(session, tmp_path, tenant.id, cid)
        assert first == {"added": 2, "skipped": 0, "candidates": 2}
        # Re-seeding the same evidence adds nothing.
        again = ars.seed_campaign_from_evidence(session, tmp_path, tenant.id, cid)
        assert again == {"added": 0, "skipped": 2, "candidates": 2}

        items = ars.list_items(session, tenant.id, cid)
        assert {i["subject_id"] for i in items} == {"okta:user:1", "aws:iam:user/dana"}


# --- API endpoint ------------------------------------------------------------


def test_seed_endpoint(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from security_lakehouse.db.repository import create_api_key, create_user
    from security_lakehouse.server_app import create_app
    from test_api_v1 import _seed_lake

    _seed_lake(tmp_path)
    _write_silver(tmp_path, _EVENTS)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="sec@acme.test", role="security_admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}

    cid = client.post("/api/v1/access-reviews", json={"name": "review"}, headers=headers).json()["data"]["id"]
    seeded = client.post(f"/api/v1/access-reviews/{cid}/seed", headers=headers)
    assert seeded.status_code == HTTPStatus.OK
    assert seeded.json()["data"]["added"] == 2
    items = client.get(f"/api/v1/access-reviews/{cid}/items", headers=headers).json()["data"]
    assert len(items) == 2
