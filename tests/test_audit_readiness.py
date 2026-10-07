"""Audit readiness API."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.audit_readiness import build_audit_readiness  # noqa: E402
from security_lakehouse.db import vendor_assessments as vendor_assessment_db  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake, _write_jsonl  # noqa: E402


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_build_audit_readiness_fixture(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="auditco", name="Audit Co")
        create_user(session, tenant_id=tenant.id, email="admin@auditco.test", role="admin")
        session.commit()
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)
    assert "audit_score" in data
    assert data["control_tests"]["total"] >= 0
    assert data["workflow_coverage"]["scored"] is False


def test_audit_readiness_api(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="api-audit", name="API Audit")
        user = create_user(session, tenant_id=tenant.id, email="read@api-audit.test", role="read_only")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        session.commit()
    resp = client.get("/api/v1/platform/audit-readiness", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()["data"]
    assert body["workflow_coverage"]["scored"] is False
    assert any(row["id"] == "continuous_controls" for row in body["workflow_coverage"]["checklist"])
    assert all("assessed_controls" in row for row in body["frameworks"])
    assert "vendor_risk" in body
    assert body["vendor_risk"]["total"] == 0


def test_audit_readiness_vendor_gaps(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="vendor-audit", name="Vendor Audit")
        create_user(session, tenant_id=tenant.id, email="admin@vendor-audit.test", role="admin")
        vendor_assessment_db.create_assessment(
            session,
            tenant_id=tenant.id,
            vendor_name="Cloud SaaS",
            template_id="soc2-vendor-standard",
            due_at=datetime.now(UTC) - timedelta(days=3),
        )
        session.commit()
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)
    assert data["vendor_risk"]["total"] == 1
    assert data["vendor_risk"]["overdue"] == 1
    assert any(gap["id"] == "vendor_overdue" for gap in data["gaps"])


def test_audit_readiness_personnel_summary(tmp_path: Path) -> None:
    from security_lakehouse.db import access_reviews as access_reviews_db
    from security_lakehouse.services import access_reviews as access_review_services

    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="personnel-audit", name="Personnel Audit")
        create_user(session, tenant_id=tenant.id, email="admin@personnel-audit.test", role="admin")
        campaign = access_review_services.create_campaign(session, tenant_id=tenant.id, name="Q2 users")
        access_review_services.set_campaign_status(
            session, tenant_id=tenant.id, campaign_id=campaign["id"], status="active"
        )
        access_reviews_db.add_item(
            session,
            tenant_id=tenant.id,
            campaign_id=campaign["id"],
            subject_id="user-1",
            subject_name="Alice",
        )
        session.commit()
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)

    assert data["personnel"]["active_campaigns"] == 1
    assert data["personnel"]["pending_certifications"] == 1
    assert any(gap["id"] == "personnel_idp" for gap in data["gaps"])
    personnel_row = next(row for row in data["workflow_coverage"]["checklist"] if row["id"] == "personnel_tracking")
    assert personnel_row["shipped"] is True


def test_audit_readiness_stale_evidence_gap(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="stale-audit", name="Stale Audit")
        create_user(session, tenant_id=tenant.id, email="admin@stale-audit.test", role="admin")
        session.commit()
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)
    assert data["evidence_freshness"]["stale_count"] > 0
    assert any(gap["id"] == "stale_evidence" for gap in data["gaps"])


def test_audit_readiness_auditor_share_gap(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="share-audit", name="Share Audit")
        create_user(session, tenant_id=tenant.id, email="admin@share-audit.test", role="admin")
        session.commit()
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)
    assert any(gap["id"] == "auditor_share" for gap in data["gaps"])


def test_audit_readiness_api_requires_auth(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = client.get("/api/v1/platform/audit-readiness")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def _readiness(tmp_path: Path, slug: str) -> dict[str, object]:
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug=slug, name=slug)
        create_user(session, tenant_id=tenant.id, email=f"admin@{slug}.test", role="admin")
        session.commit()
        return build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)


def _passing_control(control_id: str, framework: str) -> dict[str, object]:
    return {
        "control_id": control_id,
        "framework": framework,
        "owner": "security",
        "risk_score": 0,
        "status": "pass",
        "title": control_id,
    }


def test_framework_with_one_assessed_control_is_not_ready(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from security_lakehouse.io import read_jsonl

    _seed_lake(tmp_path)
    # Keep the positive score explicit: this test isolates insufficient catalog
    # coverage, not stale evidence whose legacy penalty happened to be small.
    events = read_jsonl(tmp_path / "silver/normalized_events.jsonl")
    for event in events:
        event["event_time"] = datetime.now(UTC).isoformat()
    _write_jsonl(tmp_path / "silver/normalized_events.jsonl", events)
    data = _readiness(tmp_path, "coverage-floor")

    ai_rmf = next(row for row in data["frameworks"] if row["framework"] == "NIST AI RMF")
    assert ai_rmf["score"] == 100
    assert ai_rmf["assessed_controls"] == 1
    assert ai_rmf["total_controls"] > 50
    assert ai_rmf["coverage_pct"] < 50
    assert ai_rmf["ready"] is False
    assert data["posture"]["frameworks_ready"] == 0


def test_framework_ready_when_score_and_coverage_meet_floor(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    _write_jsonl(
        tmp_path / "gold" / "control_posture.jsonl",
        [_passing_control(f"HIPAA-SR-{idx}", "HIPAA Security Rule") for idx in range(3)],
    )
    from datetime import UTC, datetime

    _write_jsonl(
        tmp_path / "silver/normalized_events.jsonl",
        [
            {
                "event_id": f"hipaa-{idx}",
                "control_ids": [f"HIPAA-SR-{idx}"],
                "event_time": datetime.now(UTC).isoformat(),
                "status": "pass",
                "severity": "info",
                "evidence_ref": f"fixture://hipaa-{idx}",
                "asset_id": f"asset-{idx}",
                "source": "fixture",
            }
            for idx in range(3)
        ],
    )
    data = _readiness(tmp_path, "coverage-ready")

    hipaa = next(row for row in data["frameworks"] if row["framework"] == "HIPAA Security Rule")
    assert hipaa["assessed_controls"] == 3
    assert hipaa["total_controls"] == 6
    assert hipaa["coverage_pct"] == 50.0
    assert hipaa["ready"] is True
    assert data["posture"]["frameworks_ready"] == 1


def test_product_capabilities_do_not_move_audit_score(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse import audit_readiness

    _seed_lake(tmp_path)
    baseline = _readiness(tmp_path, "caps-a")["audit_score"]
    monkeypatch.setattr(
        audit_readiness,
        "_workflow_checklist",
        lambda **_kwargs: [{"id": "x", "label": "x", "shipped": False, "note": ""}],
    )
    assert _readiness(tmp_path, "caps-b")["audit_score"] == baseline


def test_audit_score_is_evidence_based_only(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    data = _readiness(tmp_path, "score-formula")

    posture = data["posture"]["score"]
    tests = data["control_tests"]
    pass_rate = 100 * tests["passing"] / tests["total"] if tests["total"] else 0
    ready_rate = (
        100 * data["posture"]["frameworks_ready"] / data["posture"]["frameworks_total"]
        if data["posture"]["frameworks_total"]
        else 0
    )
    assert data["audit_score"] == round((posture * 0.4 + pass_rate * 0.3 + ready_rate * 0.2) / 0.9)


def test_assessment_score_is_rounded_like_the_overview(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The audit room and Overview show one assessment score: round, never truncate."""
    from security_lakehouse import audit_readiness

    _seed_lake(tmp_path)
    real = audit_readiness.build_current_posture

    def _posture(lake: Path) -> dict[str, object]:
        payload = real(lake)
        payload["posture"] = {**(payload.get("posture") or {}), "score": 6.8}
        return payload

    monkeypatch.setattr(audit_readiness, "build_current_posture", _posture)
    assert _readiness(tmp_path, "rounding")["posture"]["score"] == 7


def test_connector_gap_suppressed_when_evidence_sources_exist(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    data = _readiness(tmp_path, "sources-present")

    assert data["connectors"]["enabled"] == 0
    assert data["connectors"]["evidence_sources"] > 0
    assert not any(gap["id"] == "connectors" for gap in data["gaps"])


def test_connector_gap_fires_when_no_evidence_and_no_connectors(tmp_path: Path) -> None:
    (tmp_path / "console.html").write_bytes(b"<!doctype html>")
    data = _readiness(tmp_path, "empty-lake")

    assert data["connectors"]["evidence_sources"] == 0
    assert any(gap["id"] == "connectors" for gap in data["gaps"])


def test_framework_outside_catalog_has_unknown_coverage_and_is_not_ready() -> None:
    from security_lakehouse.audit_readiness import _framework_readiness

    (row,) = _framework_readiness([{"framework": "Custom Internal Standard", "score": 100, "control_count": 4}])
    assert row["coverage_pct"] is None
    assert row["total_controls"] is None
    assert row["ready"] is False


def test_empty_lake_scores_zero_audit_readiness(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="emptyco", name="Empty Co")
        session.commit()
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)
    assert data["posture"]["score"] == 0
    assert data["audit_score"] == 0
    assert data["state"] == "needs_work"
