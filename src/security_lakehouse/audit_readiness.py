"""Headless-first audit readiness aggregation for console and API."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse import trust_share
from security_lakehouse.assessment import _iter_snapshots, build_current_posture
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.db import agent_runs as agent_runs_db
from security_lakehouse.db import policy_acknowledgments as policy_acknowledgment_db
from security_lakehouse.db import remediation
from security_lakehouse.db import vendor_assessments as vendor_assessment_db
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.io import read_jsonl
from security_lakehouse.services import access_reviews as access_review_services


def _workflow_checklist(*, posture_score: int, framework_total: int) -> list[dict[str, Any]]:
    """Product capabilities available to the org; informational only, never part of the audit score."""
    return [
        {
            "id": "continuous_controls",
            "label": "Continuous control tests",
            "shipped": True,
            "note": "Deterministic tests over live connector evidence",
        },
        {
            "id": "framework_mapping",
            "label": "SOC 2 / ISO / NIST framework packs",
            "shipped": framework_total > 0,
            "note": f"{framework_total} registered framework(s)",
        },
        {
            "id": "evidence_collection",
            "label": "Automated evidence collection",
            "shipped": True,
            "note": "Read-only connectors + lake pipeline",
        },
        {
            "id": "auditor_portal",
            "label": "Auditor read-only portal",
            "shipped": True,
            "note": "Trust-center shares + auditor role redaction",
        },
        {
            "id": "access_reviews",
            "label": "Access review campaigns",
            "shipped": True,
            "note": "Certify / revoke / flag with audit trail",
        },
        {
            "id": "evidence_requests",
            "label": "Evidence requests to owners",
            "shipped": True,
            "note": "Remediation evidence-request workflow",
        },
        {
            "id": "vendor_diligence",
            "label": "Third-party vendor diligence",
            "shipped": True,
            "note": "Questionnaire templates + scored assessments (SOC 2 CC9 pattern)",
        },
        {
            "id": "policy_library",
            "label": "Policy template library",
            "shipped": True,
            "note": "Bundled templates + adopt/publish MVP",
        },
        {
            "id": "policy_attestation",
            "label": "Employee policy acknowledgment",
            "shipped": True,
            "note": "Record attestations on published policies for audit evidence",
        },
        {
            "id": "point_in_time",
            "label": "Point-in-time audit snapshot",
            "shipped": posture_score > 0,
            "note": "Assessment snapshots with hash chain",
        },
        {
            "id": "evidence_freshness_sla",
            "label": "Evidence freshness SLA enforcement",
            "shipped": True,
            "note": "Per-connector SLOs with stale/expired/missing workflows",
        },
        {
            "id": "headless_api",
            "label": "Headless API / MCP / CI gates",
            "shipped": True,
            "note": "Same /api/v1 contract for agents and console",
        },
        {
            "id": "poam_sprs",
            "label": "POA&M + SPRS (CMMC / gov programs)",
            "shipped": True,
            "note": "Auto-sync POA&M from posture; SPRS score from NIST SP 800-171 Rev 2 gaps",
        },
        {
            "id": "personnel_tracking",
            "label": "Personnel / HR onboarding",
            "shipped": True,
            "note": "IdP connectors + access-review campaigns (native HRIS roadmap)",
        },
        {
            "id": "auditor_marketplace",
            "label": "Auditor marketplace",
            "shipped": False,
            "note": "Bring your own auditor; trust shares for evidence",
        },
    ]


IDENTITY_CONNECTOR_IDS = frozenset({"okta-identity", "okta-system-log"})

FRAMEWORK_READY_SCORE = 85
FRAMEWORK_READY_MIN_COVERAGE_PCT = 50.0


def _framework_readiness(frameworks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A framework is ready only when its score clears the bar AND enough of its catalog was assessed."""
    catalog_totals = Counter(
        str(control.get("framework") or "")
        for control in load_control_catalog().values()
        if str(control.get("lifecycle_status") or "active") == "active"
    )
    out: list[dict[str, Any]] = []
    for row in frameworks:
        name = str(row.get("framework") or "")
        score = float(row.get("score") or 0)
        assessed = int(row.get("control_count") or 0)
        catalog_total = catalog_totals.get(name, 0)
        # Outside the catalog the denominator is unknown; never infer full coverage.
        total = max(catalog_total, assessed) if catalog_total else None
        coverage_pct = round(100 * assessed / total, 1) if total else None
        out.append(
            {
                "framework": name,
                "score": score,
                "assessed_controls": assessed,
                "total_controls": total,
                "coverage_pct": coverage_pct,
                "ready": coverage_pct is not None
                and score >= FRAMEWORK_READY_SCORE
                and coverage_pct >= FRAMEWORK_READY_MIN_COVERAGE_PCT,
            }
        )
    return out


def _personnel_summary(
    session: Session,
    *,
    tenant_id: str,
    connectors: list[dict[str, Any]],
) -> dict[str, Any]:
    """IdP + access-review rollup — managed-GRC personnel tracking workaround."""
    from security_lakehouse.db import access_reviews as access_reviews_db

    campaigns = access_review_services.list_campaigns(session, tenant_id=tenant_id, limit=100)
    active = [row for row in campaigns if row.get("status") == "active"]
    completed = [row for row in campaigns if row.get("status") == "completed"]

    pending_certifications = 0
    certified = 0
    for row in active:
        progress = access_reviews_db.campaign_progress(session, tenant_id=tenant_id, campaign_id=str(row["id"]))
        pending_certifications += int(progress.get("pending") or 0)
        certified += int(progress.get("certified") or 0)

    identity_connectors = sum(
        1
        for row in connectors
        if str(row.get("connector_id") or "") in IDENTITY_CONNECTOR_IDS and row.get("state") == "enabled"
    )

    return {
        "identity_connectors": identity_connectors,
        "active_campaigns": len(active),
        "completed_campaigns": len(completed),
        "pending_certifications": pending_certifications,
        "certified": certified,
    }


def _vendor_risk_summary(session: Session, *, tenant_id: str) -> dict[str, Any]:
    """Roll up vendor diligence status for audit-room parity with managed GRC SaaS."""
    now = datetime.now(UTC)
    rows = vendor_assessment_db.list_assessments(session, tenant_id=tenant_id, limit=500)
    open_statuses = {"draft", "in_review"}
    open_rows = [row for row in rows if row.status in open_statuses]
    overdue = [
        row
        for row in open_rows
        if row.due_at is not None and (row.due_at if row.due_at.tzinfo else row.due_at.replace(tzinfo=UTC)) < now
    ]
    completed = [row for row in rows if row.status == "completed"]
    high_risk_open = [
        row
        for row in open_rows
        if str(row.risk_level or "").lower() in {"high", "critical"} or (row.score is not None and row.score < 70)
    ]
    return {
        "total": len(rows),
        "open": len(open_rows),
        "overdue": len(overdue),
        "completed": len(completed),
        "high_risk_open": len(high_risk_open),
    }


def build_audit_readiness(
    *,
    lake: Path,
    session: Session,
    tenant_id: str,
) -> dict[str, Any]:
    """Aggregate audit-room metrics for human console and headless API consumers."""
    posture_payload = build_current_posture(lake)
    posture = posture_payload.get("posture") or {}
    frameworks = posture_payload.get("frameworks") or []
    violations = posture_payload.get("violations") or []
    evidence_freshness = posture_payload.get("evidence_freshness") or {}
    stale_evidence_count = int(evidence_freshness.get("stale_count") or 0)
    control_tests = read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True)

    passing = sum(1 for row in control_tests if str(row.get("result", "")).lower() in {"pass", "ready"})
    failing = sum(1 for row in control_tests if str(row.get("result", "")).lower() == "fail")
    total_tests = len(control_tests)

    framework_total = len(frameworks)
    framework_readiness = _framework_readiness(frameworks)
    frameworks_ready = sum(1 for row in framework_readiness if row["ready"])
    posture_score = round(float(posture.get("score") or 0))

    open_evidence = remediation.list_evidence_requests(session, tenant_id=tenant_id, status="open", limit=500)
    campaigns = access_review_services.list_campaigns(session, tenant_id=tenant_id, limit=50)
    active_reviews = [row for row in campaigns if row.get("status") == "active"]
    completed_reviews = [row for row in campaigns if row.get("status") == "completed"]

    ingestion = build_ingestion_status(lake)
    summary = ingestion.get("summary") or {}
    connector_rows = ingestion.get("connectors") or []
    evidence_sources = sum(1 for row in ingestion.get("sources") or [] if int(row.get("evidence_count") or 0) > 0)
    active_shares = [share for share in trust_share.list_shares(lake) if not share.get("expired")]
    auditor_shares = [share for share in active_shares if str(share.get("role") or "") == "auditor"]

    agent_runs = agent_runs_db.list_agent_runs(session, tenant_id=tenant_id, limit=20)
    pending_decisions = sum(
        1
        for row in agent_runs
        for decision in agent_runs_db.agent_run_decisions(row)
        if decision.get("status") == "proposed"
    )

    snapshot_rows = _iter_snapshots(lake)
    latest_snapshot = snapshot_rows[-1][1] if snapshot_rows else None

    gaps: list[dict[str, str]] = []
    if int(summary.get("enabled_connectors") or 0) == 0 and evidence_sources == 0:
        gaps.append(
            {"id": "connectors", "label": "Connect at least one evidence source", "href": "/console/connectors"}
        )
    if failing > 0:
        gaps.append(
            {"id": "failing_controls", "label": f"{failing} control test(s) failing", "href": "/console/controls"}
        )
    if open_evidence:
        gaps.append(
            {
                "id": "evidence_requests",
                "label": f"{len(open_evidence)} open evidence request(s)",
                "href": "/console/remediation",
            }
        )
    if not active_reviews:
        gaps.append(
            {
                "id": "access_review",
                "label": "No active access review campaign",
                "href": "/console/access-reviews",
            }
        )
    if stale_evidence_count > 0:
        gaps.append(
            {
                "id": "stale_evidence",
                "label": f"{stale_evidence_count} stale/expired/missing evidence item(s)",
                "href": "/console/evidence?freshness=stale",
            }
        )
    if not auditor_shares:
        gaps.append(
            {
                "id": "auditor_share",
                "label": "Create an auditor trust-center share",
                "href": "/console/trust-center",
            }
        )

    vendor_risk = _vendor_risk_summary(session, tenant_id=tenant_id)
    personnel = _personnel_summary(session, tenant_id=tenant_id, connectors=connector_rows)
    if personnel["identity_connectors"] == 0:
        gaps.append(
            {
                "id": "personnel_idp",
                "label": "Connect an identity provider for personnel evidence",
                "href": "/console/connectors/?connect=okta-identity",
            }
        )
    elif personnel["active_campaigns"] == 0:
        gaps.append(
            {
                "id": "personnel_access_review",
                "label": "Start an access review campaign for personnel certification",
                "href": "/console/access-reviews",
            }
        )
    elif personnel["pending_certifications"] > 0:
        gaps.append(
            {
                "id": "personnel_pending",
                "label": f"{personnel['pending_certifications']} access certification(s) pending review",
                "href": "/console/access-reviews",
            }
        )

    if vendor_risk["total"] == 0:
        gaps.append(
            {
                "id": "vendor_diligence",
                "label": "Record vendor diligence for critical third parties",
                "href": "/console/vendor-risk",
            }
        )
    elif vendor_risk["overdue"] > 0:
        gaps.append(
            {
                "id": "vendor_overdue",
                "label": f"{vendor_risk['overdue']} overdue vendor assessment(s)",
                "href": "/console/vendor-risk",
            }
        )
    elif vendor_risk["open"] > 0:
        gaps.append(
            {
                "id": "vendor_incomplete",
                "label": f"{vendor_risk['open']} vendor assessment(s) pending completion",
                "href": "/console/vendor-risk",
            }
        )

    policy_attestation = policy_acknowledgment_db.attestation_summary(session, tenant_id=tenant_id)
    if policy_attestation["published"] > 0 and policy_attestation["unattested"] > 0:
        gaps.append(
            {
                "id": "policy_attestation",
                "label": (f"{policy_attestation['unattested']} published polic(ies) without employee acknowledgment"),
                "href": "/console/policies",
            }
        )

    checklist = _workflow_checklist(posture_score=posture_score, framework_total=framework_total)
    coverage_score = round(100 * sum(1 for row in checklist if row["shipped"]) / max(len(checklist), 1))

    # Scored only on the org's own evidence, controls, and frameworks, never on product features.
    audit_score = round(
        (
            posture_score * 0.4
            + (100 * passing / total_tests if total_tests else 0) * 0.3
            + (100 * frameworks_ready / framework_total if framework_total else 0) * 0.2
        )
        / 0.9
    )

    state = "audit_ready" if audit_score >= 85 and not gaps else ("on_track" if audit_score >= 60 else "needs_work")

    return {
        "state": state,
        "audit_score": audit_score,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "posture": {
            "score": posture_score,
            "open_violations": len(violations),
            "frameworks_ready": frameworks_ready,
            "frameworks_total": framework_total,
        },
        "control_tests": {
            "passing": passing,
            "failing": failing,
            "total": total_tests,
        },
        "evidence_freshness": {
            "total": int(evidence_freshness.get("count") or 0),
            "stale_count": stale_evidence_count,
            "fresh_rate_pct": round(
                100
                * (int(evidence_freshness.get("count") or 0) - stale_evidence_count)
                / max(int(evidence_freshness.get("count") or 0), 1),
                1,
            ),
        },
        "evidence_requests": {"open": len(open_evidence)},
        "access_reviews": {
            "active": len(active_reviews),
            "completed": len(completed_reviews),
        },
        "trust_shares": {
            "active": len(active_shares),
            "auditor": len(auditor_shares),
        },
        "connectors": {
            "enabled": int(summary.get("enabled_connectors") or 0),
            "failed": int(summary.get("failed_connectors") or 0),
            "evidence_count": int(summary.get("evidence_count") or 0),
            "evidence_sources": evidence_sources,
        },
        "snapshots": {
            "latest_hash": latest_snapshot.get("assessment_hash") if latest_snapshot else None,
            "latest_at": latest_snapshot.get("evaluated_at") if latest_snapshot else None,
            "count": len(snapshot_rows),
        },
        "agents": {"pending_decisions": pending_decisions},
        "vendor_risk": vendor_risk,
        "personnel": personnel,
        "policy_attestation": policy_attestation,
        "frameworks": framework_readiness,
        "framework_ready_criteria": {
            "min_score": FRAMEWORK_READY_SCORE,
            "min_coverage_pct": FRAMEWORK_READY_MIN_COVERAGE_PCT,
        },
        "gaps": gaps,
        "workflow_coverage": {
            "scored": False,
            "description": "Product capabilities available in TrustOps; not part of the audit score.",
            "score": coverage_score,
            "checklist": checklist,
        },
    }


__all__ = ["build_audit_readiness"]
