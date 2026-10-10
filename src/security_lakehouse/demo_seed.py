"""Synthetic application-state records for the local golden demo.

``fixtures load --company golden`` builds the evidence lake; the console's
remediation, risk, policy, vendor, and insights pages read a separate
application-state database that a fresh lake leaves empty. This module seeds a
small set of clearly synthetic records into that database for the local no-auth
demo tenant, through the same service functions the HTTP API uses.

Guarantees:

- Only the lake-local SQLite database is written. A configured
  ``GRC_LAKE_DATABASE_URL`` is never treated as a demo target.
- Lake files (bronze/silver/gold, snapshots, manifest) are never touched, so
  assessment hashes and pinned pipeline outputs do not change.
- Re-running is a no-op for records that already exist.
- Remediation tasks and risks link only to findings the golden pipeline opened.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.runtime_environment import runtime_env

DEMO_SEED_ACTOR = "trustops-demo-seed"
SYNTHETIC_MARKER = "Synthetic demo"
_NOTE = f"{SYNTHETIC_MARKER} record seeded by `fixtures load --company golden`; not production data."

_TASKS: tuple[dict[str, Any], ...] = (
    {
        "title": "Remove stale admin grants after role change",
        "control_id": "SOC2-CC6.4",
        "owner": "identity-team",
        "priority": "critical",
        "due_days": 2,
        "status": "in_progress",
    },
    {
        "title": "Patch internet-facing hosts with critical CVEs",
        "control_id": "SOC2-CC7.1",
        "owner": "platform-sre",
        "priority": "high",
        "due_days": 5,
    },
    {
        "title": "Require approvals on production change pipelines",
        "control_id": "SOC2-CC8.1",
        "owner": "devops",
        "priority": "high",
        "due_days": -1,
    },
    {
        "title": "Document AI model risk tolerances for GOVERN 1.2",
        "control_id": "NIST-AI-RMF-GOVERN-1.2",
        "owner": "ai-governance",
        "priority": "medium",
        "due_days": 14,
    },
)

_RISKS: tuple[dict[str, Any], ...] = (
    {
        "title": "Privileged access outlives role changes",
        "category": "Identity & access",
        "severity": "high",
        "likelihood": "high",
        "impact": "high",
        "status": "mitigating",
        "treatment": "Quarterly access reviews plus automated deprovisioning on role change.",
        "owner": "identity-team",
        "control_id": "SOC2-CC6.4",
    },
    {
        "title": "Internet-facing hosts carry unpatched critical CVEs",
        "category": "Vulnerability management",
        "severity": "critical",
        "likelihood": "medium",
        "impact": "critical",
        "status": "open",
        "treatment": "Patch within the 7-day critical SLA; isolate hosts that miss it.",
        "owner": "platform-sre",
        "control_id": "SOC2-CC7.1",
    },
    {
        "title": "Production changes ship without peer approval",
        "category": "Change management",
        "severity": "high",
        "likelihood": "medium",
        "impact": "high",
        "status": "mitigating",
        "treatment": "Branch protection with required reviews on deploy pipelines.",
        "owner": "devops",
        "control_id": "SOC2-CC8.1",
    },
    {
        "title": "AI model risk tolerances are undocumented",
        "category": "AI governance",
        "severity": "medium",
        "likelihood": "medium",
        "impact": "medium",
        "status": "open",
        "treatment": "Publish risk tolerances per model and review them with the AI council.",
        "owner": "ai-governance",
        "control_id": "NIST-AI-RMF-GOVERN-1.2",
    },
)

_POLICY_TEMPLATE = "access-control-policy"
_POLICY_OWNER = "security-team"

_VENDORS: tuple[dict[str, Any], ...] = (
    {
        "vendor_name": "Payroll provider (synthetic demo)",
        "owner": "procurement",
        "due_days": 10,
        "status": "in_review",
    },
    {
        "vendor_name": "Log analytics vendor (synthetic demo)",
        "owner": "security-team",
        "due_days": 21,
        "status": "draft",
    },
)
_VENDOR_TEMPLATE = "soc2-vendor-standard"

# Earlier synthetic trend points: (days before now, score delta, open-violation delta).
_HISTORY: tuple[tuple[int, float, int], ...] = ((14, -8.0, 5), (7, -4.0, 2))


def _demo_tenant() -> str:
    from security_lakehouse.auth.authority import INSECURE_IDENTITY

    return INSECURE_IDENTITY.tenant_id


def seed_golden_demo(
    lake_dir: str | Path,
    *,
    tenant_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Seed synthetic demo records into the lake-local app-state database.

    Returns ``{"seeded": False, "reason": ...}`` when seeding is not allowed,
    otherwise ``{"seeded": True, "tenant_id": ..., "created": {table: count}}``.
    """
    try:
        from security_lakehouse.db import migrate
        from security_lakehouse.db.base import ENV_DATABASE_URL, create_engine_for, session_factory
    except ModuleNotFoundError:
        return {"seeded": False, "reason": "the 'server' extra is not installed"}
    if runtime_env().get(ENV_DATABASE_URL):
        return {
            "seeded": False,
            "reason": f"{ENV_DATABASE_URL} is set; demo records only go to the lake-local database",
        }

    from security_lakehouse.assessment import build_current_posture

    lake = Path(lake_dir)
    tenant = tenant_id or _demo_tenant()
    moment = now or datetime.now(UTC)
    open_violations = {
        str(row["control_id"]): str(row["violation_id"])
        for row in build_current_posture(lake, now=moment, inline_violation_cap=None).get("violations") or []
        if row.get("control_id") and row.get("violation_id")
    }

    migrate.upgrade(lake)
    engine = create_engine_for(lake)
    try:
        factory = session_factory(engine)
        with factory() as session:
            created = {
                "remediation_tasks": _seed_tasks(session, tenant, open_violations, moment),
                "risks": _seed_risks(session, tenant, open_violations, moment),
                "policy_documents": _seed_policy(session, tenant, moment),
                "vendor_assessments": _seed_vendors(session, tenant, moment),
                "posture_metric_points": _seed_metrics(session, tenant, lake, moment),
            }
    finally:
        engine.dispose()
    return {"seeded": True, "tenant_id": tenant, "created": created}


def _seed_tasks(session, tenant: str, open_violations: dict[str, str], moment: datetime) -> int:
    from security_lakehouse.services import grc

    existing = {row["title"] for row in grc.list_tasks(session, tenant)}
    created = 0
    for spec in _TASKS:
        control_id = spec["control_id"]
        if spec["title"] in existing or control_id not in open_violations:
            continue
        task = grc.create_task(
            session,
            tenant,
            title=spec["title"],
            description=_NOTE,
            control_id=control_id,
            violation_id=open_violations[control_id],
            owner=spec["owner"],
            priority=spec["priority"],
            due_at=moment + timedelta(days=spec["due_days"]),
            created_by=DEMO_SEED_ACTOR,
        )
        if spec.get("status"):
            grc.update_task(session, tenant, task["id"], changes={"status": spec["status"]})
        created += 1
    return created


def _seed_risks(session, tenant: str, open_violations: dict[str, str], moment: datetime) -> int:
    from security_lakehouse.services import grc

    existing = {row["title"] for row in grc.list_risks(session, tenant)}
    created = 0
    for spec in _RISKS:
        if spec["title"] in existing or spec["control_id"] not in open_violations:
            continue
        grc.create_risk(session, tenant, description=_NOTE, due_at=moment + timedelta(days=30), **spec)
        created += 1
    return created


def _seed_policy(session, tenant: str, moment: datetime) -> int:
    from security_lakehouse.services import policy_documents

    if any(row["template_id"] == _POLICY_TEMPLATE for row in policy_documents.list_documents(session, tenant)):
        return 0
    document = policy_documents.adopt_template(
        session,
        tenant,
        template_id=_POLICY_TEMPLATE,
        variables={
            "company_name": "Golden demo workspace",
            "policy_owner": _POLICY_OWNER,
            "effective_date": moment.date().isoformat(),
        },
        owner=_POLICY_OWNER,
        created_by=DEMO_SEED_ACTOR,
    )
    policy_documents.publish_document(session, tenant, document["id"])
    return 1


def _seed_vendors(session, tenant: str, moment: datetime) -> int:
    from security_lakehouse.services import vendor_risk

    existing = {row["vendor_name"] for row in vendor_risk.list_assessments(session, tenant)}
    created = 0
    for spec in _VENDORS:
        if spec["vendor_name"] in existing:
            continue
        row = vendor_risk.create_assessment(
            session,
            tenant,
            vendor_name=spec["vendor_name"],
            template_id=_VENDOR_TEMPLATE,
            owner=spec["owner"],
            due_at=moment + timedelta(days=spec["due_days"]),
            created_by=DEMO_SEED_ACTOR,
        )
        if spec["status"] != "draft":
            vendor_risk.update_assessment(session, tenant, row["id"], changes={"status": spec["status"]})
        created += 1
    return created


def _seed_metrics(session, tenant: str, lake: Path, moment: datetime) -> int:
    """One live capture plus earlier synthetic points so the Insights trends draw lines."""
    from sqlalchemy import func, select

    from security_lakehouse.db import metrics
    from security_lakehouse.db.models import PostureMetricPoint

    if session.scalar(
        select(func.count()).select_from(PostureMetricPoint).where(PostureMetricPoint.tenant_id == tenant)
    ):
        return 0
    current = metrics.capture_metric_point(session, tenant_id=tenant, lake_dir=lake, now=moment)
    for days, score_delta, violation_delta in _HISTORY:
        step = days // 7
        session.add(
            PostureMetricPoint(
                tenant_id=tenant,
                captured_at=moment - timedelta(days=days),
                posture_score=max(0.0, round(current.posture_score + score_delta, 2)),
                control_pass_rate=max(0.0, round(current.control_pass_rate - 0.05 * step, 4)),
                open_violations=current.open_violations + violation_delta,
                critical_violations=current.critical_violations + step,
                stale_controls=current.stale_controls + 2 * step,
                evidence_fresh_pct=max(0.0, round(current.evidence_fresh_pct - 0.05 * step, 4)),
                remediation_open=max(0, current.remediation_open - step),
                remediation_overdue=0,
            )
        )
    session.commit()
    return 1 + len(_HISTORY)


__all__ = ["DEMO_SEED_ACTOR", "SYNTHETIC_MARKER", "seed_golden_demo"]
