"""One rule-aware verdict contract for catalog controls and explicit safeguards."""

from typing import Any

from security_lakehouse.event_status import FAIL_STATUSES, normalize_event_status
from security_lakehouse.policy import ControlContext, RuleResult, evaluate_control


def evaluate_evidence_verdict(control_id: str, rows: list[dict[str, Any]], rule: Any, *, stale: bool) -> RuleResult:
    """Keep rule failure, unknown outcome and unavailable evidence distinct.

    Observations retain provenance at the caller but cannot supply verdict
    evidence. Source failures respect the declared rule's severity threshold.
    Freshness is evaluated over current evidence populations by the caller.
    """
    verdict_rows = [row for row in rows if normalize_event_status(row["status"]) != "observed"]
    failures = [row for row in verdict_rows if normalize_event_status(row["status"]) in FAIL_STATUSES]
    unknown = any(normalize_event_status(row["status"]) == "not_evaluated" for row in verdict_rows)
    evidence = [row for row in verdict_rows if row.get("evidence_ref") and row.get("evidence_available", True)]
    top_open = max(failures, key=lambda row: row["severity_score"], default=None)
    context = ControlContext(
        control_id=control_id,
        open_violation_count=len(failures),
        event_count=len(verdict_rows),
        evidence_count=len(evidence),
        max_severity=str(top_open["severity"]) if top_open else "info",
        evidence_status="stale" if stale else "fresh",
    )
    result = evaluate_control(context, rule)
    if result.status == "fail" and (failures or not evidence):
        return result
    if unknown or not verdict_rows:
        result.status = "not_evaluated"
        result.reasons.append(
            "Source evidence has an unknown or unevaluated outcome."
            if unknown
            else "Source evidence contains only observations, without an evaluated outcome."
        )
    elif stale or not evidence:
        result.status = "stale"
    return result
