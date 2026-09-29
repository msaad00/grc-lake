"""Deterministic guardrail evaluations for agent harnesses."""

from __future__ import annotations

from typing import Any

from security_lakehouse.agents.model_contract import POSTURE_REVIEW_TOOL_CALLS, SOC_TRIAGE_TOOL_CALLS


def _decision_items(state: dict[str, Any]) -> list[Any]:
    return list(state.get("decisions") or [])


def _decision_action(item: Any) -> str:
    return str(getattr(item, "action", "") or (item.get("action") if isinstance(item, dict) else ""))


def _decision_requires_approval(item: Any) -> bool:
    if hasattr(item, "requires_approval"):
        return bool(item.requires_approval)
    if isinstance(item, dict):
        return bool(item.get("requires_approval"))
    return False


def _decision_status(item: Any) -> str:
    return str(getattr(item, "status", "") or (item.get("status") if isinstance(item, dict) else ""))


def _check(check: str, passed: bool, detail: dict[str, Any] | None = None, *, weight: int = 1) -> dict[str, Any]:
    return {"check": check, "passed": passed, "detail": detail or {}, "weight": weight}


def _budget_status(state: dict[str, Any]) -> str:
    context = state.get("model_context")
    if not isinstance(context, dict):
        context = {}
    budget = context.get("budget")
    if not isinstance(budget, dict):
        budget = {}
    return str(budget.get("status") or "not_applicable")


def _rejected_tool_calls(state: dict[str, Any]) -> list[Any]:
    model_output = state.get("model_output")
    if not isinstance(model_output, dict):
        model_output = {}
    rejected = model_output.get("rejected_tool_calls", []) if isinstance(model_output, dict) else []
    return rejected if isinstance(rejected, list) else []


def _coverage(state: dict[str, Any], *, use_case: str) -> dict[str, Any]:
    decisions = _decision_items(state)
    return {
        "use_case": use_case,
        "mode": state.get("mode", "rules_only"),
        "decisions_total": len(decisions),
        "approval_gated_decisions": sum(1 for item in decisions if _decision_requires_approval(item)),
        "proposed_decisions": sum(1 for item in decisions if _decision_status(item) == "proposed"),
        "model_rejected_tool_calls": len(_rejected_tool_calls(state)),
        "model_budget_status": _budget_status(state),
        "errors": len(state.get("errors") or []),
    }


def _result(checks: list[dict[str, Any]], coverage: dict[str, Any]) -> dict[str, Any]:
    total_weight = sum(int(item.get("weight") or 1) for item in checks) or 1
    passed_weight = sum(int(item.get("weight") or 1) for item in checks if item.get("passed"))
    score = round((passed_weight / total_weight) * 100)
    failures = [item for item in checks if not item.get("passed")]
    rejected_count = int(coverage.get("model_rejected_tool_calls", 0) or 0)
    if failures:
        confidence = "low" if score < 70 else "medium"
    elif rejected_count:
        confidence = "medium"
    elif score >= 90:
        confidence = "high"
    elif score >= 70:
        confidence = "medium"
    else:
        confidence = "low"
    risk_level = "critical" if any(item["check"] == "writes_are_approval_gated" for item in failures) else "high"
    if not failures:
        risk_level = "low" if rejected_count == 0 else "medium"
    return {
        "ok": not failures,
        "score": score,
        "confidence": confidence,
        "risk_level": risk_level,
        "checks": checks,
        "failures": failures,
        "coverage": coverage,
    }


def evaluate_agent_run(state: dict[str, Any], *, use_case: str) -> dict[str, Any]:
    """Evaluate generic harness safety invariants and deterministic confidence."""
    allowed = SOC_TRIAGE_TOOL_CALLS if use_case == "soc_triage" else POSTURE_REVIEW_TOOL_CALLS
    checks: list[dict[str, Any]] = []
    decisions = _decision_items(state)
    unsupported = sorted({_decision_action(item) for item in decisions if _decision_action(item) not in allowed})
    checks.append(_check("allowed_actions_only", not unsupported, {"unsupported_actions": unsupported}, weight=3))
    unsafe_writes = [
        _decision_action(item)
        for item in decisions
        if _decision_action(item) in allowed
        and (not _decision_requires_approval(item) or _decision_status(item) == "executed")
    ]
    checks.append(_check("writes_are_approval_gated", not unsafe_writes, {"unsafe_actions": unsafe_writes}, weight=4))
    model_output = state.get("model_output")
    if not isinstance(model_output, dict):
        model_output = {}
    rejected = model_output.get("rejected_tool_calls", []) if isinstance(model_output, dict) else []
    checks.append(
        _check(
            "model_rejections_recorded",
            isinstance(rejected, list),
            {"rejected_tool_calls": rejected if isinstance(rejected, list) else "invalid"},
            weight=1,
        )
    )
    budget_status = _budget_status(state)
    errors = {str(item) for item in state.get("errors") or []}
    checks.append(
        _check(
            "context_budget_enforced",
            budget_status != "over_budget" or "model_skipped: context_budget_exceeded" in errors,
            {"budget_status": budget_status},
            weight=2,
        )
    )
    coverage = _coverage(state, use_case=use_case)
    if use_case == "posture_review":
        evidence_gaps = [row for row in state.get("evidence_gaps", []) if isinstance(row, dict)]
        gap_control_ids = {str(row.get("control_id") or "") for row in evidence_gaps if row.get("control_id")}
        covered_control_ids = set()
        for item in decisions:
            payload = (
                getattr(item, "payload", None)
                if hasattr(item, "payload")
                else item.get("payload")
                if isinstance(item, dict)
                else {}
            )
            if isinstance(payload, dict) and payload.get("control_id"):
                covered_control_ids.add(str(payload["control_id"]))
        missing = sorted(control_id for control_id in gap_control_ids if control_id not in covered_control_ids)
        checks.append(
            _check(
                "evidence_gaps_have_actions",
                not missing,
                {"missing_control_ids": missing},
                weight=2,
            )
        )
        coverage = {
            **coverage,
            "evidence_gaps_total": len(evidence_gaps),
            "covered_evidence_gap_controls": len(gap_control_ids) - len(missing),
            "evidence_gap_coverage": 1.0
            if not gap_control_ids
            else round((len(gap_control_ids) - len(missing)) / len(gap_control_ids), 4),
        }
    return _result(checks, coverage)


def evaluate_posture_review(state: dict[str, Any]) -> dict[str, Any]:
    """Evaluate posture-review guardrails and deterministic confidence."""
    return evaluate_agent_run(state, use_case="posture_review")


def evaluate_soc_triage(state: dict[str, Any]) -> dict[str, Any]:
    """Evaluate SOC triage-specific deterministic guardrails."""
    base = evaluate_agent_run(state, use_case="soc_triage")
    alerts = [row for row in state.get("alerts", []) if isinstance(row, dict)]
    high_priority = {
        str(row.get("event_id") or "")
        for row in alerts
        if str(row.get("status") or "").lower() in {"open", "failed", "blocked", "noncompliant"}
        and str(row.get("severity") or "").lower() in {"critical", "high"}
    }
    covered = set()
    for item in _decision_items(state):
        payload = (
            getattr(item, "payload", None)
            if hasattr(item, "payload")
            else item.get("payload")
            if isinstance(item, dict)
            else {}
        )
        if isinstance(payload, dict):
            covered.add(str(payload.get("event_id") or ""))
    missing = sorted(event_id for event_id in high_priority if event_id and event_id not in covered)
    check = _check(
        "high_priority_alerts_have_actions",
        not missing,
        {"missing_event_ids": missing},
        weight=3,
    )
    coverage = {
        **base["coverage"],
        "alerts_total": len(alerts),
        "high_priority_alerts": len([event_id for event_id in high_priority if event_id]),
        "covered_high_priority_alerts": len([event_id for event_id in high_priority if event_id]) - len(missing),
        "high_priority_coverage": 1.0
        if not high_priority
        else round((len([event_id for event_id in high_priority if event_id]) - len(missing)) / len(high_priority), 4),
    }
    return _result([*base["checks"], check], coverage)
