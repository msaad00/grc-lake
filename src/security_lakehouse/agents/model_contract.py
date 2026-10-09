"""Model contract for optional GRC Lake agent runs.

The model sees redacted facts and tool schemas. It may summarize, rank, and
propose allowed tool calls, but GRC Lake core remains the executor and source
of truth for compliance decisions.
"""

from __future__ import annotations

import json
from typing import Any

from security_lakehouse.agents.budgets import AgentBudgetPolicy, apply_budget
from security_lakehouse.agents.providers import ModelProviderConfig

POSTURE_REVIEW_TOOL_CALLS = {"create_evidence_request", "create_remediation_task", "freeze_snapshot"}
SOC_TRIAGE_TOOL_CALLS = {
    "create_soc_case",
    "create_remediation_task",
    "assign_owner",
    "enrich_alert",
    "notify_channel",
    "freeze_snapshot",
}
ALLOWED_MODEL_TOOL_CALLS = POSTURE_REVIEW_TOOL_CALLS | SOC_TRIAGE_TOOL_CALLS


def tool_manifest(*, use_case: str = "posture_review") -> list[dict[str, Any]]:
    """Return deterministic tools the optional model is allowed to reason about."""
    shared = [
        {
            "name": "load_redacted_posture",
            "mode": "read",
            "description": "Loads current GRC Lake posture after role-based redaction.",
            "inputs": {"lake_dir": "string", "role": "string"},
            "outputs": {"posture": "object"},
        },
        {
            "name": "load_evidence_gaps",
            "mode": "read",
            "description": "Lists missing, stale, or expired evidence gaps after role-based redaction.",
            "inputs": {"lake_dir": "string", "role": "string"},
            "outputs": {"evidence_gaps": "array"},
        },
        {
            "name": "create_evidence_request",
            "mode": "propose_only",
            "description": "Proposes a human-approved evidence request. GRC Lake APIs execute it later.",
            "inputs": {"control_id": "string", "reason": "string"},
            "outputs": {"proposal": "object"},
        },
        {
            "name": "create_remediation_task",
            "mode": "propose_only",
            "description": "Proposes a human-approved remediation task. GRC Lake APIs execute it later.",
            "inputs": {"control_id": "string", "reason": "string", "owner": "string"},
            "outputs": {"proposal": "object"},
        },
        {
            "name": "freeze_snapshot",
            "mode": "propose_only",
            "description": "Proposes freezing a point-in-time snapshot. GRC Lake computes and signs it.",
            "inputs": {"reason": "string"},
            "outputs": {"proposal": "object"},
        },
    ]
    if use_case != "soc_triage":
        return shared
    return [
        *shared,
        {
            "name": "load_soc_alerts",
            "mode": "read",
            "description": "Lists open detection, vulnerability, runtime, cloud, and identity alerts after redaction.",
            "inputs": {"lake_dir": "string", "role": "string"},
            "outputs": {"alerts": "array"},
        },
        {
            "name": "create_soc_case",
            "mode": "propose_only",
            "description": "Proposes a SOC case for an alert. GRC Lake APIs execute it later.",
            "inputs": {"event_id": "string", "severity": "string", "reason": "string"},
            "outputs": {"proposal": "object"},
        },
        {
            "name": "assign_owner",
            "mode": "propose_only",
            "description": "Proposes assigning an owner to an alert or case.",
            "inputs": {"event_id": "string", "owner": "string", "reason": "string"},
            "outputs": {"proposal": "object"},
        },
        {
            "name": "enrich_alert",
            "mode": "propose_only",
            "description": "Proposes deterministic enrichment for an alert from approved sources.",
            "inputs": {"event_id": "string", "sources": "array"},
            "outputs": {"proposal": "object"},
        },
        {
            "name": "notify_channel",
            "mode": "propose_only",
            "description": "Proposes notifying an approved channel. GRC Lake egress policy gates execution.",
            "inputs": {"event_id": "string", "channel": "string", "reason": "string"},
            "outputs": {"proposal": "object"},
        },
    ]


def build_model_context(
    state: dict[str, Any],
    provider: ModelProviderConfig,
    *,
    use_case: str = "posture_review",
    budget: AgentBudgetPolicy | None = None,
) -> dict[str, Any]:
    """Build a redacted, bounded model context from deterministic harness state."""
    policy = budget or AgentBudgetPolicy.from_env()
    context = {
        "contract": "trustops.agent_context.v1",
        "use_case": use_case,
        "objective": state.get("objective", ""),
        "role": state.get("role", "read_only"),
        "provider": provider.public_dict(),
        "policy": {
            "compliance_truth": "GRC Lake deterministic controls, evidence, hashes, and snapshots only",
            "model_allowed": ["summarize", "rank", "explain", "propose_allowed_tool_calls"],
            "model_forbidden": [
                "mark_control_passed",
                "change_evidence",
                "bypass_rbac",
                "execute_writes_directly",
                "invent_framework_mappings",
            ],
            "writes": "approval_required_and_executed_only_by_trustops_core",
        },
        "tool_manifest": tool_manifest(use_case=use_case),
        "facts": {
            "posture": state.get("posture", {}),
            "evidence_gaps": state.get("evidence_gaps", []),
            "alerts": state.get("alerts", []),
            "deterministic_decisions": [
                {
                    "action": item.action,
                    "reason": item.reason,
                    "requires_approval": item.requires_approval,
                    "payload": item.payload,
                    "status": item.status,
                }
                for item in state.get("decisions", [])
            ],
        },
        "expected_output": {
            "summary": "string",
            "priorities": [{"control_id": "string", "reason": "string", "rank": "integer"}],
            "proposed_tool_calls": [{"name": "string", "arguments": "object", "requires_approval": True}],
        },
    }
    return apply_budget(context, policy)


def model_messages(context: dict[str, Any]) -> list[dict[str, str]]:
    """Render provider-agnostic chat messages for JSON-output models."""
    return [
        {
            "role": "system",
            "content": (
                "You are the optional GRC Lake orchestration brain. You do not decide compliance. "
                "Use only the supplied redacted facts and tool manifest. Return strict JSON."
            ),
        },
        {
            "role": "user",
            "content": (
                "Review this GRC Lake agent context and return JSON with summary, priorities, "
                f"and proposed_tool_calls only:\n{json.dumps(context, sort_keys=True, separators=(',', ':'))}"
            ),
        },
    ]


def validate_model_output(
    payload: Any,
    *,
    allowed_tool_calls: set[str] | None = None,
) -> dict[str, Any]:
    """Validate and normalize model JSON without executing any proposed action."""
    if not isinstance(payload, dict):
        return {"summary": "", "priorities": [], "proposed_tool_calls": [], "rejected_tool_calls": ["non_object"]}

    priorities = payload.get("priorities")
    if not isinstance(priorities, list):
        priorities = []
    normalized_priorities: list[dict[str, Any]] = []
    for index, item in enumerate(priorities[:10], start=1):
        if not isinstance(item, dict):
            continue
        control_id = str(item.get("control_id") or "").strip()
        if not control_id:
            continue
        normalized_priorities.append(
            {
                "control_id": control_id,
                "reason": str(item.get("reason") or "model-prioritized gap")[:500],
                "rank": int(item.get("rank") or index),
            }
        )

    proposed = payload.get("proposed_tool_calls")
    if not isinstance(proposed, list):
        proposed = []
    accepted: list[dict[str, Any]] = []
    rejected: list[str] = []
    allowed = allowed_tool_calls or ALLOWED_MODEL_TOOL_CALLS
    for item in proposed[:10]:
        if not isinstance(item, dict):
            rejected.append("non_object_tool_call")
            continue
        name = str(item.get("name") or "").strip()
        if name not in allowed:
            rejected.append(name or "missing_name")
            continue
        arguments = item.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        accepted.append({"name": name, "arguments": arguments, "requires_approval": True, "status": "proposed"})

    return {
        "summary": str(payload.get("summary") or "")[:2000],
        "priorities": normalized_priorities,
        "proposed_tool_calls": accepted,
        "rejected_tool_calls": rejected,
    }
