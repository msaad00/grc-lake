"""Deterministic SOC triage harness for alert-centered use cases."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from security_lakehouse.agents.budgets import AgentBudgetPolicy
from security_lakehouse.agents.checkpoints import invoke_with_checkpoint, memory_checkpointer
from security_lakehouse.agents.evaluations import evaluate_soc_triage
from security_lakehouse.agents.graphs import ModelClient, build_soc_triage_graph
from security_lakehouse.agents.model_client import ModelClientError, call_model_json
from security_lakehouse.agents.model_contract import SOC_TRIAGE_TOOL_CALLS, build_model_context, validate_model_output
from security_lakehouse.agents.providers import ModelProviderConfig, provider_from_env
from security_lakehouse.agents.state import AgentDecision, AgentOrchestrator, AgentRunState
from security_lakehouse.agents.tools import assess_data_readiness
from security_lakehouse.data_policy import redact_payload
from security_lakehouse.event_status import FAIL_STATUSES
from security_lakehouse.io import read_jsonl

SOC_EVENT_PREFIXES = (
    "detection.",
    "vulnerability.",
    "runtime.",
    "cloud.",
    "aws.",
    "azure.",
    "gcp.",
    "okta.",
    "google_workspace.",
)
OPEN_STATUSES = FAIL_STATUSES
HIGH_SEVERITIES = {"critical", "high"}


def load_soc_alerts(lake_dir: str | Path, *, role: str, limit: int = 25) -> list[dict[str, Any]]:
    """Load open SOC-relevant alerts from normalized evidence."""
    rows = read_jsonl(Path(lake_dir) / "silver" / "normalized_events.jsonl", missing_ok=True)
    alerts: list[dict[str, Any]] = []
    for row in rows:
        event_type = str(row.get("event_type") or "")
        status = str(row.get("status") or "").lower()
        severity = str(row.get("severity") or "info").lower()
        if status not in OPEN_STATUSES:
            continue
        if not event_type.startswith(SOC_EVENT_PREFIXES) and severity not in HIGH_SEVERITIES:
            continue
        alert = {
            "event_id": row.get("event_id"),
            "event_time": row.get("event_time"),
            "event_type": event_type,
            "source": row.get("source"),
            "asset_id": row.get("asset_id"),
            "asset_type": row.get("asset_type"),
            "asset_owner": row.get("asset_owner"),
            "environment": row.get("environment"),
            "severity": severity,
            "severity_score": int(row.get("severity_score") or 0),
            "status": status,
            "control_ids": row.get("control_ids") or [],
            "evidence_ref": row.get("evidence_ref"),
            "raw_sha256": row.get("raw_sha256"),
        }
        redacted = redact_payload(alert, role=role)
        if isinstance(redacted, dict):
            alerts.append(redacted)
    alerts.sort(
        key=lambda item: (int(item.get("severity_score") or 0), str(item.get("event_time") or "")), reverse=True
    )
    return alerts[:limit]


def propose_soc_actions(alerts: list[dict[str, Any]], *, limit: int = 10) -> list[AgentDecision]:
    """Build deterministic, approval-required SOC action proposals."""
    decisions: list[AgentDecision] = []
    for alert in alerts[:limit]:
        event_id = str(alert.get("event_id") or "")
        severity = str(alert.get("severity") or "info").lower()
        event_type = str(alert.get("event_type") or "unknown")
        owner = str(alert.get("asset_owner") or "security")
        if severity in HIGH_SEVERITIES:
            decisions.append(
                AgentDecision(
                    action="create_soc_case",
                    reason=f"{severity} open {event_type} on {alert.get('asset_id')}",
                    requires_approval=True,
                    payload={"event_id": event_id, "severity": severity, "event_type": event_type},
                    status="proposed",
                )
            )
            decisions.append(
                AgentDecision(
                    action="assign_owner",
                    reason=f"route {event_id} to owning security team",
                    requires_approval=True,
                    payload={"event_id": event_id, "owner": owner},
                    status="proposed",
                )
            )
        else:
            decisions.append(
                AgentDecision(
                    action="enrich_alert",
                    reason=f"collect deterministic enrichment before case creation for {event_type}",
                    requires_approval=True,
                    payload={"event_id": event_id, "sources": ["asset", "control", "evidence_hash"]},
                    status="proposed",
                )
            )
    return decisions


def run_soc_triage(
    lake_dir: str | Path,
    *,
    role: str = "read_only",
    objective: str = "Triage open SOC alerts and propose guarded actions.",
    provider: ModelProviderConfig | None = None,
    budget: AgentBudgetPolicy | None = None,
    model_client: ModelClient | None = None,
    orchestrator: AgentOrchestrator = "sequential",
    checkpoint_thread_id: str | None = None,
    resume: bool = False,
) -> AgentRunState:
    """Run a deterministic SOC triage harness with optional model assistance."""
    if orchestrator not in {"sequential", "langgraph"}:
        raise ValueError("soc_triage orchestrator must be 'sequential' or 'langgraph'")
    provider = provider or provider_from_env()
    budget = budget or AgentBudgetPolicy.from_env()
    state: AgentRunState = {
        "lake_dir": str(lake_dir),
        "role": role,
        "objective": objective,
        "mode": "rules_only",
        "orchestrator": orchestrator,
        "model_provider": provider.public_dict(),
        "agent_budget": budget.public_dict(),
        "data_readiness": assess_data_readiness(lake_dir, role=role, harness="soc_triage"),
        "errors": [],
    }
    if orchestrator == "langgraph":
        state = cast(
            AgentRunState,
            invoke_with_checkpoint(
                build_soc_triage_graph(checkpointer=memory_checkpointer() if checkpoint_thread_id else None),
                state,
                thread_id=checkpoint_thread_id,
                resume=resume,
            ),
        )
        state["mode"] = "langgraph"
        state["orchestrator"] = "langgraph"
    else:
        state["alerts"] = load_soc_alerts(lake_dir, role=role)
        state["decisions"] = propose_soc_actions(state["alerts"])
    if provider.enabled:
        context = build_model_context(dict(state), provider, use_case="soc_triage", budget=budget)
        state["model_context"] = context
        if context.get("budget", {}).get("status") == "over_budget":
            state["errors"] = [*state.get("errors", []), "model_skipped: context_budget_exceeded"]
        elif provider.should_call_model:
            client = model_client or call_model_json
            try:
                raw_output = client(context, provider)
                state["model_output"] = validate_model_output(raw_output, allowed_tool_calls=SOC_TRIAGE_TOOL_CALLS)
                state["mode"] = "model_assisted"
            except ModelClientError as exc:
                state["errors"] = [*state.get("errors", []), f"model_error: {exc}"]
    state["evaluation"] = evaluate_soc_triage(dict(state))
    return state
