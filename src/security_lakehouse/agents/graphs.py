"""Optional LangGraph workflows around GRC Lake facts."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from security_lakehouse.agents.budgets import AgentBudgetPolicy
from security_lakehouse.agents.checkpoints import invoke_with_checkpoint, memory_checkpointer
from security_lakehouse.agents.evaluations import evaluate_posture_review
from security_lakehouse.agents.model_client import ModelClientError, call_model_json
from security_lakehouse.agents.model_contract import (
    POSTURE_REVIEW_TOOL_CALLS,
    build_model_context,
    validate_model_output,
)
from security_lakehouse.agents.providers import ModelProviderConfig, provider_from_env
from security_lakehouse.agents.state import AgentDecision, AgentOrchestrator, AgentRunState
from security_lakehouse.agents.tools import (
    assess_data_readiness,
    load_evidence_gaps,
    load_redacted_posture,
    propose_evidence_gap_actions,
)

ModelClient = Callable[[dict[str, Any], ModelProviderConfig], dict[str, Any]]


def _initial_posture_state(
    lake_dir: str | Path,
    *,
    role: str,
    objective: str,
    provider: ModelProviderConfig,
    budget: AgentBudgetPolicy,
    orchestrator: AgentOrchestrator,
) -> AgentRunState:
    return {
        "lake_dir": str(lake_dir),
        "role": role,
        "objective": objective,
        "mode": "rules_only",
        "orchestrator": orchestrator,
        "model_provider": provider.public_dict(),
        "agent_budget": budget.public_dict(),
        "data_readiness": assess_data_readiness(lake_dir, role=role, harness="posture_review"),
        "errors": [],
    }


def _load_posture_node(state: AgentRunState) -> AgentRunState:
    return {
        **state,
        "posture": load_redacted_posture(state["lake_dir"], role=state.get("role", "read_only")),
    }


def _load_gaps_node(state: AgentRunState) -> AgentRunState:
    return {
        **state,
        "evidence_gaps": load_evidence_gaps(state["lake_dir"], role=state.get("role", "read_only")),
    }


def _propose_actions_node(state: AgentRunState) -> AgentRunState:
    decisions = [
        AgentDecision(
            action=str(item["action"]),
            reason=str(item["reason"]),
            requires_approval=bool(item["requires_approval"]),
            payload={"control_id": item["control_id"]},
            status="proposed",
        )
        for item in propose_evidence_gap_actions(state.get("evidence_gaps", []))
    ]
    return {**state, "decisions": decisions}


def _finalize_no_gaps_node(state: AgentRunState) -> AgentRunState:
    return {**state, "decisions": []}


def run_posture_review(
    lake_dir: str | Path,
    *,
    role: str = "read_only",
    objective: str = "Review posture and propose evidence-gap actions.",
    provider: ModelProviderConfig | None = None,
    budget: AgentBudgetPolicy | None = None,
    model_client: ModelClient | None = None,
    orchestrator: AgentOrchestrator = "sequential",
    checkpoint_thread_id: str | None = None,
    resume: bool = False,
) -> AgentRunState:
    """Run the posture-review harness without requiring LangGraph or an LLM."""
    provider = provider or provider_from_env()
    budget = budget or AgentBudgetPolicy.from_env()
    if orchestrator not in {"sequential", "langgraph"}:
        raise ValueError("posture_review orchestrator must be 'sequential' or 'langgraph'")
    state = _initial_posture_state(
        lake_dir,
        role=role,
        objective=objective,
        provider=provider,
        budget=budget,
        orchestrator=orchestrator,
    )
    if orchestrator == "langgraph":
        state = cast(
            AgentRunState,
            invoke_with_checkpoint(
                build_posture_review_graph(checkpointer=memory_checkpointer() if checkpoint_thread_id else None),
                state,
                thread_id=checkpoint_thread_id,
                resume=resume,
            ),
        )
        state["mode"] = "langgraph"
        state["orchestrator"] = "langgraph"
    else:
        state = _load_posture_node(state)
        state = _load_gaps_node(state)
        state = _propose_actions_node(state)
    if provider.enabled:
        context = build_model_context(dict(state), provider, budget=budget)
        state["model_context"] = context
        if context.get("budget", {}).get("status") == "over_budget":
            state["errors"] = [*state.get("errors", []), "model_skipped: context_budget_exceeded"]
        elif provider.should_call_model:
            client = model_client or call_model_json
            try:
                raw_output = client(context, provider)
                state["model_output"] = validate_model_output(raw_output, allowed_tool_calls=POSTURE_REVIEW_TOOL_CALLS)
                state["mode"] = "model_assisted"
            except ModelClientError as exc:
                state["errors"] = [*state.get("errors", []), f"model_error: {exc}"]
    state["evaluation"] = evaluate_posture_review(dict(state))
    return state


def build_posture_review_graph(*, checkpointer: Any | None = None) -> Any:
    """Build a LangGraph StateGraph when the optional extra is installed."""
    try:
        from langgraph.graph import END, StateGraph
    except ImportError as exc:  # pragma: no cover - exercised without optional extra
        raise RuntimeError("install grc-lake[agents] to use LangGraph orchestration") from exc

    graph = StateGraph(AgentRunState)

    def _route_after_gaps(state: AgentRunState) -> str:
        gaps = state.get("evidence_gaps") or []
        return "propose_actions" if gaps else "finalize_no_gaps"

    graph.add_node("load_posture", _load_posture_node)
    graph.add_node("load_evidence_gaps", _load_gaps_node)
    graph.add_node("propose_actions", _propose_actions_node)
    graph.add_node("finalize_no_gaps", _finalize_no_gaps_node)
    graph.set_entry_point("load_posture")
    graph.add_edge("load_posture", "load_evidence_gaps")
    graph.add_conditional_edges(
        "load_evidence_gaps",
        _route_after_gaps,
        {"propose_actions": "propose_actions", "finalize_no_gaps": "finalize_no_gaps"},
    )
    graph.add_edge("propose_actions", END)
    graph.add_edge("finalize_no_gaps", END)
    return graph.compile(checkpointer=checkpointer) if checkpointer is not None else graph.compile()


def _load_alerts_node(state: AgentRunState) -> AgentRunState:
    from security_lakehouse.agents.soc import load_soc_alerts

    return {
        **state,
        "alerts": load_soc_alerts(state["lake_dir"], role=state.get("role", "read_only")),
    }


def _propose_soc_actions_node(state: AgentRunState) -> AgentRunState:
    from security_lakehouse.agents.soc import propose_soc_actions

    decisions = propose_soc_actions(state.get("alerts") or [])
    return {**state, "decisions": decisions}


def build_soc_triage_graph(*, checkpointer: Any | None = None) -> Any:
    """Build the SOC triage LangGraph when the optional extra is installed."""
    try:
        from langgraph.graph import END, StateGraph
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("install grc-lake[agents] to use LangGraph orchestration") from exc

    graph = StateGraph(AgentRunState)
    graph.add_node("load_alerts", _load_alerts_node)
    graph.add_node("propose_actions", _propose_soc_actions_node)
    graph.set_entry_point("load_alerts")
    graph.add_edge("load_alerts", "propose_actions")
    graph.add_edge("propose_actions", END)
    return graph.compile(checkpointer=checkpointer) if checkpointer is not None else graph.compile()
