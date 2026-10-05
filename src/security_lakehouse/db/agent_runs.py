"""Persistence helpers for human/headless agent harness runs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from security_lakehouse.agents import AgentBudgetPolicy, AgentDecision, run_posture_review, run_soc_triage
from security_lakehouse.agents.providers import ModelProviderConfig, provider_from_env
from security_lakehouse.agents.state import AgentOrchestrator
from security_lakehouse.db.models import AGENT_RUN_HARNESSES, AGENT_RUN_STATUSES, AgentRun


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _json_default(value: Any) -> Any:
    if isinstance(value, AgentDecision):
        return asdict(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json_default)


def _json_loads(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _state_for_storage(state: dict[str, Any]) -> dict[str, Any]:
    clean = dict(state)
    clean.pop("lake_dir", None)
    if "decisions" in clean:
        clean["decisions"] = [
            asdict(item) if isinstance(item, AgentDecision) else item for item in list(clean.get("decisions") or [])
        ]
    return clean


def _input_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_json_dumps(payload).encode("utf-8")).hexdigest()


def get_agent_run(session: Session, *, tenant_id: str, run_id: str) -> AgentRun | None:
    row = session.get(AgentRun, run_id)
    return row if row is not None and row.tenant_id == tenant_id else None


def get_agent_run_by_idempotency_key(session: Session, *, tenant_id: str, idempotency_key: str) -> AgentRun | None:
    stmt = select(AgentRun).where(AgentRun.tenant_id == tenant_id, AgentRun.idempotency_key == idempotency_key)
    return session.scalars(stmt).one_or_none()


def list_agent_runs(
    session: Session,
    *,
    tenant_id: str,
    harness: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[AgentRun]:
    stmt = select(AgentRun).where(AgentRun.tenant_id == tenant_id)
    if harness:
        stmt = stmt.where(AgentRun.harness == harness)
    if status:
        stmt = stmt.where(AgentRun.status == status)
    return list(session.scalars(stmt.order_by(AgentRun.created_at.desc()).limit(max(1, min(limit, 1000)))))


def agent_run_decisions(row: AgentRun) -> list[dict[str, Any]]:
    raw = _json_loads(row.decisions_json, [])
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


class DecisionConflict(ValueError):
    """A decision has changed, was consumed, or needs execution reconciliation."""


def claim_decision(
    session: Session,
    row: AgentRun,
    *,
    decision_index: int,
    actor: str,
    rejection_reason: str | None = None,
) -> None:
    """Compare-and-swap the reviewed payload and commit before any side effect.

    Serialize decisions within one run as their state is stored together. This
    also prevents a later completion from overwriting another decision's claim.
    """
    before = row.decisions_json
    previous_state = row.state_json
    decisions = agent_run_decisions(row)
    if (
        not 0 <= decision_index < len(decisions)
        or decisions[decision_index].get("status") != "proposed"
        or any(item.get("status") == "executing" for item in decisions)
    ):
        raise DecisionConflict("decision is unavailable or needs reconciliation")
    decision = dict(decisions[decision_index])
    moment = _now(None).isoformat()
    if rejection_reason is None:
        decision.update(status="executing", approved_by=actor, approved_at=moment)
    else:
        decision.update(status="rejected", rejected_by=actor, rejected_at=moment, rejection_reason=rejection_reason)
    decisions[decision_index] = decision
    state = _json_loads(previous_state, None)
    if not isinstance(state, dict):
        raise DecisionConflict("agent run state is invalid")
    state["decisions"] = decisions
    result = session.execute(
        update(AgentRun)
        .where(
            AgentRun.id == row.id,
            AgentRun.tenant_id == row.tenant_id,
            AgentRun.decisions_json == before,
            AgentRun.state_json == previous_state,
            AgentRun.status == "completed",
        )
        .values(decisions_json=_json_dumps(decisions), state_json=_json_dumps(state))
        .execution_options(synchronize_session=False)
    )
    if cast(CursorResult[Any], result).rowcount != 1:
        session.rollback()
        raise DecisionConflict("agent decision changed before it could be claimed")
    session.commit()
    session.refresh(row)


def mark_decision_executed(
    row: AgentRun,
    *,
    decision_index: int,
    approved_by: str,
    execution_result: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    decisions = agent_run_decisions(row)
    if decision_index < 0 or decision_index >= len(decisions):
        raise IndexError("decision not found")
    moment = _now(now)
    decision = dict(decisions[decision_index])
    decision.update(
        {
            "status": "executed",
            "approved_by": approved_by,
            "approved_at": moment.isoformat(),
            "execution_result": execution_result,
        }
    )
    decisions[decision_index] = decision
    state = _json_loads(row.state_json, {})
    if isinstance(state, dict):
        state["decisions"] = decisions
        row.state_json = _json_dumps(state)
    row.decisions_json = _json_dumps(decisions)
    return decision


def mark_decision_rejected(
    row: AgentRun,
    *,
    decision_index: int,
    rejected_by: str,
    reason: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    decisions = agent_run_decisions(row)
    if decision_index < 0 or decision_index >= len(decisions):
        raise IndexError("decision not found")
    moment = _now(now)
    decision = dict(decisions[decision_index])
    decision.update(
        {
            "status": "rejected",
            "rejected_by": rejected_by,
            "rejected_at": moment.isoformat(),
            "rejection_reason": reason,
        }
    )
    decisions[decision_index] = decision
    state = _json_loads(row.state_json, {})
    if isinstance(state, dict):
        state["decisions"] = decisions
        row.state_json = _json_dumps(state)
    row.decisions_json = _json_dumps(decisions)
    return decision


def run_and_persist_agent(
    session: Session,
    *,
    tenant_id: str,
    lake_dir: Path,
    harness: str,
    objective: str,
    role: str,
    created_by: str,
    created_by_id: str | None = None,
    idempotency_key: str | None = None,
    provider: ModelProviderConfig | None = None,
    budget: AgentBudgetPolicy | None = None,
    orchestrator: str = "sequential",
    now: datetime | None = None,
) -> tuple[AgentRun, bool]:
    """Run a harness and persist the sanitized result.

    Returns ``(row, created)``. When ``idempotency_key`` is supplied and already
    exists for the tenant, the previous row is returned without rerunning.
    """
    if harness not in AGENT_RUN_HARNESSES:
        raise ValueError(f"harness must be one of {list(AGENT_RUN_HARNESSES)}, got {harness!r}")
    if orchestrator not in {"sequential", "langgraph"}:
        raise ValueError("orchestrator must be 'sequential' or 'langgraph'")
    if orchestrator == "langgraph" and importlib.util.find_spec("langgraph") is None:
        raise ValueError("langgraph orchestrator requires trustops-security-data-lake[agents]")
    safe_orchestrator: AgentOrchestrator = "langgraph" if orchestrator == "langgraph" else "sequential"
    checkpoint_thread_id = idempotency_key if safe_orchestrator == "langgraph" and idempotency_key else None
    if idempotency_key:
        existing = get_agent_run_by_idempotency_key(session, tenant_id=tenant_id, idempotency_key=idempotency_key)
        if existing is not None:
            return existing, False

    provider = provider or provider_from_env()
    budget = budget or AgentBudgetPolicy.from_env()
    moment = _now(now)
    input_payload = {
        "harness": harness,
        "objective": objective,
        "role": role,
        "provider": provider.public_dict(),
        "budget": budget.public_dict(),
        "orchestrator": safe_orchestrator,
    }
    safe_lake = lake_dir.resolve()
    if not safe_lake.exists() or not safe_lake.is_dir():
        raise ValueError("agent run lake path must be an existing directory")
    status = "completed"
    try:
        if harness == "posture_review":
            state = dict(
                run_posture_review(
                    safe_lake,
                    role=role,
                    objective=objective,
                    provider=provider,
                    budget=budget,
                    orchestrator=safe_orchestrator,
                    checkpoint_thread_id=checkpoint_thread_id,
                )
            )
        else:
            state = dict(
                run_soc_triage(
                    safe_lake,
                    role=role,
                    objective=objective,
                    provider=provider,
                    budget=budget,
                    orchestrator=safe_orchestrator,
                    checkpoint_thread_id=checkpoint_thread_id,
                )
            )
    except Exception as exc:  # noqa: BLE001 - persisted failure must be generic and inspectable
        status = "failed"
        state = {
            "role": role,
            "mode": "rules_only",
            "orchestrator": safe_orchestrator,
            "objective": objective,
            "model_provider": provider.public_dict(),
            "agent_budget": budget.public_dict(),
            "data_readiness": {"status": "unknown", "next_action": "inspect_harness_error"},
            "decisions": [],
            "errors": [f"harness_error: {type(exc).__name__}"],
            "evaluation": {
                "ok": False,
                "score": 0,
                "confidence": "low",
                "risk_level": "high",
                "checks": [],
                "failures": [{"check": "harness_completed", "passed": False}],
                "coverage": {"harness": harness},
            },
        }
    if status not in AGENT_RUN_STATUSES:
        raise AssertionError("invalid agent run status")
    clean = _state_for_storage(state)
    row = AgentRun(
        tenant_id=tenant_id,
        harness=harness,
        objective=objective,
        role=role,
        mode=str(clean.get("mode") or "rules_only"),
        status=status,
        idempotency_key=idempotency_key or None,
        input_hash=_input_hash(input_payload),
        provider_json=_json_dumps(clean.get("model_provider") or provider.public_dict()),
        budget_json=_json_dumps(clean.get("agent_budget") or budget.public_dict()),
        evaluation_json=_json_dumps(clean.get("evaluation") or {}),
        decisions_json=_json_dumps(clean.get("decisions") or []),
        state_json=_json_dumps(clean),
        errors_json=_json_dumps(clean.get("errors") or []),
        created_by=created_by,
        created_by_id=created_by_id,
        created_at=moment,
        completed_at=moment,
    )
    session.add(row)
    session.flush()
    return row, True


def agent_run_to_dict(row: AgentRun, *, include_state: bool = False) -> dict[str, Any]:
    data = {
        "id": row.id,
        "harness": row.harness,
        "objective": row.objective,
        "role": row.role,
        "mode": row.mode,
        "status": row.status,
        "idempotency_key": row.idempotency_key,
        "input_hash": row.input_hash,
        "provider": _json_loads(row.provider_json, {}),
        "budget": _json_loads(row.budget_json, {}),
        "evaluation": _json_loads(row.evaluation_json, {}),
        "decisions": _json_loads(row.decisions_json, []),
        "errors": _json_loads(row.errors_json, []),
        "created_by": row.created_by,
        "created_by_id": row.created_by_id,
        "created_at": _iso(row.created_at),
        "completed_at": _iso(row.completed_at),
    }
    if include_state:
        data["state"] = _json_loads(row.state_json, {})
    return data


__all__ = [
    "agent_run_to_dict",
    "agent_run_decisions",
    "get_agent_run",
    "get_agent_run_by_idempotency_key",
    "list_agent_runs",
    "mark_decision_executed",
    "run_and_persist_agent",
]
