"""LangGraph checkpoint helpers for resumable harness orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def memory_checkpointer() -> Any:
    """Return a process-local MemorySaver checkpointer."""
    try:
        from langgraph.checkpoint.memory import MemorySaver
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError("install grc-lake[agents] to use LangGraph checkpoints") from exc
    return MemorySaver()


def run_config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}}


def checkpoint_state(compiled: Any, thread_id: str) -> dict[str, Any] | None:
    """Return the latest checkpointed harness state for ``thread_id``, if any."""
    snapshot = compiled.get_state(run_config(thread_id))
    values = getattr(snapshot, "values", None)
    if isinstance(values, dict) and values:
        return dict(values)
    return None


def invoke_with_checkpoint(
    compiled: Any,
    state: Mapping[str, Any],
    *,
    thread_id: str | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    """Invoke a compiled LangGraph, optionally checkpointing by ``thread_id``.

    The optional model step stays outside the graph; checkpoints only cover
    deterministic GRC Lake tool nodes.
    """
    if not thread_id:
        return dict(compiled.invoke(state))
    config = run_config(thread_id)
    if resume and checkpoint_state(compiled, thread_id) is not None:
        result = compiled.invoke(None, config)
        return dict(result) if isinstance(result, dict) else dict(state)
    result = compiled.invoke(state, config)
    return dict(result)
