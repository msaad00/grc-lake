"""Token and context budgets for optional model-assisted harness runs."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from security_lakehouse.runtime_environment import runtime_env


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = runtime_env().get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


@dataclass(frozen=True)
class AgentBudgetPolicy:
    """Bound how much context an optional model can receive."""

    max_context_chars: int = 12_000
    max_fact_items: int = 20
    max_output_tokens: int = 600
    max_string_chars: int = 1_000

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_context_chars", max(256, min(int(self.max_context_chars), 200_000)))
        object.__setattr__(self, "max_fact_items", max(1, min(int(self.max_fact_items), 250)))
        object.__setattr__(self, "max_output_tokens", max(64, min(int(self.max_output_tokens), 8_000)))
        object.__setattr__(self, "max_string_chars", max(128, min(int(self.max_string_chars), 16_000)))

    @classmethod
    def from_env(cls) -> AgentBudgetPolicy:
        """Load bounded budget knobs from environment."""
        return cls(
            max_context_chars=_env_int("GRC_LAKE_AGENT_MAX_CONTEXT_CHARS", 12_000, minimum=1_000, maximum=200_000),
            max_fact_items=_env_int("GRC_LAKE_AGENT_MAX_FACT_ITEMS", 20, minimum=1, maximum=250),
            max_output_tokens=_env_int("GRC_LAKE_AGENT_MAX_OUTPUT_TOKENS", 600, minimum=64, maximum=8_000),
            max_string_chars=_env_int("GRC_LAKE_AGENT_MAX_STRING_CHARS", 1_000, minimum=128, maximum=16_000),
        )

    def public_dict(self) -> dict[str, int | str]:
        """Return non-secret budget policy metadata for audit output."""
        return {
            "profile": "small_context_default",
            "max_context_chars": self.max_context_chars,
            "max_fact_items": self.max_fact_items,
            "max_output_tokens": self.max_output_tokens,
            "max_string_chars": self.max_string_chars,
        }


def estimate_tokens(payload: Any) -> int:
    """Estimate model input tokens without provider-specific tokenizers."""
    chars = len(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))
    return max(1, (chars + 3) // 4)


def apply_budget(context: dict[str, Any], policy: AgentBudgetPolicy) -> dict[str, Any]:
    """Return a compacted model context with budget telemetry attached."""
    original_chars = _context_chars(context)
    original_tokens = estimate_tokens(context)
    for item_limit in _candidate_limits(policy.max_fact_items):
        candidate = deepcopy(context)
        omitted: dict[str, int] = {}
        _limit_fact_lists(candidate, item_limit=item_limit, omitted=omitted)
        _truncate_strings(candidate, max_chars=policy.max_string_chars, omitted=omitted)
        candidate["budget"] = {
            **policy.public_dict(),
            "status": "checking",
            "estimated_context_chars_before": original_chars,
            "estimated_context_tokens_before": original_tokens,
            "estimated_context_chars": 0,
            "estimated_context_tokens": 0,
            "fact_item_limit_applied": item_limit,
            "truncated": bool(omitted),
            "omitted": omitted,
        }
        compacted_chars = _context_chars(candidate)
        if compacted_chars <= policy.max_context_chars or item_limit == 1:
            status = "within_budget" if compacted_chars <= policy.max_context_chars else "over_budget"
            candidate["budget"] = {
                **policy.public_dict(),
                "status": status,
                "estimated_context_chars_before": original_chars,
                "estimated_context_tokens_before": original_tokens,
                "estimated_context_chars": compacted_chars,
                "estimated_context_tokens": estimate_tokens(candidate),
                "fact_item_limit_applied": item_limit,
                "truncated": bool(omitted),
                "omitted": omitted,
            }
            return candidate
    raise AssertionError("candidate limits always return at least one policy")


def _candidate_limits(max_items: int) -> list[int]:
    limits: list[int] = []
    current = max(1, max_items)
    while current not in limits:
        limits.append(current)
        if current == 1:
            break
        current = max(1, current // 2)
    return limits


def _context_chars(payload: Any) -> int:
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))


def _limit_fact_lists(context: dict[str, Any], *, item_limit: int, omitted: dict[str, int]) -> None:
    facts = context.get("facts")
    if not isinstance(facts, dict):
        return
    for key in ("evidence_gaps", "alerts", "deterministic_decisions"):
        value = facts.get(key)
        if not isinstance(value, list) or len(value) <= item_limit:
            continue
        facts[key] = value[:item_limit]
        omitted[f"facts.{key}"] = len(value) - item_limit


def _truncate_strings(value: Any, *, max_chars: int, omitted: dict[str, int], path: str = "") -> Any:
    if isinstance(value, dict):
        for key, child in list(value.items()):
            child_path = f"{path}.{key}" if path else str(key)
            value[key] = _truncate_strings(child, max_chars=max_chars, omitted=omitted, path=child_path)
        return value
    if isinstance(value, list):
        for index, child in enumerate(list(value)):
            value[index] = _truncate_strings(child, max_chars=max_chars, omitted=omitted, path=f"{path}[{index}]")
        return value
    if isinstance(value, str) and len(value) > max_chars:
        omitted[path or "string"] = len(value) - max_chars
        return value[:max_chars] + "...[truncated]"
    return value
