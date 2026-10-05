"""Canonical evidence states shared by import, evaluation, and projections."""

FAIL_STATUSES = frozenset({"open", "failed", "blocked", "noncompliant"})
PASS_STATUSES = frozenset({"pass", "passed", "resolved", "closed", "compliant"})
_ALIASES = {
    "fail": "failed",
    "failing": "failed",
    "non-compliant": "noncompliant",
    "ok": "pass",
    "ready": "pass",
}


def normalize_event_status(value: object) -> str:
    """Unknown source outcomes remain unevaluated, never successful evidence."""
    text = str(value).strip().lower()
    text = _ALIASES.get(text, text)
    return text if text in FAIL_STATUSES | PASS_STATUSES | {"observed"} else "not_evaluated"
