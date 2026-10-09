"""Canonical evidence states shared by import, evaluation, and projections."""

from security_lakehouse.vocabulary import EventStatus

FAIL_STATUSES = frozenset(
    status.value for status in (EventStatus.OPEN, EventStatus.FAILED, EventStatus.BLOCKED, EventStatus.NONCOMPLIANT)
)
PASS_STATUSES = frozenset(
    status.value
    for status in (
        EventStatus.PASS,
        EventStatus.PASSED,
        EventStatus.RESOLVED,
        EventStatus.CLOSED,
        EventStatus.COMPLIANT,
    )
)
_KNOWN_STATUSES = frozenset(status.value for status in EventStatus)
_ALIASES = {
    "fail": EventStatus.FAILED.value,
    "failing": EventStatus.FAILED.value,
    "non-compliant": EventStatus.NONCOMPLIANT.value,
    "ok": EventStatus.PASS.value,
    "ready": EventStatus.PASS.value,
}


def normalize_event_status(value: object) -> str:
    """Unknown source outcomes remain unevaluated, never successful evidence."""
    text = str(value).strip().lower()
    text = _ALIASES.get(text, text)
    return text if text in _KNOWN_STATUSES else EventStatus.NOT_EVALUATED.value
