"""Closed vocabularies for control verdicts, evidence statuses and severities.

Members are ``StrEnum`` values, so they compare and serialize as their plain
string values. Exported sets and maps hold plain ``str`` values so error
messages, sorted output and non-JSON serializers see exactly the same data.
"""

from __future__ import annotations

from enum import StrEnum


class ControlVerdict(StrEnum):
    """Rule-aware verdict for a control or explicit safeguard."""

    PASS = "pass"
    FAIL = "fail"
    STALE = "stale"
    NOT_EVALUATED = "not_evaluated"


class EventStatus(StrEnum):
    """Normalized evidence-event outcome (see ``event_status.normalize_event_status``)."""

    OPEN = "open"
    FAILED = "failed"
    BLOCKED = "blocked"
    NONCOMPLIANT = "noncompliant"
    PASS = "pass"
    PASSED = "passed"
    RESOLVED = "resolved"
    CLOSED = "closed"
    COMPLIANT = "compliant"
    OBSERVED = "observed"
    NOT_EVALUATED = "not_evaluated"


class Severity(StrEnum):
    """Event severity, declared from least to most severe."""

    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    severity.value: rank for rank, severity in enumerate(s for s in Severity if s is not Severity.NONE)
}

__all__ = ["SEVERITY_ORDER", "ControlVerdict", "EventStatus", "Severity"]
