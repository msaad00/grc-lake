"""Closed verdict, event-status and severity vocabularies stay byte-compatible."""

from __future__ import annotations

import json
from typing import Any

import pytest

from security_lakehouse.ccf_evaluation import _combine
from security_lakehouse.control_verdict import evaluate_evidence_verdict
from security_lakehouse.event_status import FAIL_STATUSES, PASS_STATUSES, normalize_event_status
from security_lakehouse.ledger import canonical_record_hash
from security_lakehouse.models import SEVERITY_SCORE
from security_lakehouse.policy import SEVERITY_ORDER, ControlContext, evaluate_control
from security_lakehouse.repo_governance import _findings_severity
from security_lakehouse.validation import VALID_SEVERITIES, validate_raw_event
from security_lakehouse.vocabulary import ControlVerdict, EventStatus, Severity


def _exact_str_keys(mapping: dict[str, Any]) -> bool:
    return all(type(key) is str for key in mapping)


def test_control_verdict_is_the_rule_aware_verdict_set() -> None:
    assert [verdict.value for verdict in ControlVerdict] == ["pass", "fail", "stale", "not_evaluated"]
    assert ControlVerdict.NOT_EVALUATED == "not_evaluated"


def test_event_status_is_the_normalized_closed_set() -> None:
    assert {status.value for status in EventStatus} == FAIL_STATUSES | PASS_STATUSES | {"observed", "not_evaluated"}
    assert frozenset({"open", "failed", "blocked", "noncompliant"}) == FAIL_STATUSES
    assert frozenset({"pass", "passed", "resolved", "closed", "compliant"}) == PASS_STATUSES
    assert all(type(value) is str for value in FAIL_STATUSES | PASS_STATUSES)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("open", "open"),
        (" FAIL ", "failed"),
        ("failing", "failed"),
        ("non-compliant", "noncompliant"),
        ("ok", "pass"),
        ("ready", "pass"),
        ("Resolved", "resolved"),
        ("observed", "observed"),
        ("unknown", "not_evaluated"),
        (None, "not_evaluated"),
        (3, "not_evaluated"),
        (EventStatus.CLOSED, "closed"),
    ],
)
def test_normalize_event_status_returns_plain_strings(raw: object, expected: str) -> None:
    result = normalize_event_status(raw)
    assert result == expected
    assert type(result) is str


def test_severity_has_one_canonical_order() -> None:
    assert [severity.value for severity in Severity] == ["none", "info", "low", "medium", "high", "critical"]
    assert SEVERITY_ORDER == {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    assert list(SEVERITY_ORDER) == ["info", "low", "medium", "high", "critical"]
    assert _exact_str_keys(SEVERITY_ORDER)
    assert SEVERITY_SCORE == {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5, "none": 0}
    assert list(SEVERITY_SCORE) == ["critical", "high", "medium", "low", "info", "none"]
    assert _exact_str_keys(SEVERITY_SCORE)
    assert set(SEVERITY_SCORE) == {severity.value for severity in Severity}
    assert {"critical", "high", "medium", "low", "info", "none"} == VALID_SEVERITIES
    assert all(type(value) is str for value in VALID_SEVERITIES)


def test_invalid_severity_message_is_unchanged() -> None:
    errors = validate_raw_event(
        {
            "event_id": "e1",
            "tenant_id": "t",
            "event_time": "2026-05-20T10:00:00Z",
            "source": "s",
            "event_type": "x",
            "entity": {"asset_id": "a", "asset_type": "host"},
            "severity": "urgent",
        }
    )
    assert "severity must be one of ['critical', 'high', 'info', 'low', 'medium', 'none']" in errors


@pytest.mark.parametrize(
    ("levels", "expected"),
    [
        ([], "info"),
        (["low", "medium"], "medium"),
        (["critical", "high"], "critical"),
        (["bogus", "low"], "low"),
    ],
)
def test_repo_governance_findings_severity_uses_canonical_order(levels: list[str], expected: str) -> None:
    payload = {"code_scanning": [{"state": "open", "rule": {"security_severity_level": level}} for level in levels]}
    result = _findings_severity(payload)
    assert result == expected
    assert type(result) is str


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], "not_evaluated"),
        (["pass", "fail"], "fail"),
        (["pass", "not_evaluated"], "not_evaluated"),
        (["pass", "stale"], "stale"),
        (["pass"], "pass"),
    ],
)
def test_ccf_combine_returns_plain_verdicts(statuses: list[str], expected: str) -> None:
    result = _combine(statuses)
    assert result == expected
    assert type(result) is str


def _row(status: str, *, severity: str = "high", evidence: bool = True) -> dict[str, Any]:
    return {
        "status": status,
        "severity": severity,
        "severity_score": SEVERITY_SCORE[severity],
        "evidence_ref": "ref" if evidence else None,
    }


@pytest.mark.parametrize(
    ("rows", "stale", "expected"),
    [
        ([_row("open")], False, "fail"),
        ([_row("passed")], False, "pass"),
        ([_row("passed")], True, "stale"),
        ([_row("passed", evidence=False)], False, "fail"),
        ([_row("mystery")], False, "not_evaluated"),
        ([_row("observed")], False, "not_evaluated"),
        ([], False, "not_evaluated"),
    ],
)
def test_evidence_verdict_status_stays_plain_string(rows: list[dict[str, Any]], stale: bool, expected: str) -> None:
    result = evaluate_evidence_verdict("CTRL-1", rows, "fail_when_missing_evidence", stale=stale)
    assert result.status == expected
    assert type(result.status) is str


def test_policy_rule_results_are_plain_strings() -> None:
    passed = evaluate_control(ControlContext(control_id="C"), "fail_when_open_violation")
    failed = evaluate_control(
        ControlContext(control_id="C", open_violation_count=1, max_severity="critical"), "fail_when_high_severity_open"
    )
    assert (passed.status, failed.status) == ("pass", "fail")
    assert type(passed.status) is str and type(failed.status) is str


def test_str_enum_values_hash_identically_to_plain_strings() -> None:
    record = {"status": "not_evaluated", "severity": "high"}
    enum_record = {"status": ControlVerdict.NOT_EVALUATED, "severity": Severity.HIGH}
    assert json.dumps(enum_record, sort_keys=True) == json.dumps(record, sort_keys=True)
    assert canonical_record_hash(enum_record) == canonical_record_hash(record)
