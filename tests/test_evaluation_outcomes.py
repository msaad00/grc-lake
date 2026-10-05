"""An observation or empty dataset must not be counted as passing evidence."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_lakehouse.connectors_okta import OktaFixtureClient, collect_okta_system_log_evidence
from security_lakehouse.io import canonical_sha256, read_jsonl
from security_lakehouse.pipeline import _build_control_rows, _build_metrics, _silver_row

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"


def control(status, rule):
    raw = read_jsonl(RAW)[0]
    raw.update(status=status, controls=["TEST"], severity="low")
    silver = _silver_row(raw, canonical_sha256(raw))
    mapping = {"TEST": {"control_id": "TEST", "evaluation_rule": rule}}
    return _build_control_rows([silver], mapping)[0]


@pytest.mark.parametrize("status", ["observed", "not_evaluated", "provider-unknown"])
def test_observation_is_not_a_pass(status):
    assert control(status, "fail_when_open_violation")["status"] == "not_evaluated"


def test_high_severity_rule_retains_its_threshold():
    assert control("open", "fail_when_high_severity_open")["status"] == "pass"
    assert control("open", "fail_when_open_violation")["status"] == "fail"


def test_empty_dataset_has_no_passing_control_rate():
    assert _build_metrics([], [], [])["control_pass_rate"] == 0


def test_failed_authentication_is_an_observation_not_a_control_violation():
    fixture = Path(__file__).parent / "fixtures/okta-system-log"
    rows = collect_okta_system_log_evidence(OktaFixtureClient(fixture), collected_at=datetime(2026, 5, 28, tzinfo=UTC))
    failed = next(row for row in rows if row["attributes"]["outcome_result"] == "FAILURE")
    assert failed["status"] == "observed"
    assert failed["severity"] == "info"
    assert failed["attributes"]["outcome_result"] == "FAILURE"


def test_control_test_result_respects_evaluated_rule_threshold():
    from security_lakehouse.programs import _test_result

    evaluated = control("open", "fail_when_high_severity_open")
    event = {"status": "open", "severity": "low"}
    assert _test_result(evaluated, [event], [event], {"status": "fresh"}) == "pass"
