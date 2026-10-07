"""Identical rule inputs retain the same verdict across evaluation surfaces."""

from datetime import UTC, datetime, timedelta

import pytest

from security_lakehouse.ccf_evaluation import evaluate_safeguards
from security_lakehouse.event_status import PASS_STATUSES
from security_lakehouse.evidence_freshness import build_evidence_freshness, stale_control_ids
from security_lakehouse.pipeline import _build_control_rows
from test_ccf_operational_assessment import normalized

NOW = datetime(2026, 10, 6, tzinfo=UTC)


def row(status="pass", **kwargs):
    return normalized(status=status, event_time=NOW.isoformat(), evidence_collected_at=NOW.isoformat(), **kwargs)


def statuses(rows, rule="fail_when_open_violation"):
    definition = {"control_id": "REQ", "evaluation_rule": rule}
    controls = {"REQ": definition}
    stale = stale_control_ids(build_evidence_freshness(rows, now=NOW))
    control = _build_control_rows(rows, controls, stale)[0]
    payload = {
        "review_log_verified": True,
        "safeguards": [
            {
                "safeguard_id": "SG-0",
                "title": "Fixture",
                "asset_types": ["iam_role"],
                "evaluation_rule": rule,
                "satisfies": [{"control_id": "REQ", "effective_review_state": "maintainer_reviewed"}],
            }
        ],
    }
    ccf = evaluate_safeguards(rows, payload, controls, now=NOW)
    return control["status"], ccf["safeguards"][0]["status"]


@pytest.mark.parametrize("alias", sorted(PASS_STATUSES))
def test_passing_alias_with_observation_has_one_verdict(alias):
    assert statuses([row(alias), row("observed", event_id="activity")]) == ("pass", "pass")


@pytest.mark.parametrize(
    "status,expected", [("observed", "not_evaluated"), ("unknown", "not_evaluated"), ("open", "fail")]
)
def test_explicit_outcomes_and_observations_remain_distinct(status, expected):
    assert statuses([row(status)]) == (expected, expected)


def test_low_failure_respects_declared_severity_threshold():
    assert statuses([row("open", severity="low", severity_score=25)], "fail_when_high_severity_open") == (
        "pass",
        "pass",
    )


def test_bronze_pointer_is_not_available_source_evidence():
    assert statuses([row(evidence_available=False)], "fail_when_missing_evidence") == ("fail", "fail")


def test_observation_cannot_supply_verdict_evidence():
    assert statuses([row(evidence_ref=""), row("observed", event_id="activity")]) == ("stale", "stale")


def test_new_observation_supersedes_only_its_own_freshness_population():
    old = row(event_id="old")
    old["evidence_collected_at"] = (NOW - timedelta(days=30)).isoformat()
    assert statuses([old, row(event_id="new")]) == ("pass", "pass")
    assert statuses([old, row(asset="other", event_id="new")]) == ("stale", "stale")


def test_same_event_id_from_different_tenants_does_not_share_freshness():
    old = row(tenant_id="old-tenant")
    old["evidence_collected_at"] = (NOW - timedelta(days=30)).isoformat()
    assert statuses([old, row(tenant_id="new-tenant")]) == ("stale", "stale")


def test_future_evidence_cannot_pass():
    future = row()
    future["evidence_collected_at"] = (NOW + timedelta(minutes=1)).isoformat()
    assert statuses([future]) == ("stale", "stale")


def test_latest_unavailable_source_evidence_cannot_borrow_an_older_attachment():
    old = row(event_id="old")
    old["evidence_collected_at"] = (NOW - timedelta(minutes=1)).isoformat()
    assert statuses([old, row(event_id="new", evidence_available=False)]) == ("stale", "stale")
