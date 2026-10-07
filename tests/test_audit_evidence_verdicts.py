"""Passing aliases and unknown evidence must retain their intended meaning."""

import pytest

from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.event_status import PASS_STATUSES
from security_lakehouse.io import write_jsonl
from security_lakehouse.server_app import create_app
from security_lakehouse.services import poam
from security_lakehouse.sprs import CMMC_FRAMEWORK_ID, build_sprs_report
from test_cmmc_current_freshness import source
from test_control_assurance import case, evaluate


@pytest.mark.parametrize("status", sorted(PASS_STATUSES) + [" PASSED "])
def test_workpaper_pass_aliases_preserve_design_and_operating_result(tmp_path, status):
    plan, events = case(tmp_path)
    for event in events:
        event["status"] = status
    control = evaluate(tmp_path, plan, events)["controls"][0]
    assert control["design"]["status"] == "documented"
    assert control["operating"]["status"] == "sample_pass"
    assert control["conclusion"] == "pending_human_review"


@pytest.mark.parametrize("unknown", [None, "not_evaluated", "observed", "stale", "warn"])
def test_poam_only_closes_on_pass_and_reopens_completed_failures(tmp_path, unknown):
    app = create_app(tmp_path)
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [source()])

    def posture(result):
        write_jsonl(
            tmp_path / "gold/control_tests.jsonl",
            []
            if result is None
            else [{"framework_id": CMMC_FRAMEWORK_ID, "control_id": "CMMC-3.1.1", "result": result}],
        )

    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="first", name="First")
        other = create_tenant(session, slug="other", name="Other")
        posture("fail")
        assert poam.sync_poam_from_posture(session, tenant.id, tmp_path)["created"] == 1
        item = poam.list_poam_items(session, tenant.id)[0]
        poam.update_poam_item(session, tenant.id, item["id"], changes={"owner": "owner", "milestone": "retest"})
        posture(unknown)
        assert poam.sync_poam_from_posture(session, tenant.id, tmp_path)["closed"] == 0
        assert poam.list_poam_items(session, tenant.id)[0]["status"] == "open"
        posture("fail")
        assert poam.sync_poam_from_posture(session, tenant.id, tmp_path)["created"] == 0
        posture("pass")
        assert poam.sync_poam_from_posture(session, tenant.id, tmp_path)["closed"] == 1
        posture("fail")
        assert poam.sync_poam_from_posture(session, tenant.id, tmp_path)["updated"] == 1
        reopened = poam.list_poam_items(session, tenant.id)[0]
        assert (
            reopened["id"],
            reopened["status"],
            reopened["completed_at"],
            reopened["owner"],
            reopened["milestone"],
        ) == (item["id"], "open", None, "owner", "retest")
        assert poam.sync_poam_from_posture(session, tenant.id, tmp_path)["updated"] == 0
        assert poam.list_poam_items(session, other.id) == []
        poam.update_poam_item(session, tenant.id, item["id"], changes={"status": "risk_accepted"})
        poam.sync_poam_from_posture(session, tenant.id, tmp_path)
        assert poam.list_poam_items(session, tenant.id)[0]["status"] == "risk_accepted"


@pytest.mark.parametrize(
    "results,met,unmet", [(["pass"], 1, 0), (["pass", "warn"], 0, 0), (["pass", "fail"], 0, 1), (["stale"], 0, 0)]
)
def test_sprs_and_poam_share_requirement_precedence(tmp_path, results, met, unmet):
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [source()])
    write_jsonl(
        tmp_path / "gold/control_tests.jsonl",
        [{"framework_id": CMMC_FRAMEWORK_ID, "control_id": "CMMC-3.1.1", "result": result} for result in results],
    )
    report = build_sprs_report(tmp_path)
    assert report["requirements_met"] == met
    assert report["requirements_unmet"] == unmet
