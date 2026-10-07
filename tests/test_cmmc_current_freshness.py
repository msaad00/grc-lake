"""Persisted CMMC passes must retain current source evidence to close POA&M."""

from datetime import UTC, datetime, timedelta

import pytest

from security_lakehouse import assessment, evidence_freshness
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.server_app import create_app
from security_lakehouse.services import poam
from security_lakehouse.sprs import CMMC_FRAMEWORK_ID, evaluate_cmmc_posture
from test_assurance_truth import event

CONTROL = "CMMC-3.1.1"


def source(status="pass", **extra):
    now = datetime.now(UTC).isoformat()
    return {
        "event_id": "current",
        "tenant_id": "audit",
        "source": "fixture",
        "asset_id": "account",
        "event_type": "iam.access_review",
        "control_ids": [CONTROL],
        "status": status,
        "event_time": now,
        "evidence_collected_at": now,
        "evidence_ref": "fixture://current",
        **extra,
    }


def gold(result="pass", **extra):
    return {"framework_id": CMMC_FRAMEWORK_ID, "control_id": CONTROL, "result": result, **extra}


def test_pipeline_pass_cannot_close_poam_after_source_evidence_expires(tmp_path, monkeypatch):
    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, [{**event(), "controls": [CONTROL]}])
    run_pipeline(raw, lake, tenant_id="audit")
    assert read_jsonl(lake / "gold/control_tests.jsonl")[0]["result"] == "pass"
    assert evaluate_cmmc_posture(lake)[1]["3.1.1"] == "pass"
    later = datetime.now(UTC) + timedelta(days=30)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return later if tz else later.replace(tzinfo=None)

    monkeypatch.setattr(assessment, "datetime", Clock)
    monkeypatch.setattr(evidence_freshness, "datetime", Clock)
    assert assessment.build_current_posture(lake)["posture"]["score"] == 0
    report, outcomes = evaluate_cmmc_posture(lake)
    assert report["requirements_met"] == 0
    assert outcomes["3.1.1"] == "not_evaluated"
    app = create_app(lake)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="audit", name="Audit")
        other = create_tenant(session, slug="other", name="Other")
        item = poam.create_poam_item(
            session,
            tenant.id,
            requirement_id="3.1.1",
            control_id=CONTROL,
            title="Fixture",
            weakness="Previous failure",
            sprs_points=5,
        )
        poam.update_poam_item(session, tenant.id, item["id"], changes={"owner": "owner", "milestone": "retest"})
        for _ in range(2):
            assert poam.sync_poam_from_posture(session, tenant.id, lake)["closed"] == 0
        retained = poam.list_poam_items(session, tenant.id)[0]
        assert (retained["status"], retained["completed_at"], retained["owner"], retained["milestone"]) == (
            "open",
            None,
            "owner",
            "retest",
        )
        assert poam.list_poam_items(session, other.id) == []
        poam.update_poam_item(session, tenant.id, item["id"], changes={"status": "risk_accepted"})
        poam.sync_poam_from_posture(session, tenant.id, lake)
        assert poam.list_poam_items(session, tenant.id)[0]["status"] == "risk_accepted"


@pytest.mark.parametrize(
    "kind", ["missing", "stale", "future", "unavailable", "observed", "unknown", "wrong_control", "required_type"]
)
def test_persisted_fresh_flag_does_not_replace_current_source_evidence(tmp_path, kind):
    row = source()
    test = gold(freshness_status="fresh")
    if kind == "stale":
        row["evidence_collected_at"] = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    elif kind == "future":
        row["evidence_collected_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif kind == "unavailable":
        row["evidence_available"] = False
    elif kind in {"observed", "unknown"}:
        row["status"] = kind
    elif kind == "wrong_control":
        row["control_ids"] = ["CMMC-3.1.2"]
    elif kind == "required_type":
        test["required_evidence_types"] = ["missing.required"]
    write_jsonl(tmp_path / "gold/control_tests.jsonl", [test])
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [] if kind == "missing" else [row])
    report, outcomes = evaluate_cmmc_posture(tmp_path)
    assert report["requirements_met"] == 0
    assert outcomes["3.1.1"] == "not_evaluated"


def test_fresh_pass_and_failure_precedence_survive_current_evidence_gate(tmp_path):
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [source()])
    write_jsonl(tmp_path / "gold/control_tests.jsonl", [gold()])
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "pass"
    write_jsonl(tmp_path / "gold/control_tests.jsonl", [gold(), gold("fail")])
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [])
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "fail"


def test_current_catalog_requirements_cannot_be_omitted_by_saved_test(tmp_path, monkeypatch):
    from security_lakehouse import sprs

    write_jsonl(tmp_path / "gold/control_tests.jsonl", [gold(required_evidence_types=[])])
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [source()])
    monkeypatch.setattr(
        sprs,
        "with_program_requirements",
        lambda catalog: {CONTROL: {"required_evidence_types": ["missing.current.requirement"]}},
    )
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "not_evaluated"


def test_connector_freshness_and_source_populations_remain_effective(tmp_path, monkeypatch):
    from security_lakehouse import sprs

    write_jsonl(tmp_path / "gold/control_tests.jsonl", [gold()])
    monkeypatch.setattr(sprs, "load_connector_catalog", lambda: {"fixture": {"freshness_slo_minutes": 5}})
    old = source(evidence_collected_at=(datetime.now(UTC) - timedelta(minutes=20)).isoformat())
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [old])
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "not_evaluated"
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [old, source(event_id="new")])
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "pass"
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", [old, source(event_id="new", tenant_id="other")])
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "not_evaluated"


def test_observation_cannot_supply_attachment_for_a_passing_verdict(tmp_path):
    write_jsonl(tmp_path / "gold/control_tests.jsonl", [gold()])
    write_jsonl(
        tmp_path / "silver/normalized_events.jsonl",
        [
            source(evidence_ref=""),
            source("observed", event_id="activity"),
        ],
    )
    assert evaluate_cmmc_posture(tmp_path)[1]["3.1.1"] == "not_evaluated"


@pytest.mark.parametrize("consumer", ["report", "poam"])
def test_cmmc_reader_pins_gold_and_source_across_publication(tmp_path, monkeypatch, consumer):
    from security_lakehouse import sprs
    from security_lakehouse.generations import active_generation

    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, [{**event(), "controls": [CONTROL]}])
    run_pipeline(raw, lake, tenant_id="audit")
    first_generation = active_generation(lake)
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, [{**event("fail"), "controls": [CONTROL]}])
    original_read = sprs.read_jsonl
    switched = False

    def publish_between_reads(path, **kwargs):
        nonlocal switched
        rows = original_read(path, **kwargs)
        if not switched and path.name == "control_tests.jsonl":
            switched = True
            run_pipeline(changed, lake, tenant_id="audit")
        return rows

    monkeypatch.setattr(sprs, "read_jsonl", publish_between_reads)
    if consumer == "report":
        report, outcomes = sprs.evaluate_cmmc_posture(lake)
        assert report["requirements_met"] == 1
        assert outcomes["3.1.1"] == "pass"
    else:
        app = create_app(lake)
        with session_scope(app.state.sessionmaker) as session:
            tenant = create_tenant(session, slug="audit", name="Audit")
            poam.create_poam_item(
                session,
                tenant.id,
                requirement_id="3.1.1",
                control_id=CONTROL,
                title="Fixture",
                weakness="Previous failure",
                sprs_points=5,
            )
            assert poam.sync_poam_from_posture(session, tenant.id, lake)["closed"] == 1
            assert poam.sync_poam_from_posture(session, tenant.id, lake)["updated"] == 1
            assert poam.list_poam_items(session, tenant.id)[0]["status"] == "open"
    assert switched
    assert active_generation(lake) != first_generation
    assert sprs.evaluate_cmmc_posture(lake)[1]["3.1.1"] == "fail"
