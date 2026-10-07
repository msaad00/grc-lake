"""Reproductions for remaining evidence-integrity and collector contracts."""

import json
import urllib.error
from datetime import UTC, datetime

import pytest

from security_lakehouse import connectors_clickhouse, connectors_jira, mapping_review
from security_lakehouse.assessment import _framework_scores
from security_lakehouse.connectors_okta import _mfa_event, _safe_factors
from security_lakehouse.connectors_runtime import _raw_from_event
from security_lakehouse.controls import expand_controls
from security_lakehouse.oscal import build_assessment_results
from test_ccf_operational_assessment import assessment, normalized
from test_mapping_review import _decide, _item


def test_empty_legacy_posture_cannot_bypass_export_verification(tmp_path):
    (tmp_path / "gold").mkdir()
    (tmp_path / "gold/control_posture.jsonl").write_text("")
    with pytest.raises(ValueError, match="verified generation"):
        build_assessment_results(tmp_path)


def test_empty_signed_review_log_cannot_revert_to_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_MAPPING_REVIEW_SIGNING_KEY", "test-signing-key")
    # Use the actual configured variable below, independent of ambient configuration.
    monkeypatch.setattr(mapping_review, "_tip_key", lambda: b"test-key")
    _decide(tmp_path, "approve", _item("SG-A", "ISO27001-A.5.15", "iso-27001-2022"))
    mapping_review.review_log_path(tmp_path).write_text("")
    assert mapping_review.verify_review_log(tmp_path)["ok"] is False


def test_capped_score_uses_same_control_risk_as_uncapped():
    controls = [{"control_id": "C", "framework": "F", "status": "fail", "risk_score": 100, "open_event_count": 2}]
    controls.extend([{"control_id": c, "framework": "F", "status": "pass"} for c in ("A", "B")])
    details = [{"control_id": "C", "severity": "high", "severity_score": 70}] * 2
    assert (
        _framework_scores(controls, None, set())[0]["score"] == _framework_scores(controls, details, set())[0]["score"]
    )


def test_repeated_control_tags_do_not_double_count():
    assert len(expand_controls(["C", "C"], {"C": {"control_id": "C"}})) == 1


@pytest.mark.parametrize("kind", ["issues", "projects"])
def test_jira_page_limit_does_not_return_partial_success(monkeypatch, kind):
    monkeypatch.setattr(connectors_jira, "MAX_PAGES", 1)
    client = connectors_jira.JiraClient("https://example.test", email="a", token="test")
    monkeypatch.setattr(
        client, "_json", lambda url: {"issues": [{"id": "1"}], "values": [{"id": "1"}], "total": 2, "isLast": False}
    )
    with pytest.raises(ValueError, match="incomplete"):
        getattr(client, kind)()


def test_clickhouse_page_limit_does_not_return_partial_success(monkeypatch):
    monkeypatch.setattr(connectors_clickhouse, "MAX_PAGES", 1)
    client = connectors_clickhouse.ClickHouseClient("https://example.test", user="a")
    monkeypatch.setattr(
        client, "_query_json_each_row", lambda *a, **k: [{"event_id": "1", "event_time": "2026-10-06T00:00:00Z"}]
    )
    with pytest.raises(ValueError, match="incomplete"):
        client.normalized_events(page_size=1)


def test_factor_authorization_error_is_unknown_not_no_mfa():
    class Denied:
        def factors(self, user_id):
            raise urllib.error.HTTPError("https://example.test", 403, "denied", {}, None)

    assert _safe_factors(Denied(), "u") is None


def test_security_question_alone_does_not_establish_mfa():
    row = _mfa_event(
        "https://example.test",
        "org",
        "u",
        {"status": "ACTIVE"},
        [{"status": "ACTIVE", "factorType": "question"}],
        datetime.now(UTC),
        "tenant",
    )
    assert row["status"] == "open"


@pytest.mark.parametrize("status", ["blocked", "denied", "rejected"])
def test_runtime_enforcement_is_observation_not_failed_control(status):
    row = _raw_from_event(
        {"id": "1", "timestamp": "2026-10-06T00:00:00Z", "status": status},
        collected_at=datetime.now(UTC),
        tenant_id="t",
    )
    assert row["status"] == "observed"
    assert row["attributes"]["source_status"] == status


def test_unrelated_ambiguous_asset_does_not_block_every_safeguard():
    result = assessment(
        [
            normalized(),
            normalized("other", bindings=[], asset_type="database"),
            normalized("other", bindings=[], asset_type="bucket", event_id="other2"),
        ]
    )
    assert result["safeguards"][0]["status"] == "pass"


def test_aws_inventory_does_not_assert_control_pass():
    from security_lakehouse.connectors_aws import collect_aws_inventory_evidence

    class Client:
        def inventory(self, service, *, region_name):
            return [{"id": "resource", "multi_region": False}]

    rows = collect_aws_inventory_evidence(
        Client(), account_id="test", regions=["us-east-1"], services=["ec2", "cloudtrail"]
    )
    assert [r["status"] for r in rows] == ["observed", "open"]


def test_missing_evidence_rule_can_fail_without_losing_bronze_lineage(tmp_path):
    from security_lakehouse.pipeline import _build_control_rows, _silver_row
    from test_assurance_truth import event

    raw = event()
    raw["evidence"] = {}
    row = _silver_row(raw, "a" * 64)
    result = _build_control_rows(
        [row], {"SOC2-CC6.1": {"control_id": "SOC2-CC6.1", "evaluation_rule": "fail_when_missing_evidence"}}
    )
    assert row["evidence_ref"].startswith("trustops://bronze/")
    assert result[0]["status"] == "fail"


def test_legacy_external_snapshot_can_be_imported_without_rewriting_ledger(tmp_path):
    from security_lakehouse import assessment, evidence_migration
    from test_api_v1 import _seed_lake

    lake = tmp_path / "lake"
    lake.mkdir()
    _seed_lake(lake)
    path = assessment.write_assessment_snapshot(lake)
    external = tmp_path / "old-exports"
    external.mkdir()
    path.rename(external / path.name)
    ledger = assessment._ledger_path(lake).read_bytes()
    assert not assessment.verify_snapshot_chain(lake)["ok"]
    assert evidence_migration.restore_snapshot_files(lake, external)["restored"] == 1
    assert assessment.verify_snapshot_chain(lake)["ok"]
    assert assessment._ledger_path(lake).read_bytes() == ledger


def test_resealed_evidence_does_not_match_external_checkpoint(tmp_path):
    from security_lakehouse import evidence_migration
    from security_lakehouse.io import write_jsonl
    from security_lakehouse.pipeline import run_pipeline
    from test_assurance_truth import event

    raw = tmp_path / "raw.jsonl"
    lake = tmp_path / "lake"
    write_jsonl(raw, [event()])
    run_pipeline(raw, lake)
    anchor = evidence_migration.integrity_checkpoint(lake)
    write_jsonl(raw, [{**event(), "status": "fail"}])
    run_pipeline(raw, lake)
    assert evidence_migration.verify_checkpoint(lake, anchor)["ok"] is False


def test_mapping_decision_is_bound_to_control_definition(tmp_path, monkeypatch):
    from copy import deepcopy

    from test_mapping_review import _PAYLOAD

    catalog = {"ISO27001-A.5.15": {"control_id": "ISO27001-A.5.15", "version": "1.0.0", "title": "Original"}}
    monkeypatch.setattr(mapping_review, "load_control_catalog", lambda: catalog)
    _decide(tmp_path, "approve", _item("SG-A", "ISO27001-A.5.15", "iso-27001-2022"))
    catalog["ISO27001-A.5.15"]["version"] = "2.0.0"
    data = mapping_review.effective_safeguards(tmp_path, payload=deepcopy(_PAYLOAD))
    member = data["safeguards"][0]["satisfies"][1]
    assert member["effective_review_state"] == "proposed"


def test_manifest_unknown_fields_are_not_accepted_after_resealing(tmp_path):
    from security_lakehouse.generations import active_generation
    from security_lakehouse.io import canonical_sha256, write_jsonl
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.verification import verify_lake_integrity
    from test_assurance_truth import event

    raw = tmp_path / "raw.jsonl"
    lake = tmp_path / "lake"
    write_jsonl(raw, [event()])
    run_pipeline(raw, lake)
    path = active_generation(lake) / "gold/evidence_integrity.json"
    data = json.loads(path.read_text())
    data["authenticated"] = True
    data["manifest_sha256"] = canonical_sha256({k: v for k, v in data.items() if k != "manifest_sha256"})
    path.write_text(json.dumps(data))
    generation = active_generation(lake)
    seal = json.loads((generation / "generation.json").read_text())
    from security_lakehouse.io import file_sha256

    seal["artifacts"]["gold/evidence_integrity.json"] = file_sha256(path)
    (generation / "generation.json").write_text(json.dumps(seal))
    assert verify_lake_integrity(lake)["ok"] is False


@pytest.mark.parametrize("scenario", ["reopened", "partial", "regressed"])
def test_remediation_requires_new_complete_evidence_and_reopens_regressions(tmp_path, scenario):
    from datetime import timedelta

    from security_lakehouse.db import remediation
    from security_lakehouse.db.base import session_scope
    from security_lakehouse.db.repository import create_tenant
    from security_lakehouse.io import write_jsonl
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.remediation_verification import verify_task
    from security_lakehouse.server_app import create_app

    app = create_app(tmp_path)
    now = datetime.now(UTC)
    from pathlib import Path

    raw = json.loads(Path("data/raw/security_events.jsonl").read_text().splitlines()[0])
    raw["status"] = "pass"
    raw["severity"] = "info"
    raw["event_time"] = (now - timedelta(minutes=1)).isoformat()
    raw["evidence"]["collected_at"] = raw["event_time"]
    source = tmp_path / "input.jsonl"
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="t", name="Test")
        task = remediation.create_task(session, tenant_id=tenant.id, title="Fix", control_id="HIPAA-164.308(a)(4)")
        task.created_at = now - timedelta(minutes=5)
        session.commit()
        rows = [raw]
        if scenario == "partial":
            rows.append({**raw, "event_id": "gap", "controls": [], "attributes": {"collection_gap": True}})
        write_jsonl(source, rows)
        run_pipeline(source, tmp_path, tenant_id=tenant.id)

        def verify():
            return verify_task(
                session,
                tmp_path,
                tenant_id=tenant.id,
                task_id=task.id,
                reviewer_id="r",
                reviewer="r@example.test",
                now=now,
            )

        if scenario == "partial":
            with pytest.raises(ValueError, match="partial"):
                verify()
        else:
            verify()
            session.commit()
            if scenario == "reopened":
                remediation.update_task(
                    session, tenant_id=tenant.id, task_id=task.id, changes={"status": "open"}, now=now
                )
                with pytest.raises(ValueError, match="new|retest"):
                    verify()
            else:
                write_jsonl(source, [{**raw, "status": "failed", "severity": "high"}])
                run_pipeline(source, tmp_path, tenant_id=tenant.id)
                session.expire_all()
                assert remediation.get_task(session, tenant_id=tenant.id, task_id=task.id).status == "open"


def test_connector_bindings_are_explicit_and_apply_only_to_matching_types():
    from security_lakehouse.connector_runner import bind_safeguard_evidence
    from test_assurance_truth import event

    raw = event()
    assert "safeguard_ids" not in bind_safeguard_evidence([raw], {})[0]
    bound = bind_safeguard_evidence([raw], {"iam.access_review": ["SG-IDENTITY-001"]})
    assert bound[0]["safeguard_ids"] == ["SG-IDENTITY-001"]
    assert bind_safeguard_evidence([raw], {"another.type": ["SG-IDENTITY-001"]})[0].get("safeguard_ids", []) == []
    with pytest.raises(ValueError):
        bind_safeguard_evidence([raw], {"iam.access_review": ["UNKNOWN"]})


def test_baseline_label_and_compatibility_map_match_shipped_scope():
    from security_lakehouse.catalog import load_control_catalog
    from security_lakehouse.controls import DEFAULT_MAPPING_PATH

    catalog = load_control_catalog()
    assert all(
        row["framework"] == "NIST 800-53B Moderate"
        for row in catalog.values()
        if row.get("framework_id") == "fedramp-moderate"
    )
    assert {r["control_id"] for r in json.loads(DEFAULT_MAPPING_PATH.read_text())["controls"]} == set(catalog)


def test_reviewed_mapping_cannot_follow_a_different_control_version():
    from security_lakehouse.safeguards import effective_review_state

    assert (
        effective_review_state(
            {"review_status": "reviewed", "control_version": "1.0.0", "current_control_version": "2.0.0"}
        )
        == "proposed"
    )
    assert (
        effective_review_state(
            {"review_status": "reviewed", "control_version": "1.0.0", "current_control_version": "2.0.0"}, "approve"
        )
        == "org_reviewed"
    )


@pytest.mark.parametrize("change", [{"schema_version": "unknown"}, {"extra": True}, {"legacy": "false"}])
def test_generation_manifest_rejects_forged_fields(tmp_path, change):
    from security_lakehouse.generations import active_generation, verify_generation
    from security_lakehouse.io import write_jsonl
    from security_lakehouse.pipeline import run_pipeline
    from test_assurance_truth import event

    write_jsonl(tmp_path / "input.jsonl", [event()])
    run_pipeline(tmp_path / "input.jsonl", tmp_path)
    generation = active_generation(tmp_path)
    path = generation / "generation.json"
    manifest = json.loads(path.read_text())
    manifest.update(change)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="manifest"):
        verify_generation(generation)


@pytest.mark.parametrize("kind", ["issues", "projects"])
def test_jira_premature_empty_page_is_incomplete(monkeypatch, kind):
    client = connectors_jira.JiraClient("https://example.test", email="a", token="test")
    monkeypatch.setattr(client, "_json", lambda url: {"issues": [], "values": [], "total": 2, "isLast": False})
    with pytest.raises(ValueError, match="incomplete"):
        getattr(client, kind)()


def test_independent_checkpoint_detects_deleted_review_log_and_tip(tmp_path, monkeypatch):
    from security_lakehouse import evidence_migration
    from security_lakehouse.io import write_jsonl
    from security_lakehouse.pipeline import run_pipeline
    from test_assurance_truth import event

    lake = tmp_path / "lake"
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [event()])
    run_pipeline(raw, lake)
    monkeypatch.setattr(mapping_review, "_tip_key", lambda: b"test-key")
    _decide(lake, "approve", _item("SG-A", "ISO27001-A.5.15", "iso-27001-2022"))
    checkpoint = evidence_migration.integrity_checkpoint(lake)
    mapping_review.review_log_path(lake).unlink()
    mapping_review.review_tip_path(lake).unlink()
    # Absence alone cannot prove there used to be history. The independently
    # retained pre-deletion checkpoint supplies that missing fact.
    assert evidence_migration.verify_checkpoint(lake, checkpoint)["ok"] is False
