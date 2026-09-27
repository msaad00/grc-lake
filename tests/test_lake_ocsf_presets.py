"""Built-in OCSF mapping presets against realistic Amazon Security Lake rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_lakehouse.lake_mapping import (
    compile_select,
    list_presets,
    load_preset,
    map_rows,
    read_fixture_table,
    resolve_mapping_ref,
    resolve_mappings,
)
from security_lakehouse.validation import validate_raw_events

FIXTURES = Path(__file__).parent / "fixtures" / "ocsf"
REPO_ROOT = Path(__file__).resolve().parents[1]
COLLECTED = datetime(2026, 9, 22, tzinfo=UTC)
EXPECTED_PRESETS = {
    "ocsf/authentication": 3002,
    "ocsf/account_change": 3001,
    "ocsf/api_activity": 6003,
    "ocsf/detection_finding": 2004,
    "ocsf/vulnerability_finding": 2002,
    "ocsf/compliance_finding": 2003,
    "ocsf/security_finding": 2001,
}


def _preset(name: str, table: str = "amazon_security_lake_table_us_east_1_sh_findings_2_0"):
    return resolve_mapping_ref({"preset": name, "source": {"table": table}})


def _catalog_control_ids() -> set[str]:
    catalog = json.loads((REPO_ROOT / "controls" / "catalog.json").read_text(encoding="utf-8"))
    return {control["control_id"] for control in catalog["controls"]}


def test_every_expected_preset_ships_and_parses() -> None:
    assert set(list_presets()) == set(EXPECTED_PRESETS)
    for name, class_uid in EXPECTED_PRESETS.items():
        spec = _preset(name)
        assert spec.preset == name
        assert [(f.column, f.op, f.value) for f in spec.filters] == [("class_uid", "eq", class_uid)]
        assert "OCSF 1." in spec.description, "each preset must cite the OCSF version it targets"


def test_preset_control_hints_exist_in_the_control_catalog() -> None:
    known = _catalog_control_ids()
    for name in EXPECTED_PRESETS:
        controls = load_preset(name)["fields"]["controls"]["const"]
        assert controls, name
        assert set(controls) <= known, (name, set(controls) - known)


def test_cloudtrail_table_splits_into_the_three_activity_classes() -> None:
    rows = read_fixture_table(FIXTURES, "cloud_trail_mgmt_2_0")
    by_class = {}
    for name in ("ocsf/authentication", "ocsf/account_change", "ocsf/api_activity"):
        result = map_rows(_preset(name, "cloud_trail_mgmt_2_0"), rows, collected_at=COLLECTED)
        assert result.errors == []
        assert validate_raw_events(result.events) == []
        by_class[name] = result.events
    assert [len(events) for events in by_class.values()] == [1, 1, 1]

    [auth] = by_class["ocsf/authentication"]
    assert auth["event_type"] == "ocsf.authentication"
    assert auth["source"] == "CloudTrail"
    assert auth["event_time"] == "2026-09-21T14:03:11Z"
    assert auth["entity"]["asset_id"] == "AIDAEXAMPLEALICE"
    # a failed sign-in is activity evidence, not a control failure
    assert auth["status"] == "observed"
    assert auth["attributes"]["outcome"] == "Failure"
    assert auth["attributes"]["is_mfa"] is False
    assert auth["attributes"]["cloud_account"] == "111122223333"
    assert "SOC2-CC6.1" in auth["controls"]

    [change] = by_class["ocsf/account_change"]
    assert change["entity"]["asset_id"] == "AIDAEXAMPLEBOT"
    assert change["attributes"]["actor"] == "platform-admin"

    [api] = by_class["ocsf/api_activity"]
    assert api["entity"]["asset_id"] == "arn:aws:s3:::acme-audit-logs"
    assert api["entity"]["asset_type"] == "AWS::S3::Bucket"
    assert api["attributes"]["api_operation"] == "PutBucketPolicy"


def test_security_hub_v2_table_splits_into_finding_classes() -> None:
    rows = read_fixture_table(FIXTURES, "sh_findings_2_0")

    detection = map_rows(_preset("ocsf/detection_finding"), rows, collected_at=COLLECTED).events
    assert len(detection) == 1
    assert detection[0]["severity"] == "high"
    assert detection[0]["status"] == "open"
    assert detection[0]["source"] == "GuardDuty"
    assert detection[0]["entity"]["asset_id"].endswith("instance/i-0abc1234def567890")
    assert detection[0]["evidence"]["evidence_ref"].startswith("https://console.aws.amazon.com/guardduty/")

    vulnerability = map_rows(_preset("ocsf/vulnerability_finding"), rows, collected_at=COLLECTED).events
    assert len(vulnerability) == 1
    assert vulnerability[0]["severity"] == "critical"
    assert vulnerability[0]["attributes"]["cve"] == "CVE-2024-3094"
    assert vulnerability[0]["attributes"]["fix_available"] is True

    compliance = map_rows(_preset("ocsf/compliance_finding"), rows, collected_at=COLLECTED).events
    statuses = {event["attributes"]["compliance_control"]: event["status"] for event in compliance}
    assert statuses == {"IAM.6": "open", "S3.1": "pass"}
    assert validate_raw_events(detection + vulnerability + compliance) == []


def test_legacy_security_finding_reads_ocsf_rc2_rows() -> None:
    rows = read_fixture_table(FIXTURES, "sh_findings_1_0")
    [event] = map_rows(_preset("ocsf/security_finding", "sh_findings_1_0"), rows, collected_at=COLLECTED).events
    assert event["event_time"] == "2026-09-20T10:26:40Z"
    assert event["status"] == "open"
    assert event["severity"] == "high"
    assert event["attributes"]["cloud_account"] == "111122223333"
    assert event["attributes"]["ocsf_version"] == "1.0.0-rc.2"


def test_finding_ids_are_stable_so_updates_replace_prior_state() -> None:
    rows = read_fixture_table(FIXTURES, "sh_findings_2_0")
    spec = _preset("ocsf/compliance_finding")
    first = map_rows(spec, rows).events
    resolved = [dict(row, status_id=4, status="Resolved") for row in rows]
    second = map_rows(spec, resolved).events
    assert [e["event_id"] for e in first] == [e["event_id"] for e in second]


def test_connector_options_accept_preset_references_alongside_inline_specs() -> None:
    specs = resolve_mappings(
        {
            "mappings": [
                {"preset": "ocsf/authentication", "source": {"table": "db.cloudtrail"}},
                {"preset": "ocsf/api_activity", "source": {"table": "db.cloudtrail"}},
            ]
        }
    )
    assert [(s.name, s.source_table) for s in specs] == [
        ("ocsf_authentication", "db.cloudtrail"),
        ("ocsf_api_activity", "db.cloudtrail"),
    ]


def test_preset_overrides_merge_onto_the_preset() -> None:
    spec = resolve_mapping_ref(
        {
            "preset": "ocsf/api_activity",
            "source": {"table": "db.custom_ocsf", "lookback_minutes": 5},
            "fields": {"observed_at": {"column": "time", "format": "epoch_ms"}},
        }
    )
    assert spec.observed_column == "time"
    assert spec.lookback_minutes == 5
    assert spec.fields["event_type"].const == "ocsf.api_activity"


@pytest.mark.parametrize("dialect", ["snowflake", "databricks", "clickhouse", "bigquery"])
def test_every_preset_compiles_for_every_sql_dialect(dialect: str) -> None:
    for name in EXPECTED_PRESETS:
        query = compile_select(
            _preset(name, "sec.amazon_security_lake_table"),
            dialect,
            since="2026-09-21T00:00:00Z",
            limit=100,
        )
        assert query.sql.startswith("SELECT ")
        assert "2026" not in query.sql
        assert query.params["since"]
