"""Unified golden fixture tests."""

from __future__ import annotations

import json
from pathlib import Path

from security_lakehouse import api_v1
from security_lakehouse.assessment import build_current_posture
from security_lakehouse.fixtures import find_fixture
from security_lakehouse.golden_fixture import (
    GOLDEN_COMPANY,
    build_golden_events,
    golden_control_ids,
    golden_fixture_summary,
)
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.validation import validate_raw_events


def test_golden_fixture_summary_lists_37_controls() -> None:
    summary = golden_fixture_summary()
    assert summary["company"] == GOLDEN_COMPANY
    assert summary["control_count"] == 37
    assert summary["soc2_control_count"] == 33
    assert summary["nist_ai_control_count"] == 4
    assert len(golden_control_ids()) == 37


def test_golden_events_validate() -> None:
    rows = build_golden_events()
    assert len(rows) == 37
    assert validate_raw_events(rows) == []
    assert {row["controls"][0] for row in rows} == set(golden_control_ids())


def test_golden_fixture_ships_and_populates_dashboard(tmp_path: Path) -> None:
    fixture = find_fixture(GOLDEN_COMPANY)
    assert fixture is not None
    assert fixture.event_count >= len(golden_control_ids())
    expected_controls = set(golden_control_ids()) | {"ISO27001-A.5.15"}
    assert set(fixture.controls) == expected_controls

    run_pipeline(fixture.raw_path, tmp_path)
    posture_rows = [
        json.loads(line)
        for line in (tmp_path / "gold" / "control_posture.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(posture_rows) == len(expected_controls)
    assert {row["control_id"] for row in posture_rows} == expected_controls

    posture = build_current_posture(tmp_path)
    assert posture["posture"]["control_count"] == len(expected_controls)
    assert posture["posture"]["framework_count"] == 3
    frameworks = {row["framework"] for row in posture["frameworks"]}
    assert frameworks == {"SOC 2", "NIST AI RMF", "ISO 27001:2022"}


def test_golden_asset_types_match_their_event_types() -> None:
    from security_lakehouse.golden_fixture import build_golden_events

    ai_asset_types = {"model", "agent", "ai_model", "ai_agent"}
    ai_event_types = {"model.lineage", "runtime.inference"}
    for row in build_golden_events():
        is_ai_asset = row["entity"]["asset_type"] in ai_asset_types
        assert is_ai_asset == (row["event_type"] in ai_event_types), row["event_id"]


def test_committed_golden_fixture_asset_types_match_event_types() -> None:
    from security_lakehouse.golden_fixture import golden_fixture_path

    ai_asset_types = {"model", "agent", "ai_model", "ai_agent"}
    ai_event_types = {"model.lineage", "runtime.inference", "ai.model_inventory", "model.inventory"}
    for line in golden_fixture_path().read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        is_ai_asset = row["entity"]["asset_type"] in ai_asset_types
        assert is_ai_asset == (row["event_type"] in ai_event_types), row["event_id"]
        if is_ai_asset:
            assert not row["entity"]["asset_id"].startswith("golden:asset:soc2-"), row["event_id"]


def test_golden_sources_match_their_event_types() -> None:
    """A model-drift alert comes from the SIEM, never from AWS Config."""
    from security_lakehouse.golden_fixture import golden_fixture_path

    expected = {
        "cloud.config": {"aws_config"},
        "iam.access_review": {"okta"},
        "monitoring.audit": {"audit_log"},
        "monitoring.detection": {"siem"},
        "scm.branch_protection": {"github"},
        "scanner.dependency": {"github"},
        "model.lineage": {"model_registry"},
        "runtime.inference": {"runtime_gateway"},
    }
    for line in golden_fixture_path().read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["event_type"] in expected:
            assert row["source"] in expected[row["event_type"]], (row["event_id"], row["event_type"], row["source"])


def test_committed_golden_fixture_is_exactly_the_generator_output() -> None:
    """The demo loads the committed JSONL, so it must not drift from the generator."""
    from security_lakehouse.golden_fixture import golden_fixture_path, render_golden_fixture

    assert golden_fixture_path().read_text(encoding="utf-8") == render_golden_fixture()


def test_golden_assets_have_readable_names_and_keep_stable_ids() -> None:
    from security_lakehouse.golden_fixture import build_golden_fixture_rows

    rows = build_golden_fixture_rows()
    names_by_id: dict[str, set[str]] = {}
    for row in rows:
        entity = row["entity"]
        name = entity.get("asset_name")
        assert isinstance(name, str) and name.strip(), row["event_id"]
        assert ":" not in name, row["event_id"]
        names_by_id.setdefault(entity["asset_id"], set()).add(name)
    # One name per asset, and no two assets share a name.
    assert all(len(names) == 1 for names in names_by_id.values())
    assert len({next(iter(names)) for names in names_by_id.values()}) == len(names_by_id)
    ids = set(names_by_id)
    assert {"golden:asset:soc2-cc1.1", "golden:model:risk-scorer", "golden:agent:triage-agent"} <= ids
    assert "github:repo:acme/model-service" in ids


def test_golden_asset_names_reach_evidence_findings_and_graph(tmp_path: Path) -> None:
    from security_lakehouse.graph import build_compliance_graph

    fixture = find_fixture(GOLDEN_COMPANY)
    assert fixture is not None
    run_pipeline(fixture.raw_path, tmp_path)

    silver = [
        json.loads(line)
        for line in (tmp_path / "silver" / "normalized_events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    # Names are display data on gold assets; normalized events keep the v1 shape.
    assert not [row for row in silver if "asset_name" in row]

    status, body = api_v1.handle_get("/api/v1/evidence", {"limit": ["500"]}, tmp_path)
    assert status == 200
    first = next(row for row in body["data"] if row["event_id"] == "golden-001")
    assert first["asset_id"] == "golden:asset:soc2-cc1.1"
    assert first["asset_name"] == "Customer records bucket"

    assets = {row["asset_id"]: row for row in api_v1.handle_get("/api/v1/assets", {}, tmp_path)[1]["data"]}
    assert assets["golden:model:risk-scorer"]["asset_name"] == "Risk scorer model"

    violations = build_current_posture(tmp_path)["violations"]
    assert violations and all(v.get("asset_name") for v in violations)

    graph = build_compliance_graph(tmp_path)
    asset_nodes = [node for node in graph["nodes"] if node["kind"] == "asset"]
    assert asset_nodes
    assert not [node for node in asset_nodes if str(node["label"]).startswith("golden:")]
    customer = next(node for node in asset_nodes if node.get("asset_id") == "golden:asset:soc2-cc1.1")
    assert customer["label"] == "Customer records bucket"


def test_asset_names_come_from_raw_entities_and_only_label_known_assets() -> None:
    from security_lakehouse.asset_names import asset_names_from_raw, with_asset_names

    raw = [
        {"entity": {"asset_id": "arn:aws:s3:::logs", "asset_name": "  Logs bucket "}},
        {"entity": {"asset_id": "arn:aws:s3:::logs", "asset_name": "Renamed later"}},
        {"entity": {"id": "i-123"}},
        {"entity": "not-an-object"},
    ]
    names = asset_names_from_raw(raw)
    assert names == {"arn:aws:s3:::logs": "Logs bucket"}
    rows = with_asset_names([{"asset_id": "arn:aws:s3:::logs"}, {"asset_id": "i-123"}], names)
    assert rows == [{"asset_id": "arn:aws:s3:::logs", "asset_name": "Logs bucket"}, {"asset_id": "i-123"}]


def test_golden_ai_inventory_carries_asset_names(tmp_path: Path) -> None:
    from security_lakehouse.ai_governance import list_ai_inventory

    fixture = find_fixture(GOLDEN_COMPANY)
    assert fixture is not None
    run_pipeline(fixture.raw_path, tmp_path)
    items = list_ai_inventory(lake=tmp_path, limit=100)
    assert items and all(item.get("asset_name") for item in items)
    by_id = {item["asset_id"]: item for item in items}
    assert by_id["golden:model:risk-scorer"]["asset_name"] == "Risk scorer model"
