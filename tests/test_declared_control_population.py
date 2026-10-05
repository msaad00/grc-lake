"""Declared eligible assets cannot disappear from period sampling."""

import copy

import pytest

from security_lakehouse.audit_workpapers import build_workpaper
from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.pipeline import run_pipeline
from test_control_assurance import case


@pytest.mark.parametrize("eligible", [True, False])
def test_declared_asset_without_period_observation(tmp_path, eligible):
    plan, events = case(tmp_path)
    late = copy.deepcopy(events[-1])
    late.update(event_id="late", event_time="2026-01-03T12:00:00Z")
    late["entity"]["asset_id"] = "untested-in-period"
    late["evidence"].update(collected_at=late["event_time"], evidence_id="late")
    if not eligible:
        late["safeguard_ids"] = []
    events.append(late)
    raw = tmp_path / "raw.jsonl"
    lake = tmp_path / "lake"
    write_jsonl(raw, events)
    run_pipeline(raw, lake, tenant_id=plan["tenant_id"])
    silver = read_jsonl(lake / "silver/normalized_events.jsonl")
    assets = sorted({row["asset_id"] for row in silver})
    account = silver[0]["tenant_id"]
    baseline = {
        "schema_version": "trustops.population_baseline.v1",
        "tenant_id": plan["tenant_id"],
        "as_of": plan["as_of"],
        "max_age_days": 2,
        "inventory": {
            "source": "urn:inventory",
            "owner": "owner",
            "exported_at": "2026-01-03T00:00:00Z",
            "accounts": [{"source_tenant_id": account, "asset_ids": assets}],
        },
        "collections": [
            {
                "source_tenant_id": account,
                "source": "urn:receipt",
                "status": "complete",
                "cursor_exhausted": True,
                "asset_count": len(assets),
                "completed_at": "2026-01-03T23:00:00Z",
            }
        ],
    }
    workpaper = build_workpaper(lake, plan=plan, baseline=baseline)
    operating = workpaper["assurance"]["controls"][0]["operating"]
    assert workpaper["population"]["status"] == "declared_scope_reconciled"
    assert operating["status"] == ("insufficient_evidence" if eligible else "sample_pass")
    if eligible:
        assert {row["asset_id"] for row in operating["gaps"]} == {"untested-in-period"}
