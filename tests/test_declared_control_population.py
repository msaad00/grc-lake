"""Declared eligible assets cannot disappear from period sampling."""

import copy

import pytest

from security_lakehouse.audit_workpapers import build_workpaper, export_workpaper, verify_workpaper_export
from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.pipeline import run_pipeline
from test_control_assurance import case


@pytest.mark.parametrize("bound", [True, False])
def test_declared_asset_without_period_observation(tmp_path, bound):
    plan, events = case(tmp_path)
    late = copy.deepcopy(events[-1])
    late.update(event_id="late", event_time="2026-01-03T12:00:00Z")
    late["entity"]["asset_id"] = "untested-in-period"
    late["evidence"].update(collected_at=late["event_time"], evidence_id="late")
    if not bound:
        late["safeguard_ids"] = []
    events.append(late)
    _, _, workpaper = build_case(tmp_path, plan, events, declared_extra=set())
    operating = workpaper["assurance"]["controls"][0]["operating"]
    assert workpaper["population"]["status"] == "declared_scope_reconciled"
    assert operating["status"] == "insufficient_evidence"
    assert {row["asset_id"] for row in operating["gaps"]} == {"untested-in-period"}


def build_case(tmp_path, plan, events, *, declared_extra):
    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, events)
    run_pipeline(raw, lake, tenant_id=plan["tenant_id"])
    silver = read_jsonl(lake / "silver/normalized_events.jsonl")
    observed = {(row["tenant_id"], row["asset_id"]) for row in silver}
    declared = observed | declared_extra
    accounts = sorted({account for account, _ in declared})
    baseline = {
        "schema_version": "trustops.population_baseline.v1",
        "tenant_id": plan["tenant_id"],
        "as_of": plan["as_of"],
        "max_age_days": 2,
        "inventory": {
            "source": "urn:inventory",
            "owner": "owner",
            "exported_at": "2026-01-03T00:00:00Z",
            "accounts": [
                {
                    "source_tenant_id": account,
                    "asset_ids": sorted(asset for tenant, asset in declared if tenant == account),
                }
                for account in accounts
            ],
        },
        "collections": [
            {
                "source_tenant_id": account,
                "source": "urn:receipt",
                "status": "complete",
                "cursor_exhausted": True,
                "asset_count": sum(tenant == account for tenant, _ in observed),
                "completed_at": "2026-01-03T23:00:00Z",
            }
            for account in accounts
        ],
    }
    return lake, baseline, build_workpaper(lake, plan=plan, baseline=baseline)


@pytest.mark.parametrize(
    "evidence",
    [
        "missing",
        "unbound",
        "other_safeguard",
        "unknown_type",
        "ambiguous_type",
        "incompatible_type",
        "future_incompatible_type",
        "other_account",
    ],
)
def test_declared_population_does_not_depend_on_safeguard_binding(tmp_path, evidence):
    plan, events = case(tmp_path)
    account, asset = events[0]["tenant_id"], "declared-extra"
    if evidence == "other_account":
        account, asset = "other-account", events[0]["entity"]["asset_id"]
    elif evidence != "missing":
        extra = copy.deepcopy(events[-1])
        extra.update(event_id="unbound", safeguard_ids=[])
        extra["entity"]["asset_id"] = asset
        extra["evidence"]["evidence_id"] = extra["event_id"]
        if evidence == "other_safeguard":
            extra["safeguard_ids"] = ["SG-CHANGEMANAGEMENT-001"]
        if evidence == "unknown_type":
            extra["entity"]["asset_type"] = "unknown"
        if "incompatible_type" in evidence or evidence == "ambiguous_type":
            extra["entity"]["asset_type"] = "ai_model"
        if evidence == "future_incompatible_type":
            extra["evidence"]["collected_at"] = "2026-01-05T00:00:00Z"
        events.append(extra)
        if evidence == "ambiguous_type":
            other = copy.deepcopy(extra)
            other.update(event_id="other-type")
            other["evidence"]["evidence_id"] = other["event_id"]
            other["entity"]["asset_type"] = "network"
            events.append(other)
    _, _, result = build_case(tmp_path, plan, events, declared_extra={(account, asset)})
    operating = result["assurance"]["controls"][0]["operating"]
    if evidence == "incompatible_type":
        assert operating["status"] == "sample_pass"
        assert operating["expected_asset_count"] == 1
        assert operating["gaps"] == []
    else:
        assert operating["status"] == "insufficient_evidence"
        assert operating["expected_asset_count"] == 2
        assert operating["expected_asset_windows"] == 4
        assert operating["tested_asset_windows"] == 2
        assert {(row["source_tenant_id"], row["asset_id"]) for row in operating["gaps"]} == {(account, asset)}
        assert len(operating["gaps"]) == 2
        assert {row["event_id"] for row in operating["samples"]} == {"op1", "op2"}


def test_new_population_does_not_rewrite_prior_workpaper_or_evidence(tmp_path):
    plan, events = case(tmp_path)
    lake, baseline, original = build_case(tmp_path, plan, events, declared_extra=set())
    output = tmp_path / "export"
    export_workpaper(original, output)
    saved = {path.name: path.read_bytes() for path in output.iterdir()}
    evidence = (lake / "silver/normalized_events.jsonl").read_bytes()
    baseline["inventory"]["accounts"][0]["asset_ids"].append("missing-declared")
    revised = build_workpaper(lake, plan=plan, baseline=baseline)
    first, second = (item["assurance"]["controls"][0]["operating"] for item in (original, revised))
    assert first["status"] == "sample_pass"
    assert second["status"] == "insufficient_evidence"
    assert first["samples"] == second["samples"]
    assert original["generation"] == revised["generation"]
    assert original["assurance"]["workpaper_sha256"] != revised["assurance"]["workpaper_sha256"]
    assert {path.name: path.read_bytes() for path in output.iterdir()} == saved
    assert (lake / "silver/normalized_events.jsonl").read_bytes() == evidence
    verified = verify_workpaper_export(output)
    assert verified["ok"]
