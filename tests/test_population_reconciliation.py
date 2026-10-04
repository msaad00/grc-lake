"""Reconciliation cannot infer completeness from only observed assets."""

import copy

import pytest


def inputs():
    baseline = {
        "schema_version": "trustops.population_baseline.v1",
        "tenant_id": "platform-tenant",
        "as_of": "2026-01-04T00:00:00Z",
        "max_age_days": 2,
        "inventory": {
            "source": "urn:synthetic:inventory",
            "owner": "inventory-owner",
            "exported_at": "2026-01-03T00:00:00Z",
            "accounts": [{"source_tenant_id": "account-a", "asset_ids": ["a", "b"]}],
        },
        "collections": [
            {
                "source_tenant_id": "account-a",
                "source": "urn:synthetic:collection",
                "status": "complete",
                "cursor_exhausted": True,
                "asset_count": 2,
                "completed_at": "2026-01-03T02:00:00Z",
            }
        ],
    }
    events = [
        {
            "event_id": key,
            "tenant_id": "account-a",
            "asset_id": key,
            "asset_type": "host",
            "event_time": "2026-01-03T00:00:00Z",
            "evidence_collected_at": "2026-01-03T01:00:00Z",
            "status": "pass",
            "raw_sha256": key * 64,
        }
        for key in ("a", "b")
    ]
    return baseline, events


def reconcile(baseline, events, **kwargs):
    from security_lakehouse.population_reconciliation import reconcile_population

    return reconcile_population(events, baseline, **kwargs)


def test_matches_declared_scope_without_certifying_inventory_or_provider():
    baseline, events = inputs()
    result = reconcile(baseline, events)
    assert result["status"] == "declared_scope_reconciled"
    assert result["inventory_completeness"] == "not_independently_verified"
    assert result["collection_proof"] == "operator_supplied_receipts"
    assert result["expected_asset_count"] == result["observed_asset_count"] == 2
    assert result == reconcile(baseline, events[::-1])


@pytest.mark.parametrize(
    "failure",
    [
        "missing_asset",
        "missing_account",
        "unexpected",
        "duplicate_inventory",
        "duplicate_event",
        "partial",
        "cursor",
        "count",
        "stale",
        "future",
        "ambiguous",
    ],
)
def test_reconciliation_reports_gaps_and_never_passes(failure):
    baseline, events = inputs()
    if failure == "missing_asset":
        events.pop()
    if failure == "missing_account":
        baseline["inventory"]["accounts"].append({"source_tenant_id": "missing", "asset_ids": ["c"]})
    if failure == "unexpected":
        events[1]["asset_id"] = "surprise"
    if failure == "duplicate_inventory":
        baseline["inventory"]["accounts"][0]["asset_ids"].append("a")
    if failure == "duplicate_event":
        events.append(copy.deepcopy(events[0]))
    if failure == "partial":
        baseline["collections"][0]["status"] = "partial"
    if failure == "cursor":
        baseline["collections"][0]["cursor_exhausted"] = False
    if failure == "count":
        baseline["collections"][0]["asset_count"] = 9
    if failure == "stale":
        events[0]["event_time"] = "2025-12-01T00:00:00Z"
    if failure == "future":
        events[0]["evidence_collected_at"] = "2027-01-01T00:00:00Z"
    if failure == "ambiguous":
        extra = copy.deepcopy(events[0])
        extra.update(event_id="new", asset_type="other")
        events.append(extra)
    result = reconcile(baseline, events)
    assert result["status"] == "incomplete"
    assert sum(section["count"] for section in result["issues"].values()) > 0


def test_missing_details_are_bounded_but_totals_are_not_truncated():
    baseline, events = inputs()
    baseline["inventory"]["accounts"][0]["asset_ids"] += [f"missing-{n}" for n in range(250)]
    result = reconcile(baseline, events, details_limit=10)
    assert result["issues"]["missing_assets"]["count"] == 250
    assert len(result["issues"]["missing_assets"]["items"]) == 10
    assert result["issues"]["missing_assets"]["truncated"] is True


def test_source_account_identity_is_part_of_asset_key():
    baseline, events = inputs()
    events[1]["tenant_id"] = "account-b"
    result = reconcile(baseline, events)
    assert result["issues"]["missing_assets"]["count"] == 1
    assert result["issues"]["unexpected_assets"]["count"] == 1


def test_baseline_provenance_and_closed_cutoff_are_required():
    baseline, events = inputs()
    baseline["inventory"]["owner"] = ""
    with pytest.raises(ValueError):
        reconcile(baseline, events)
    baseline, events = inputs()
    baseline["as_of"] = "2999-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        reconcile(baseline, events)


def test_sealed_generation_cli_reports_missing_demo_asset(tmp_path, capsys):
    import json
    from pathlib import Path

    from security_lakehouse.cli import main
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.population_reconciliation import assess_population

    root = Path(__file__).resolve().parents[1]
    lake = tmp_path / "lake"
    run_pipeline(root / "examples/control-assurance/events.jsonl", lake)
    path = root / "examples/control-assurance/baseline.json"
    exit_code = main(["assessment", "population", "--lake", str(lake), "--baseline", str(path)])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["expected_asset_count"] == 6
    assert report["observed_asset_count"] == 5
    assert report["issues"]["missing_assets"]["items"] == [["synthetic-source", "synthetic-asset-5"]]
    assert report["generation"]["manifest_sha256"]
    baseline = json.loads(path.read_text())
    with pytest.raises(ValueError, match="owned"):
        assess_population(lake, {**baseline, "tenant_id": "foreign"})
    (lake / "silver/normalized_events.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="integrity"):
        assess_population(lake, baseline)


def test_large_population_keeps_correct_totals():
    baseline, template = inputs()
    count = 5000
    baseline["inventory"]["accounts"][0]["asset_ids"] = [str(index) for index in range(count)]
    baseline["collections"][0]["asset_count"] = count
    events = [{**template[0], "event_id": str(index), "asset_id": str(index)} for index in range(count)]
    report = reconcile(baseline, events)
    assert report["status"] == "declared_scope_reconciled"
    assert report["observed_asset_count"] == count
