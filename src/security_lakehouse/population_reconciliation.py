"""Linear reconciliation of declared inventory and observed evidence.

An imported inventory and collection receipt remain operator assertions. Matching
them does not prove the inventory covers every real account or asset.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.control_assurance import bounded_integer, fields, nonempty, timestamp, verified_generation
from security_lakehouse.generations import generation_reader
from security_lakehouse.io import canonical_sha256, read_jsonl


def validate_baseline(baseline: dict[str, Any]) -> None:
    fields(baseline, {"schema_version", "tenant_id", "as_of", "max_age_days", "inventory", "collections"})
    if baseline["schema_version"] != "trustops.population_baseline.v1":
        raise ValueError("unsupported population baseline version")
    nonempty(baseline["tenant_id"])
    as_of = timestamp(baseline["as_of"])
    if as_of > datetime.now(UTC):
        raise ValueError("population cutoff cannot be in the future")
    bounded_integer(baseline["max_age_days"], 366)
    inventory = baseline["inventory"]
    fields(inventory, {"source", "owner", "exported_at", "accounts"})
    nonempty(inventory["source"])
    nonempty(inventory["owner"])
    if not as_of - timedelta(days=baseline["max_age_days"]) <= timestamp(inventory["exported_at"]) <= as_of:
        raise ValueError("inventory baseline must be fresh at the cutoff")
    if not isinstance(inventory["accounts"], list) or not 1 <= len(inventory["accounts"]) <= 1000:
        raise ValueError("baseline requires 1 to 1000 source accounts")
    accounts = set()
    total = 0
    for account in inventory["accounts"]:
        fields(account, {"source_tenant_id", "asset_ids"})
        nonempty(account["source_tenant_id"])
        if account["source_tenant_id"] in accounts:
            raise ValueError("duplicate account definition")
        accounts.add(account["source_tenant_id"])
        if not isinstance(account["asset_ids"], list):
            raise ValueError("asset_ids must be a list")
        for asset_id in account["asset_ids"]:
            nonempty(asset_id)
        total += len(account["asset_ids"])
    if total > 100000:
        raise ValueError("baseline exceeds 100000 assets; split the scope")
    if not isinstance(baseline["collections"], list) or len(baseline["collections"]) > 1000:
        raise ValueError("collections must contain at most 1000 receipts")
    seen = set()
    for receipt in baseline["collections"]:
        fields(receipt, {"source_tenant_id", "source", "status", "cursor_exhausted", "asset_count", "completed_at"})
        if receipt["source_tenant_id"] not in accounts or receipt["source_tenant_id"] in seen:
            raise ValueError("receipt account must be declared and unique")
        seen.add(receipt["source_tenant_id"])
        nonempty(receipt["source"])
        if receipt["status"] not in {"complete", "partial", "failed"} or type(receipt["cursor_exhausted"]) is not bool:
            raise ValueError("invalid collection status or cursor exhaustion")
        if type(receipt["asset_count"]) is not int or receipt["asset_count"] < 0:
            raise ValueError("collection asset count must be a nonnegative integer")
        timestamp(receipt["completed_at"])


def reconcile_population(
    events: list[dict[str, Any]], baseline: dict[str, Any], *, details_limit: int = 100
) -> dict[str, Any]:
    validate_baseline(baseline)
    bounded_integer(details_limit, 500)
    as_of = timestamp(baseline["as_of"])
    cutoff = as_of - timedelta(days=baseline["max_age_days"])
    expected = Counter(
        (account["source_tenant_id"], asset)
        for account in baseline["inventory"]["accounts"]
        for asset in account["asset_ids"]
    )
    observed: dict[tuple[str, str], set[str]] = defaultdict(set)
    fresh = set()
    event_ids: Counter[str] = Counter()
    invalid_times = set()
    latest_collection: dict[str, datetime] = {}
    by_account: Counter[str] = Counter()
    for row in events:
        key = (row["tenant_id"], row["asset_id"])
        if key not in observed:
            by_account[key[0]] += 1
        observed[key].add(row["asset_type"])
        event_ids[row["event_id"]] += 1
        observed_at, collected_at = timestamp(row["event_time"]), timestamp(row["evidence_collected_at"])
        latest_collection[key[0]] = max(latest_collection.get(key[0], collected_at), collected_at)
        if not observed_at <= collected_at <= as_of:
            invalid_times.add(row["event_id"])
        elif observed_at >= cutoff:
            fresh.add(key)
    receipts = {row["source_tenant_id"]: row for row in baseline["collections"]}
    account_gaps = []
    for account in sorted(account["source_tenant_id"] for account in baseline["inventory"]["accounts"]):
        receipt = receipts.get(account)
        if receipt is None:
            account_gaps.append({"source_tenant_id": account, "reason": "missing_collection_receipt"})
        elif (
            receipt["status"] != "complete"
            or not receipt["cursor_exhausted"]
            or receipt["asset_count"] != by_account[account]
            or not cutoff <= timestamp(receipt["completed_at"]) <= as_of
            or timestamp(receipt["completed_at"]) < latest_collection.get(account, cutoff)
        ):
            account_gaps.append({"source_tenant_id": account, "reason": "partial_inconsistent_or_stale_collection"})
    expected_keys, observed_keys = set(expected), set(observed)
    raw_issues: dict[str, list[Any]] = {
        "missing_assets": sorted(expected_keys - observed_keys),
        "unexpected_assets": sorted(observed_keys - expected_keys),
        "duplicate_inventory_assets": sorted(key for key, count in expected.items() if count > 1),
        "duplicate_event_ids": sorted(key for key, count in event_ids.items() if count > 1),
        "stale_assets": sorted((expected_keys & observed_keys) - fresh),
        "ambiguous_assets": sorted(key for key, types in observed.items() if len(types) != 1),
        "invalid_time_events": sorted(invalid_times),
        "account_collection_gaps": account_gaps,
    }
    issues = {
        name: {
            "count": len(items),
            "items": [list(item) if isinstance(item, tuple) else item for item in items[:details_limit]],
            "truncated": len(items) > details_limit,
        }
        for name, items in raw_issues.items()
    }
    return {
        "schema_version": "trustops.population_reconciliation.v1",
        "tenant_id": baseline["tenant_id"],
        "status": "incomplete" if any(raw_issues.values()) else "declared_scope_reconciled",
        "inventory_completeness": "not_independently_verified",
        "collection_proof": "operator_supplied_receipts",
        "baseline_sha256": canonical_sha256(baseline),
        "as_of": baseline["as_of"],
        "expected_asset_count": len(expected),
        "observed_asset_count": len(observed),
        "expected_account_count": len(baseline["inventory"]["accounts"]),
        "observed_account_count": len(by_account),
        "issues": issues,
    }


@generation_reader
def assess_population(lake: Path, baseline: dict[str, Any], *, details_limit: int = 100) -> dict[str, Any]:
    validate_baseline(baseline)
    generation = verified_generation(lake, baseline["tenant_id"])
    report = reconcile_population(
        read_jsonl(lake / "silver/normalized_events.jsonl"), baseline, details_limit=details_limit
    )
    report["generation"] = generation
    report["reconciliation_sha256"] = canonical_sha256(report)
    return report
