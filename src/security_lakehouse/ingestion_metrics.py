"""Ingestion loop accuracy and integration breadth metrics for API consumers."""

from __future__ import annotations

from pathlib import Path

from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.io import jsonl_field_counts, read_jsonl
from security_lakehouse.jsontypes import JsonObject

_PASS_RESULTS = frozenset({"pass", "ready"})
_FAIL_RESULTS = frozenset({"fail"})
_WARN_RESULTS = frozenset({"warn", "warning"})
_NEEDS_EVIDENCE_RESULTS = frozenset({"needs_evidence"})


def build_eval_accuracy(lake_dir: str | Path) -> JsonObject:
    """Summarize control-test accuracy after the latest lake evaluation."""
    lake = Path(lake_dir)
    rows = read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True, base_dir=lake)
    passing = sum(1 for row in rows if str(row.get("result", "")).lower() in _PASS_RESULTS)
    failing = sum(1 for row in rows if str(row.get("result", "")).lower() in _FAIL_RESULTS)
    warning = sum(1 for row in rows if str(row.get("result", "")).lower() in _WARN_RESULTS)
    needs_evidence = sum(1 for row in rows if str(row.get("result", "")).lower() in _NEEDS_EVIDENCE_RESULTS)
    total = len(rows)
    frameworks = {str(row.get("framework_id") or "") for row in rows if row.get("framework_id")}
    frameworks.discard("")
    source_counts = jsonl_field_counts(
        lake / "silver" / "normalized_events.jsonl",
        "source",
        missing_ok=True,
        base_dir=lake,
    )
    return {
        "total_tests": total,
        "passing": passing,
        "failing": failing,
        "warning": warning,
        "needs_evidence": needs_evidence,
        "pass_rate": round(passing / total, 4) if total else None,
        "framework_count": len(frameworks),
        "evidence_source_count": len(source_counts),
        "has_tests": total > 0,
    }


def build_catalog_coverage(
    *,
    connectors: list[JsonObject],
    catalog_path: str | Path | None = None,
) -> JsonObject:
    """Summarize connector catalog breadth vs implemented adapters and enablement."""
    catalog = load_connector_catalog(catalog_path)
    enabled_ids = {str(row.get("connector_id") or "") for row in connectors if row.get("state") == "enabled"}
    enabled_ids.discard("")
    by_category: dict[str, dict[str, int]] = {}
    implemented = 0
    for connector_id, row in catalog.items():
        category = str(row.get("category") or "other")
        bucket = by_category.setdefault(category, {"total": 0, "implemented": 0, "enabled": 0})
        bucket["total"] += 1
        if bool(row.get("is_implemented")):
            implemented += 1
            bucket["implemented"] += 1
        if connector_id in enabled_ids:
            bucket["enabled"] += 1
    total = len(catalog)
    enabled = len(enabled_ids)
    contract_only = total - implemented
    return {
        "total": total,
        "implemented": implemented,
        "enabled": enabled,
        "contract_only": contract_only,
        "implementation_rate": round(implemented / total, 4) if total else 0.0,
        "enabled_rate": round(enabled / implemented, 4) if implemented else 0.0,
        "by_category": [{"category": category, **counts} for category, counts in sorted(by_category.items())],
    }
