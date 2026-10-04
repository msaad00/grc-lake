"""Reproducible control test workpapers; machine results await human judgment.

Design documentation, period samples, mapping review, and population completeness
are separate claims. A passing observation never establishes effectiveness alone.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.event_status import FAIL_STATUSES, normalize_event_status
from security_lakehouse.generations import generation_identity, generation_reader
from security_lakehouse.io import canonical_sha256, read_json, read_jsonl
from security_lakehouse.safeguards import effective_review_state
from security_lakehouse.verification import verify_lake_integrity


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamps must be ISO-8601 strings with timezone")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if result.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return result


def fields(row: Any, required: set[str], optional: set[str] | None = None) -> None:
    if not isinstance(row, dict) or required - row.keys() or row.keys() - required - (optional or set()):
        raise ValueError("object has missing or unknown fields")


def nonempty(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("text fields must be nonempty strings")


def bounded_integer(value: Any, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"integer must be between 1 and {maximum}")


def verified_generation(lake: Path, tenant_id: str) -> dict[str, str]:
    identity = generation_identity(lake)
    if not identity or read_json(lake / "manifest.json").get("tenant_id") != tenant_id:
        raise ValueError("a sealed generation owned by the declared tenant is required")
    if not verify_lake_integrity(lake)["ok"]:
        raise ValueError("evidence generation failed integrity verification")
    return identity


def validate_plan(plan: dict[str, Any]) -> tuple[datetime, datetime, datetime]:
    fields(plan, {"schema_version", "tenant_id", "period_start", "period_end", "as_of", "controls"})
    if plan["schema_version"] != "trustops.control_test_plan.v1":
        raise ValueError("unsupported control test plan version")
    nonempty(plan["tenant_id"])
    start, end, as_of = (timestamp(plan[key]) for key in ("period_start", "period_end", "as_of"))
    if not start < end <= as_of <= datetime.now(UTC) or end - start > timedelta(days=366):
        raise ValueError("period must be ordered, closed, no longer than 366 days, and not in the future")
    if not isinstance(plan["controls"], list) or not 1 <= len(plan["controls"]) <= 50:
        raise ValueError("plan requires 1 to 50 controls")
    seen = set()
    for control in plan["controls"]:
        text_fields = {"safeguard_id", "activity", "owner", "system", "frequency", "procedure", "sampling_rationale"}
        fields(control, text_fields | {"cadence_days", "sample_per_window", "design_event_ids"})
        for key in text_fields:
            nonempty(control[key])
        if control["safeguard_id"] in seen:
            raise ValueError("duplicate safeguard in test plan")
        seen.add(control["safeguard_id"])
        bounded_integer(control["cadence_days"], 366)
        bounded_integer(control["sample_per_window"], 100)
        ids = control["design_event_ids"]
        if not isinstance(ids, list) or len(ids) > 100:
            raise ValueError("design evidence must be a list of at most 100 event IDs")
        for item in ids:
            nonempty(item)
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate design evidence IDs")
    return start, end, as_of


def evidence_reference(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: row[key]
        for key in ("event_id", "tenant_id", "asset_id", "event_time", "evidence_collected_at", "raw_sha256")
    }


def _valid_at(row: dict[str, Any], as_of: datetime) -> bool:
    return timestamp(row["event_time"]) <= timestamp(row["evidence_collected_at"]) <= as_of


@generation_reader
def assess_control_plan(lake: Path, plan: dict[str, Any]) -> dict[str, Any]:
    start, end, as_of = validate_plan(plan)
    generation = verified_generation(lake, plan["tenant_id"])
    catalog = {row["safeguard_id"]: row for row in read_json(lake / "catalog/safeguards.json")["safeguards"]}
    events = read_jsonl(lake / "silver/normalized_events.jsonl")
    by_id = {row["event_id"]: row for row in events}
    bound: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in events:
        for safeguard_id in row["safeguard_ids"]:
            bound[safeguard_id].append(row)
    plan_hash = canonical_sha256(plan)
    results = []
    for control in plan["controls"]:
        sid = control["safeguard_id"]
        if sid not in catalog:
            raise ValueError("test plan references an unknown safeguard")
        design = [by_id[event_id] for event_id in control["design_event_ids"] if event_id in by_id]
        design_valid = (
            bool(design)
            and len(design) == len(control["design_event_ids"])
            and all(
                sid in row["safeguard_ids"]
                and _valid_at(row, as_of)
                and start - timedelta(days=366) <= timestamp(row["event_time"]) <= start
                and normalize_event_status(row["status"]) == "pass"
                for row in design
            )
        )
        operating = [
            row
            for row in bound[sid]
            if row["event_id"] not in control["design_event_ids"] and start <= timestamp(row["event_time"]) < end
        ]
        assets = sorted({(row["tenant_id"], row["asset_id"]) for row in operating})
        windows = []
        cursor = start
        while cursor < end:
            windows.append((cursor, min(cursor + timedelta(days=control["cadence_days"]), end)))
            cursor = windows[-1][1]
        if len(assets) * len(windows) > 50000:
            raise ValueError("test plan exceeds 50000 asset/window cells; split the scope")
        cells: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
        for row in operating:
            index = (timestamp(row["event_time"]) - start) // timedelta(days=control["cadence_days"])
            cells[(row["tenant_id"], row["asset_id"], index)].append(row)
        deviations = sorted(
            row["event_id"] for row in operating if normalize_event_status(row["status"]) in FAIL_STATUSES
        )
        invalid = sorted(
            row["event_id"]
            for row in operating
            if not _valid_at(row, as_of) or normalize_event_status(row["status"]) not in {"pass", *FAIL_STATUSES}
        )
        samples: list[dict[str, Any]] = []
        gaps = []
        for account, asset in assets:
            for index, (begin, finish) in enumerate(windows):
                rows = cells[(account, asset, index)]
                eligible = [row for row in rows if _valid_at(row, as_of)]
                if len(eligible) < control["sample_per_window"]:
                    gaps.append(
                        {
                            "source_tenant_id": account,
                            "asset_id": asset,
                            "start": begin.isoformat(),
                            "end": finish.isoformat(),
                        }
                    )
                selected = sorted(eligible, key=lambda row: canonical_sha256([plan_hash, row["event_id"]]))[
                    : control["sample_per_window"]
                ]
                samples.extend(evidence_reference(row) for row in selected)
        status = (
            "sample_fail" if deviations else "insufficient_evidence" if not assets or gaps or invalid else "sample_pass"
        )
        results.append(
            {
                "safeguard_id": sid,
                "test_definition": control,
                "requirement_mappings": [
                    {**member, "effective_review_state": effective_review_state(member)}
                    for member in catalog[sid]["satisfies"]
                ],
                "design": {
                    "status": "documented" if design_valid else "insufficient_evidence",
                    "evidence": [evidence_reference(row) for row in design],
                },
                "operating": {
                    "status": status,
                    "tested_windows": len(windows),
                    "observed_asset_count": len(assets),
                    "population_event_count": len(operating),
                    "samples": samples,
                    "gaps": gaps,
                    "deviation_event_ids": deviations,
                    "invalid_event_ids": invalid,
                    "sampling_method": "sha256-ranked-per-asset-window; all observed deviations retained",
                },
                "conclusion": "pending_human_review",
            }
        )
    payload = {
        "schema_version": "trustops.control_assurance.v1",
        "tenant_id": plan["tenant_id"],
        "period_start": plan["period_start"],
        "period_end": plan["period_end"],
        "as_of": plan["as_of"],
        "plan_sha256": plan_hash,
        "generation": generation,
        "review_status": "pending_human_review",
        "population_completeness": "not_established",
        "controls": results,
    }
    payload["workpaper_sha256"] = canonical_sha256(payload)
    return payload
