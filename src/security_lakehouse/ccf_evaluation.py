"""Explicit safeguard evidence evaluated once within the observed asset scope.

Framework tags never imply a safeguard assertion. Proposed mappings and missing
asset evidence cannot become passes. Inventory completeness is a separate claim.
"""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from security_lakehouse.event_status import FAIL_STATUSES, normalize_event_status
from security_lakehouse.evidence_freshness import build_evidence_freshness
from security_lakehouse.policy import ControlContext, evaluate_control
from security_lakehouse.safeguards import ATTESTABLE_STATES, contributes_to_coverage, effective_review_state

JsonObject = dict[str, Any]


def _combine(states: list[str]) -> str:
    if "fail" in states:
        return "fail"
    if not states or "not_evaluated" in states:
        return "not_evaluated"
    if "stale" in states:
        return "stale"
    return "pass"


def evaluate_safeguards(
    events: list[JsonObject],
    payload: JsonObject,
    controls: dict[str, JsonObject],
    *,
    now: datetime | None = None,
) -> JsonObject:
    definitions = {str(row["safeguard_id"]): row for row in payload["safeguards"]}
    assets: dict[tuple[str, str], set[str]] = defaultdict(set)
    bound: dict[str, dict[tuple[str, str], list[JsonObject]]] = defaultdict(lambda: defaultdict(list))
    freshness = {row["event_id"]: row["status"] for row in build_evidence_freshness(events, now=now)}
    for event in events:
        asset_key = (str(event.get("tenant_id", "")), str(event["asset_id"]))
        assets[asset_key].add(str(event["asset_type"]))
        for safeguard_id in event.get("safeguard_ids", []):
            if safeguard_id not in definitions:
                raise ValueError("evidence references an unknown safeguard")
            bound[safeguard_id][asset_key].append(event)
    # Index the observed population once. Avoid a safeguards x events scan.
    type_counts = Counter(next(iter(types)) for types in assets.values() if len(types) == 1)
    results = []
    asset_results = []
    for safeguard_id, definition in definitions.items():
        eligible_types = set(definition.get("asset_types") or [])
        eligible_count = sum(type_counts[t] for t in eligible_types)
        ambiguous_count = sum(len(types) != 1 and bool(types & eligible_types) for types in assets.values())
        states = []
        assessed = 0
        invalid = 0
        for asset_key, rows in sorted(bound.get(safeguard_id, {}).items()):
            source_tenant_id, asset_id = asset_key
            reasons = []
            types = assets[asset_key]
            if len(types) != 1 or not types <= eligible_types:
                status = "not_evaluated"
                reasons.append("The asset type does not establish safeguard applicability.")
                invalid += 1
            else:
                assessed += 1
                failures = [row for row in rows if normalize_event_status(row["status"]) in FAIL_STATUSES]
                unknown = any(normalize_event_status(row["status"]) in {"observed", "not_evaluated"} for row in rows)
                stale = any(freshness[row["event_id"]] != "fresh" for row in rows)
                context = ControlContext(
                    control_id=safeguard_id,
                    event_count=len(rows),
                    evidence_count=sum(bool(row.get("evidence_ref")) for row in rows),
                    open_violation_count=len(failures),
                    max_severity=max(failures, key=lambda row: row["severity_score"])["severity"]
                    if failures
                    else "info",
                    evidence_status="stale" if stale else "fresh",
                )
                verdict = evaluate_control(context, definition["evaluation_rule"])
                if failures:
                    status = "fail"
                elif unknown:
                    status = "not_evaluated"
                elif stale:
                    status = "stale"
                else:
                    status = verdict.status
                reasons = list(verdict.reasons)
                if failures:
                    reasons.append("Source evidence reports a failing safeguard outcome.")
                if stale:
                    reasons.append("Safeguard evidence is stale, expired, or missing.")
                if unknown:
                    reasons = [*reasons, "An explicit safeguard outcome is required."]
            states.append(status)
            asset_results.append(
                {
                    "safeguard_id": safeguard_id,
                    "asset_id": asset_id,
                    "source_tenant_id": source_tenant_id,
                    "status": status,
                    "event_ids": sorted({str(row["event_id"]) for row in rows}),
                    "evidence_hashes": sorted({str(row["raw_sha256"]) for row in rows}),
                    "reasons": reasons,
                }
            )
        missing = max(0, eligible_count - assessed)
        if missing or ambiguous_count or invalid:
            states.append("not_evaluated")
        results.append(
            {
                "safeguard_id": safeguard_id,
                "title": definition["title"],
                "status": _combine(states),
                "applicable_asset_count": eligible_count,
                "assessed_asset_count": assessed,
                "unassessed_asset_count": missing,
                "invalid_binding_count": invalid,
            }
        )
    by_id = {row["safeguard_id"]: row["status"] for row in results}
    mappings: dict[str, list[tuple[str, str]]] = defaultdict(list)
    contextual: dict[str, list[JsonObject]] = defaultdict(list)
    for safeguard_id, definition in definitions.items():
        for member in definition["satisfies"]:
            state = effective_review_state(member)
            if state != "rejected" and not contributes_to_coverage(member):
                contextual[str(member["control_id"])].append(
                    {"safeguard_id": safeguard_id, "role": member.get("role"), "review_state": state}
                )
            elif state != "rejected":
                mappings[str(member["control_id"])].append((safeguard_id, state))
    requirements = []
    for control_id, control in sorted(controls.items()):
        links = mappings.get(control_id, [])
        reviewed = [sid for sid, state in links if state in ATTESTABLE_STATES]
        pending = sum(state not in ATTESTABLE_STATES for _, state in links)
        statuses = [by_id[sid] for sid in reviewed]
        if pending or not payload.get("review_log_verified", False):
            statuses.append("not_evaluated")
        requirements.append(
            {
                "control_id": control_id,
                "framework_id": control.get("framework_id"),
                "status": _combine(statuses) if links else "unmapped",
                "reviewed_safeguard_ids": sorted(reviewed),
                "pending_mapping_count": pending,
                "contextual_mappings": contextual.get(control_id, []),
            }
        )
    return {
        "schema_version": "trustops.ccf_assessment.v1",
        "scope": "observed_assets",
        "population_completeness": "not_established",
        "asset_count": len(assets),
        "ambiguous_asset_count": ambiguous_count,
        "review_log_verified": payload.get("review_log_verified", False),
        "safeguards": results,
        "asset_results": asset_results,
        "requirements": requirements,
    }
