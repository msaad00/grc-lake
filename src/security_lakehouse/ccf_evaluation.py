"""Explicit safeguard evidence evaluated once within the observed asset scope.

Framework tags never imply a safeguard assertion. Proposed mappings and missing
asset evidence cannot become passes. Inventory completeness is a separate claim.
"""

from collections import Counter, defaultdict
from datetime import datetime

from security_lakehouse.control_verdict import evaluate_evidence_verdict
from security_lakehouse.evidence_freshness import build_evidence_freshness, current_evidence_is_stale
from security_lakehouse.jsontypes import JsonObject
from security_lakehouse.safeguards import ATTESTABLE_STATES, contributes_to_coverage, effective_review_state


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
    freshness = {(row["tenant_id"], row["event_id"]): row for row in build_evidence_freshness(events, now=now)}
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
                stale = current_evidence_is_stale(
                    [freshness[(str(row.get("tenant_id", "")), str(row["event_id"]))] for row in rows],
                    required_types=definition.get("required_evidence_types"),
                )
                verdict = evaluate_evidence_verdict(safeguard_id, rows, definition["evaluation_rule"], stale=stale)
                status = verdict.status
                reasons = list(verdict.reasons)
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
        required = control.get("required_evidence_types") or []
        if reviewed and required:
            requirement_rows = [
                freshness[(str(row.get("tenant_id", "")), str(row["event_id"]))]
                for sid in reviewed
                for asset_rows in bound.get(sid, {}).values()
                for row in asset_rows
            ]
            if current_evidence_is_stale(requirement_rows, required_types=required):
                statuses.append("stale")
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
