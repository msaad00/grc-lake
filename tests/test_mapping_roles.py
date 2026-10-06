"""Contextual relationships cannot assert requirement implementation."""

from copy import deepcopy

import pytest

from security_lakehouse.ccf_evaluation import evaluate_safeguards
from security_lakehouse.oscal import build_component_definition
from security_lakehouse.safeguards import (
    coverage_by_framework,
    load_safeguards,
    mapping_review_items,
    requirement_status,
    safeguards_by_requirement,
    validate_safeguards,
)


@pytest.fixture(params=["supporting", "inherited"])
def contextual(request):
    payload = deepcopy(load_safeguards())
    entry = payload["safeguards"][0]
    entry["satisfies"] = entry["satisfies"][:1]
    member = {**entry["satisfies"][0], "role": request.param, "control_id": "SOC2-CC7.2", "framework_id": "soc2"}
    # Keep exactly one primary and a distinct contextual requirement.
    entry["satisfies"].append(member)
    payload["safeguards"] = [entry]
    payload["review_log_verified"] = True
    return payload, member


def test_contextual_roles_validate_and_remain_visible_for_review(contextual):
    payload, member = contextual
    assert validate_safeguards(payload) == []
    item = next(row for row in mapping_review_items(payload) if row["role"] == member["role"])
    assert item["contributes_to_coverage"] is False
    primary = next(row for row in mapping_review_items(payload) if row["role"] == "primary")
    assert member["control_id"] not in primary["reviewed_anchors"]


def test_reviewed_context_cannot_inflate_coverage_or_pass(contextual):
    payload, member = contextual
    cid = member["control_id"]
    sid = payload["safeguards"][0]["safeguard_id"]
    assert cid not in safeguards_by_requirement(payload)
    assert cid not in safeguards_by_requirement(payload, reviewed_only=True)
    assert requirement_status(cid, {sid: "pass"}, payload) == "unmapped"
    cov = coverage_by_framework(payload, catalog={cid: {"framework_id": "soc2"}})
    assert cov["covered"] == cov["reviewed"] == 0
    assert cov["contextual_mappings"] == 1
    result = evaluate_safeguards([], payload, {cid: {"framework_id": "soc2"}})
    row = result["requirements"][0]
    assert row["status"] == "unmapped"
    assert row["contextual_mappings"] == [
        {"safeguard_id": sid, "role": member["role"], "review_state": "maintainer_reviewed"}
    ]


def test_context_does_not_export_as_implemented_requirement(contextual):
    payload, member = contextual
    result = build_component_definition(safeguards_payload=payload)
    component = result["component-definition"]["components"][0]
    props = [
        prop
        for impl in component.get("control-implementations", [])
        for row in impl["implemented-requirements"]
        for prop in row["props"]
    ]
    assert not any(prop["name"] == "trustops-control-id" and prop["value"] == member["control_id"] for prop in props)


def test_context_never_changes_a_reviewed_implementation_result(contextual):
    from test_ccf_operational_assessment import normalized

    payload, member = contextual
    entry = payload["safeguards"][0]
    primary = entry["satisfies"][0]
    cid = primary["control_id"]
    member["control_id"] = cid
    events = [normalized(asset_type=entry["asset_types"][0], bindings=[entry["safeguard_id"]])]
    result = evaluate_safeguards(events, payload, {cid: {"framework_id": "soc2"}})
    assert result["requirements"][0]["status"] == "pass"
    assert result["requirements"][0]["reviewed_safeguard_ids"] == [entry["safeguard_id"]]
