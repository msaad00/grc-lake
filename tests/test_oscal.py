"""OSCAL export: component-definition and assessment-results JSON."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from security_lakehouse import api_v1
from security_lakehouse.cli import main
from security_lakehouse.oscal import (
    OSCAL_VERSION,
    _oscal_token,
    build_assessment_results,
    build_component_definition,
)

ROOT = Path(__file__).resolve().parents[1]


def _load_oscal_schema(name: str) -> dict:
    """Load a vendored OSCAL schema for structural (shape) validation.

    The upstream schema's ``TokenDatatype``/``StringDatatype`` patterns use
    PCRE Unicode property escapes (``\\p{L}``, ``\\p{N}``) that Python's
    stdlib ``re`` module cannot compile (no ``regex`` dependency is pinned in
    this repo). Since :func:`security_lakehouse.oscal._oscal_token` already
    guarantees ASCII-only output by construction, substituting an equivalent
    ASCII character class loses no real coverage for these tests -- the
    object/required-field shape (the actual point of this check) is
    unaffected.
    """
    text = (ROOT / "controls" / "oscal" / name).read_text()
    text = text.replace(r"\\p{L}", "[A-Za-z]").replace(r"\\p{N}", "[0-9]")
    return json.loads(text)


_COMPONENT_SCHEMA = _load_oscal_schema("oscal_component_schema.json")
_ASSESSMENT_RESULTS_SCHEMA = _load_oscal_schema("oscal_assessment-results_schema.json")

_CATALOG = {
    "SOC2-CC6.1": {"control_id": "SOC2-CC6.1", "framework_id": "soc2", "evidence_requirement": "Access is reviewed."},
    "ISO27001-A.5.15": {
        "control_id": "ISO27001-A.5.15",
        "framework_id": "iso-27001-2022",
        "evidence_requirement": "Access control policy is enforced.",
    },
    "HIPAA-164.308(a)(4)": {
        "control_id": "HIPAA-164.308(a)(4)",
        "framework_id": "hipaa-security-rule",
        "evidence_requirement": "Access authorization is documented.",
    },
}

_SAFEGUARDS_PAYLOAD = {
    "schema": "trustops.safeguards.v1",
    "safeguards": [
        {
            "safeguard_id": "SG-IDENTITY-001",
            "title": "Logical access and MFA",
            "risk_domain": "identity",
            "objective": "Logical access restrictions and MFA are assessed.",
            "evidence_requirement": "Current access review evidence exists.",
            "evaluation_rule": "fail_when_open_violation_or_stale_evidence",
            "owner": "security-platform",
            "satisfies": [
                {
                    "control_id": "SOC2-CC6.1",
                    "framework_id": "soc2",
                    "role": "primary",
                    "review_status": "reviewed",
                },
                {
                    "control_id": "ISO27001-A.5.15",
                    "framework_id": "iso-27001-2022",
                    "role": "equivalent",
                    "review_status": "reviewed",
                },
                {
                    # Proposed: a human has not confirmed this equivalence yet.
                    # Must never appear as an OSCAL implemented-requirement.
                    "control_id": "HIPAA-164.308(a)(4)",
                    "framework_id": "hipaa-security-rule",
                    "role": "equivalent",
                    "review_status": "proposed",
                },
            ],
        },
        {
            "safeguard_id": "SG-ALL-PROPOSED-001",
            "title": "Nothing reviewed yet",
            "risk_domain": "identity",
            "objective": "A safeguard whose only mapping is still proposed.",
            "evidence_requirement": "n/a",
            "evaluation_rule": "fail_when_open_violation_or_stale_evidence",
            "owner": "security-platform",
            "satisfies": [
                {
                    "control_id": "HIPAA-164.308(a)(4)",
                    "framework_id": "hipaa-security-rule",
                    "role": "primary",
                    "review_status": "proposed",
                },
            ],
        },
    ],
}


def _registry():
    from security_lakehouse.catalog import load_framework_registry

    real = load_framework_registry()
    return {
        "soc2": real.get("soc2", {"name": "SOC 2", "official_source_url": "https://example.com/soc2"}),
        "iso-27001-2022": real.get(
            "iso-27001-2022", {"name": "ISO 27001", "official_source_url": "https://example.com/iso"}
        ),
        "hipaa-security-rule": real.get(
            "hipaa-security-rule", {"name": "HIPAA", "official_source_url": "https://example.com/hipaa"}
        ),
    }


def _build_fixture_component_definition(monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setattr("security_lakehouse.oscal.load_framework_registry", _registry)
    return build_component_definition(_SAFEGUARDS_PAYLOAD, _CATALOG)


# --- token sanitization -----------------------------------------------------


def test_oscal_token_passes_through_already_valid_ids() -> None:
    assert _oscal_token("SOC2-CC6.1") == "SOC2-CC6.1"
    assert _oscal_token("CIS-AWS-1.10") == "CIS-AWS-1.10"


def test_oscal_token_sanitizes_parentheses_and_stays_a_valid_token() -> None:
    token = _oscal_token("HIPAA-164.308(a)(1)(ii)(A)")
    expected = "-".join(("HIPAA", "164.308", "a", "1", "ii", "A"))
    assert token == expected
    # NCName: starts with a letter/underscore, then letters/digits/./-/_
    import re

    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]*", token)


# --- component-definition ----------------------------------------------------


def test_component_definition_top_level_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = _build_fixture_component_definition(monkeypatch)
    root = doc["component-definition"]
    assert root["metadata"]["oscal-version"] == OSCAL_VERSION
    assert root["metadata"]["title"]
    assert len(root["components"]) == 2

    identity = next(c for c in root["components"] if c["title"] == "Logical access and MFA")
    assert identity["type"] == "process-procedure"
    assert identity["description"]
    frameworks = {impl["source"] for impl in identity["control-implementations"]}
    # Two reviewed frameworks (soc2, iso); hipaa's only entry is proposed.
    assert len(identity["control-implementations"]) == 2
    assert frameworks == {
        _registry()["soc2"]["official_source_url"],
        _registry()["iso-27001-2022"]["official_source_url"],
    }


def test_component_definition_excludes_proposed_mappings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The most important correctness property: proposed != implemented-requirement."""
    doc = _build_fixture_component_definition(monkeypatch)
    root = doc["component-definition"]

    all_control_ids: set[str] = set()
    for component in root["components"]:
        for impl in component.get("control-implementations", []):
            for req in impl["implemented-requirements"]:
                prop_values = {p["name"]: p["value"] for p in req["props"]}
                all_control_ids.add(prop_values["trustops-control-id"])

    assert "HIPAA-164.308(a)(4)" not in all_control_ids
    assert all_control_ids == {"SOC2-CC6.1", "ISO27001-A.5.15"}

    # The safeguard whose only mapping is proposed still becomes a component
    # (never a silently-dropped one) but carries no control-implementations.
    proposed_only = next(c for c in root["components"] if c["title"] == "Nothing reviewed yet")
    assert "control-implementations" not in proposed_only


def test_component_definition_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime

    moment = datetime(2026, 6, 30, tzinfo=UTC)
    monkeypatch.setattr("security_lakehouse.oscal.load_framework_registry", _registry)
    first = build_component_definition(_SAFEGUARDS_PAYLOAD, _CATALOG, now=moment)
    second = build_component_definition(_SAFEGUARDS_PAYLOAD, _CATALOG, now=moment)
    assert first == second


def test_component_definition_validates_against_oscal_schema() -> None:
    """Structural validation against the real shipped safeguards + catalog."""
    doc = build_component_definition()
    Draft7Validator(_COMPONENT_SCHEMA).validate(doc)


def test_component_definition_shipped_implemented_requirements_are_all_reviewed() -> None:
    """No (safeguard, control_id) pair emitted as implemented-requirement is proposed-only.

    A control_id can legitimately be *proposed* under one safeguard and
    separately *reviewed* under another (many safeguards may satisfy the same
    requirement) -- so the correctness property is per (safeguard, control_id)
    pair, not "this control_id never appears as proposed anywhere".
    """
    from security_lakehouse.safeguards import load_safeguards

    payload = load_safeguards()
    proposed_pairs = {
        (str(entry["safeguard_id"]), str(m["control_id"]))
        for entry in payload["safeguards"]
        for m in entry.get("satisfies", [])
        if m.get("review_status", "reviewed") != "reviewed"
    }
    doc = build_component_definition()
    emitted_pairs: set[tuple[str, str]] = set()
    for component in doc["component-definition"]["components"]:
        for impl in component.get("control-implementations", []):
            for req in impl["implemented-requirements"]:
                props = {p["name"]: p["value"] for p in req["props"]}
                emitted_pairs.add((props["trustops-safeguard-id"], props["trustops-control-id"]))
    assert emitted_pairs.isdisjoint(proposed_pairs)


# --- assessment-results -------------------------------------------------------


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def _seed_control_posture(lake: Path) -> None:
    _write_jsonl(
        lake / "gold" / "control_posture.jsonl",
        [
            {
                "control_id": "SOC2-CC6.1",
                "framework": "SOC 2",
                "title": "Access is reviewed",
                "status": "pass",
                "rule_reasons": [],
                "latest_event_time": "2026-05-20T13:01:00Z",
            },
            {
                "control_id": "SOC2-CC7.1",
                "framework": "SOC 2",
                "title": "Vulnerabilities are remediated",
                "status": "fail",
                "rule_reasons": ["1 open violation(s) (>= 1)"],
                "latest_event_time": "2026-05-21T13:01:00Z",
            },
            {
                "control_id": "SOC2-CC7.2",
                "framework": "SOC 2",
                "title": "Monitoring evidence stays fresh",
                "status": "stale",
                "rule_reasons": [],
                "latest_event_time": "2026-01-01T00:00:00Z",
            },
            {
                "control_id": "ISO27001-A.5.15",
                "framework": "ISO 27001",
                "title": "Not yet mapped to an active control definition",
                "status": "not_evaluated",
                "rule_reasons": ["No active control definition is available."],
                "latest_event_time": "2026-05-01T00:00:00Z",
            },
        ],
    )


def test_build_assessment_results_maps_every_status(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    _seed_control_posture(lake)
    doc = build_assessment_results(lake)
    root = doc["assessment-results"]
    assert root["metadata"]["oscal-version"] == OSCAL_VERSION
    assert root["import-ap"]["href"].startswith("urn:trustops:catalog-bundle:")

    findings = {f["props"][0]["value"]: f for f in root["results"][0]["findings"]}
    assert findings["SOC2-CC6.1"]["target"]["status"] == {"state": "satisfied", "reason": "pass"}
    assert findings["SOC2-CC7.1"]["target"]["status"] == {"state": "not-satisfied", "reason": "fail"}
    assert findings["SOC2-CC7.2"]["target"]["status"] == {"state": "not-satisfied", "reason": "other"}
    assert findings["ISO27001-A.5.15"]["target"]["status"] == {"state": "not-satisfied", "reason": "other"}

    # Every finding is backed by exactly one observation.
    observation_ids = {o["uuid"] for o in root["results"][0]["observations"]}
    for finding in root["results"][0]["findings"]:
        related = finding["related-observations"]
        assert len(related) == 1
        assert related[0]["observation-uuid"] in observation_ids


def test_build_assessment_results_never_reports_stale_or_unevaluated_as_satisfied(tmp_path: Path) -> None:
    """A control that was not confirmed passing must never look satisfied."""
    lake = tmp_path / "lake"
    _seed_control_posture(lake)
    doc = build_assessment_results(lake)
    for finding in doc["assessment-results"]["results"][0]["findings"]:
        props = {p["name"]: p["value"] for p in finding["props"]}
        status = finding["target"]["status"]
        if props["trustops-status"] in {"stale", "not_evaluated"}:
            assert status["state"] == "not-satisfied"


def test_build_assessment_results_validates_against_oscal_schema(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    _seed_control_posture(lake)
    doc = build_assessment_results(lake)
    Draft7Validator(_ASSESSMENT_RESULTS_SCHEMA).validate(doc)


def test_build_assessment_results_empty_lake_still_validates(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir(parents=True)
    doc = build_assessment_results(lake)
    assert "findings" not in doc["assessment-results"]["results"][0]
    assert "observations" not in doc["assessment-results"]["results"][0]
    Draft7Validator(_ASSESSMENT_RESULTS_SCHEMA).validate(doc)


def test_build_assessment_results_pins_to_a_snapshot(tmp_path: Path) -> None:
    from security_lakehouse.assessment import write_assessment_snapshot
    from test_api_v1 import _seed_lake

    lake = tmp_path / "lake"
    lake.mkdir(parents=True)
    _seed_lake(lake)
    snapshot_path = write_assessment_snapshot(lake, reason="oscal-test")
    snapshot_id = snapshot_path.stem

    current = build_assessment_results(lake)
    pinned = build_assessment_results(lake, snapshot_id=snapshot_id)
    assert (
        pinned["assessment-results"]["metadata"]["last-modified"]
        == json.loads(snapshot_path.read_text())["evaluated_at"]
    )
    assert (
        current["assessment-results"]["metadata"]["last-modified"]
        != pinned["assessment-results"]["metadata"]["last-modified"]
    )

    def _status_by_control(doc: dict) -> dict[str, str]:
        return {
            next(p["value"] for p in f["props"] if p["name"] == "trustops-control-id"): f["target"]["status"]
            for f in doc["assessment-results"]["results"][0]["findings"]
        }

    # Metadata (evaluated_at, uuids seeded from the assessment hash) differs
    # between current and pinned. Both refer to the same generation here;
    # the pinned findings remain unchanged after a later publication.
    assert _status_by_control(current) == _status_by_control(pinned)


def test_build_assessment_results_unknown_snapshot_raises(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        build_assessment_results(lake, snapshot_id="does-not-exist")


# --- CLI ----------------------------------------------------------------------


def test_cli_oscal_export_component_definition(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["oscal", "export", "--component-definition"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "component-definition" in out


def test_cli_oscal_export_assessment_results(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lake = tmp_path / "lake"
    _seed_control_posture(lake)
    assert main(["oscal", "export", "--assessment-results", str(lake)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "assessment-results" in out


def test_cli_oscal_export_writes_to_file(tmp_path: Path) -> None:
    out_path = tmp_path / "component-definition.json"
    assert main(["oscal", "export", "--component-definition", "--out", str(out_path)]) == 0
    doc = json.loads(out_path.read_text())
    assert "component-definition" in doc


def test_cli_oscal_export_requires_exactly_one_mode() -> None:
    with pytest.raises(SystemExit):
        main(["oscal", "export"])
    with pytest.raises(SystemExit):
        main(["oscal", "export", "--component-definition", "--assessment-results", "somewhere"])


# --- API ------------------------------------------------------------------


def test_api_oscal_component_definition_route(tmp_path: Path) -> None:
    status, body = api_v1.handle_get("/api/v1/oscal/component-definition", {}, tmp_path)
    assert status == HTTPStatus.OK
    assert "component-definition" in body["data"]
    assert body["meta"]["resource"] == "oscal.component-definition"


def test_api_oscal_assessment_results_route(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    _seed_control_posture(lake)
    status, body = api_v1.handle_get("/api/v1/oscal/assessment-results", {}, lake)
    assert status == HTTPStatus.OK
    assert "assessment-results" in body["data"]
    assert body["meta"]["resource"] == "oscal.assessment-results"


def test_api_oscal_assessment_results_unknown_snapshot_is_404(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir(parents=True)
    status, body = api_v1.handle_get("/api/v1/oscal/assessment-results", {"snapshot_id": ["nope"]}, lake)
    assert status == HTTPStatus.NOT_FOUND
    assert body["errors"]


def test_resource_catalog_lists_oscal_routes() -> None:
    paths = {row["path"] for row in api_v1.resource_catalog()}
    assert "/api/v1/oscal/component-definition" in paths
    assert "/api/v1/oscal/assessment-results" in paths
