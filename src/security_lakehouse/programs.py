"""Compliance program and continuous control test model."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import _data_root, load_control_catalog, load_framework_registry
from security_lakehouse.evidence_freshness import summarize_control_freshness
from security_lakehouse.models import utc_iso

ROOT = _data_root()
DEFAULT_PROGRAM_CATALOG = ROOT / "programs" / "catalog.json"
FAIL_STATUSES = {"open", "failed", "blocked", "noncompliant"}
LIFECYCLE = {
    "not_started",
    "collecting",
    "ready",
    "failing",
    "accepted_risk",
    "auditor_ready",
}


def load_program_catalog(path: str | Path | None = None) -> dict[str, Any]:
    payload = _read_json(path or DEFAULT_PROGRAM_CATALOG)
    programs = payload.get("programs")
    lifecycle = payload.get("status_lifecycle")
    if not isinstance(programs, list):
        raise ValueError("program catalog must contain a programs list")
    if not isinstance(lifecycle, list):
        raise ValueError("program catalog must contain a status_lifecycle list")
    return payload


def validate_program_catalog(path: str | Path | None = None) -> list[str]:
    errors: list[str] = []
    payload = load_program_catalog(path)
    frameworks = load_framework_registry()
    controls = load_control_catalog()
    lifecycle = {str(item) for item in payload["status_lifecycle"]}
    missing_lifecycle = LIFECYCLE - lifecycle
    if missing_lifecycle:
        errors.append(f"program catalog missing lifecycle states: {', '.join(sorted(missing_lifecycle))}")

    program_ids: set[str] = set()
    test_ids: set[str] = set()
    for program in payload["programs"]:
        program_id = str(program.get("program_id") or "")
        if not program_id:
            errors.append("program missing program_id")
            continue
        if program_id in program_ids:
            errors.append(f"duplicate program_id {program_id}")
        program_ids.add(program_id)

        framework_ids = {str(item) for item in program.get("framework_ids", [])}
        unknown_frameworks = framework_ids - set(frameworks)
        if unknown_frameworks:
            errors.append(
                f"program {program_id} references unknown frameworks: {', '.join(sorted(unknown_frameworks))}"
            )

        tests = program.get("control_tests")
        if not isinstance(tests, list) or not tests:
            errors.append(f"program {program_id} must define control_tests")
            continue
        for test in tests:
            test_id = str(test.get("test_id") or "")
            control_id = str(test.get("control_id") or "")
            if test_id in test_ids:
                errors.append(f"duplicate test_id {test_id}")
            test_ids.add(test_id)
            if control_id not in controls:
                errors.append(f"test {test_id} references unknown control_id {control_id}")
                continue
            control_framework = str(controls[control_id].get("framework_id"))
            if control_framework not in framework_ids:
                errors.append(f"test {test_id} control {control_id} is outside program frameworks")
            for required in ("name", "owner", "cadence", "automation_level", "required_evidence_types", "agent_skill"):
                value = test.get(required)
                if value in (None, "", []):
                    errors.append(f"test {test_id} missing {required}")
            if int(test.get("remediation_sla_hours") or 0) <= 0:
                errors.append(f"test {test_id} remediation_sla_hours must be positive")
    return errors


def build_control_tests(
    silver_rows: list[dict[str, Any]],
    control_rows: list[dict[str, Any]],
    *,
    program_path: str | Path | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    catalog = load_program_catalog(program_path)
    control_catalog = load_control_catalog()
    evaluated_at = now or datetime.now(UTC)
    test_configs = {
        str(test["control_id"]): (program, test) for program in catalog["programs"] for test in program["control_tests"]
    }
    events_by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in silver_rows:
        for control_id in event["control_ids"]:
            events_by_control[control_id].append(event)

    rows: list[dict[str, Any]] = []
    for control in control_rows:
        control_id = str(control["control_id"])
        program, config = test_configs.get(control_id, ({}, {}))
        evidence_events = events_by_control.get(control_id, [])
        failing_events = [event for event in evidence_events if event["status"] in FAIL_STATUSES]
        required_types = [
            str(item)
            for item in config.get("required_evidence_types")
            or control_catalog.get(control_id, {}).get("required_evidence_types")
            or []
        ]
        observed_types = sorted(
            {str(evidence_type) for event in evidence_events for evidence_type in _event_evidence_types(event)}
        )
        missing_types = sorted(set(required_types) - set(observed_types))
        freshness = summarize_control_freshness(
            evidence_events,
            required_evidence_types=required_types,
            now=evaluated_at,
            default_slo_minutes=int(program.get("default_freshness_days") or 7) * 24 * 60,
        )
        confidence_inputs = _confidence_inputs(control, evidence_events, missing_types, freshness, bool(config))
        confidence_score = _confidence_score(confidence_inputs)
        result = _test_result(control, evidence_events, failing_events, freshness)
        status = _lifecycle_status(result, confidence_score)
        rows.append(
            {
                "test_id": str(config.get("test_id") or f"test-{control_id.lower()}"),
                "program_id": str(program.get("program_id") or "trustops-framework-coverage"),
                "program_name": str(program.get("name") or "TrustOps Framework Coverage"),
                "control_id": control_id,
                "framework": str(control["framework"]),
                "framework_id": str(control_catalog.get(control_id, {}).get("framework_id", "unknown")),
                "name": str(config.get("name") or control["title"]),
                "owner": str(config.get("owner") or control["owner"]),
                "cadence": str(config.get("cadence") or "continuous"),
                "automation_level": str(config.get("automation_level") or "mapped_evidence_review"),
                "agent_skill": str(config.get("agent_skill") or "framework-control-analyst"),
                "status": status,
                "result": result,
                "confidence_score": confidence_score,
                "confidence_inputs": confidence_inputs,
                "required_evidence_types": required_types,
                "observed_evidence_types": observed_types,
                "missing_evidence_types": missing_types,
                "evidence_count": len(evidence_events),
                "failing_evidence_count": len(failing_events),
                "open_violation_count": len(failing_events),
                "latest_evidence_at": _latest_evidence_at(evidence_events),
                "freshness_status": freshness["status"],
                "stale_evidence_types": freshness["stale_evidence_types"],
                "expired_evidence_types": freshness["expired_evidence_types"],
                "evidence_freshness": freshness,
                "remediation_sla_hours": int(config.get("remediation_sla_hours") or 72),
                "next_action": _next_action(
                    result, missing_types, freshness, str(config.get("owner") or control["owner"])
                ),
                "api_refs": {
                    "control": f"/api/controls?control_id={control_id}",
                    "violations": f"/api/violations?control_id={control_id}",
                    "evidence": f"/api/evidence?control_id={control_id}",
                },
                "evaluated_at": utc_iso(evaluated_at),
            }
        )
    return sorted(rows, key=lambda item: (item["result"] == "pass", -int(item["confidence_score"]), item["control_id"]))


def _confidence_inputs(
    control: dict[str, Any],
    events: list[dict[str, Any]],
    missing_types: list[str],
    freshness: dict[str, Any],
    mapped_to_program: bool,
) -> dict[str, int]:
    evidence_coverage = int(round(float(control.get("evidence_coverage") or 0) * 100))
    type_coverage = 100 if not missing_types else max(0, int(round(100 - (len(missing_types) * 20))))
    source_health = min(100, len({event["source"] for event in events}) * 25)
    hash_integrity = 100 if events and all(len(str(event.get("raw_sha256", ""))) == 64 for event in events) else 0
    return {
        "evidence_coverage": evidence_coverage,
        "evidence_type_coverage": type_coverage,
        "freshness": int(freshness["score"]),
        "source_health": source_health,
        "mapping_quality": 100 if mapped_to_program else 0,
        "hash_integrity": hash_integrity,
    }


def _confidence_score(inputs: dict[str, int]) -> int:
    weights = {
        "evidence_coverage": 0.24,
        "evidence_type_coverage": 0.16,
        "freshness": 0.2,
        "source_health": 0.16,
        "mapping_quality": 0.14,
        "hash_integrity": 0.1,
    }
    return int(round(sum(inputs[key] * weight for key, weight in weights.items())))


def _test_result(
    control: dict[str, Any],
    events: list[dict[str, Any]],
    failing_events: list[dict[str, Any]],
    freshness: dict[str, Any],
) -> str:
    if not events or int(control.get("evidence_count") or 0) == 0:
        return "needs_evidence"
    if failing_events or control.get("status") == "fail":
        return "fail"
    if freshness["status"] in {"stale", "expired", "missing"}:
        return "needs_evidence"
    return "pass"


def _lifecycle_status(result: str, confidence_score: int) -> str:
    if result == "fail":
        return "failing"
    if result == "needs_evidence":
        return "collecting"
    if confidence_score >= 90:
        return "auditor_ready"
    return "ready"


def _next_action(result: str, missing_types: list[str], freshness: dict[str, Any], owner: str) -> str:
    if result == "pass":
        return "keep monitoring evidence freshness and source health"
    if missing_types:
        return f"request {', '.join(missing_types)} evidence from {owner}"
    stale_types = list(freshness.get("stale_evidence_types") or []) + list(
        freshness.get("expired_evidence_types") or []
    )
    if stale_types:
        return f"refresh stale {', '.join(sorted(stale_types))} evidence from {owner}"
    return f"open remediation workflow for {owner}"


def _latest_evidence_at(events: list[dict[str, Any]]) -> str | None:
    values = [str(event.get("evidence_collected_at") or event.get("event_time") or "") for event in events]
    values = [value for value in values if value]
    return max(values) if values else None


def _event_evidence_types(event: dict[str, Any]) -> list[str]:
    evidence_types = event.get("evidence_types")
    if isinstance(evidence_types, list):
        return [str(item) for item in evidence_types if str(item)]
    return [str(event.get("event_type") or "")]


def _read_json(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload
