"""SPRS score computation for CMMC Level 2 / NIST SP 800-171 Rev 2.

The Supplier Performance Risk System (SPRS) score starts at **110** when every
requirement is met. Each unmet requirement deducts its published weight (1, 3,
or 5). The minimum score is **-203**.
"""

from __future__ import annotations

import json
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.event_status import PASS_STATUSES, normalize_event_status
from security_lakehouse.evidence_freshness import summarize_control_freshness
from security_lakehouse.generations import generation_reader
from security_lakehouse.io import read_jsonl
from security_lakehouse.pack_data import PACK_DATA_DIR
from security_lakehouse.programs import with_program_requirements

SPRS_BASE_SCORE = 110
SPRS_MIN_SCORE = -203
CMMC_FRAMEWORK_ID = "cmmc-2-level2"


@lru_cache(maxsize=1)
def _cmmc_sprs_metadata() -> dict[str, dict[str, Any]]:
    path = PACK_DATA_DIR / "cmmc_2_level2.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        str(row["id"]): {
            "title": str(row["title"]),
            "sprs_points": int(row.get("sprs_points", 1)),
            "poam_eligible": bool(row.get("poam_eligible", True)),
        }
        for row in payload.get("requirements", [])
    }


def requirement_id_from_control(control_id: str) -> str | None:
    """Map ``CMMC-3.1.1`` → ``3.1.1``."""
    prefix = "CMMC-"
    if not control_id.startswith(prefix):
        return None
    article_id = control_id.removeprefix(prefix)
    return article_id if article_id in _cmmc_sprs_metadata() else None


def compute_sprs_score(
    *,
    failing_requirement_ids: set[str],
    risk_accepted_requirement_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Return SPRS score and per-requirement deduction breakdown."""
    metadata = _cmmc_sprs_metadata()
    risk_accepted = risk_accepted_requirement_ids or set()
    deductions: list[dict[str, Any]] = []
    total_deduction = 0
    for requirement_id, row in sorted(metadata.items(), key=lambda item: item[0]):
        if requirement_id in risk_accepted:
            continue
        if requirement_id not in failing_requirement_ids:
            continue
        points = int(row["sprs_points"])
        total_deduction += points
        deductions.append(
            {
                "requirement_id": requirement_id,
                "title": row["title"],
                "sprs_points": points,
                "poam_eligible": row["poam_eligible"],
            }
        )
    score = max(SPRS_MIN_SCORE, SPRS_BASE_SCORE - total_deduction)
    return {
        "framework_id": CMMC_FRAMEWORK_ID,
        "base_score": SPRS_BASE_SCORE,
        "minimum_score": SPRS_MIN_SCORE,
        "score": score,
        "deduction_total": total_deduction,
        "requirements_total": len(metadata),
        "requirements_met": len(metadata) - len(failing_requirement_ids),
        "requirements_unmet": len(failing_requirement_ids),
        "deductions": deductions,
    }


def _current_passing_requirements(lake: Path, candidates: set[str], control_tests: list[dict[str, Any]]) -> set[str]:
    """A saved pass can age into unknown; it cannot renew its own evidence.

    Keep the shared source/asset/type freshness populations and current catalog
    requirements. Observations cannot lend attachments to an evaluated result.
    This gates saved passes only; explicit saved failures keep precedence.
    """
    if not candidates:
        return set()
    events = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True, base_dir=lake)
    events_by_requirement: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        for control_id in event.get("control_ids", []):
            requirement = requirement_id_from_control(str(control_id))
            if requirement in candidates:
                events_by_requirement[requirement].append(event)
    catalog = with_program_requirements(load_control_catalog())
    connectors = load_connector_catalog()
    required: dict[str, set[str]] = defaultdict(set)
    for row in control_tests:
        if row.get("framework_id") == CMMC_FRAMEWORK_ID:
            required[str(row.get("control_id"))].update(row.get("required_evidence_types") or [])
    passing: set[str] = set()
    for requirement in candidates:
        control_id = f"CMMC-{requirement}"
        if control_id not in catalog:
            continue
        verdict_events = [
            event
            for event in events_by_requirement[requirement]
            if normalize_event_status(event.get("status")) != "observed"
        ]
        if not verdict_events or any(
            normalize_event_status(event.get("status")) not in PASS_STATUSES for event in verdict_events
        ):
            continue
        required[control_id].update(catalog[control_id].get("required_evidence_types") or [])
        freshness = summarize_control_freshness(
            verdict_events,
            required_evidence_types=sorted(required[control_id]),
            connectors=connectors,
        )
        if freshness["status"] == "fresh":
            passing.add(requirement)
    return passing


@generation_reader
def evaluate_cmmc_posture(lake_dir: str | Path) -> tuple[dict[str, Any], dict[str, str]]:
    """Return SPRS and explicit requirement outcomes from the same gold rows."""
    lake = Path(lake_dir)
    control_tests = read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True, base_dir=lake)
    outcomes: dict[str, set[str]] = {}
    for row in control_tests:
        if str(row.get("framework_id", "")) != CMMC_FRAMEWORK_ID:
            continue
        requirement_id = requirement_id_from_control(str(row.get("control_id", "")))
        if requirement_id:
            outcomes.setdefault(requirement_id, set()).add(str(row.get("result", "")).lower())
    failing = {key for key, values in outcomes.items() if values & {"fail", "failing", "open"}}
    passing = _current_passing_requirements(
        lake, {key for key, values in outcomes.items() if values == {"pass"}}, control_tests
    )
    unknown = set(_cmmc_sprs_metadata()) - failing - passing
    report = compute_sprs_score(failing_requirement_ids=failing)
    report.update(
        source="gold/control_tests.jsonl",
        requirements_met=len(passing),
        requirements_not_evaluated=len(unknown),
        assessment_complete=not unknown,
        score=report["score"] if not unknown else None,
    )
    verdicts = {
        key: "fail" if key in failing else "pass" if key in passing else "not_evaluated"
        for key in _cmmc_sprs_metadata()
    }
    return report, verdicts


def build_sprs_report(lake_dir: str | Path) -> dict[str, Any]:
    """Compute SPRS from gold control tests for the tenant lake."""
    return evaluate_cmmc_posture(lake_dir)[0]
