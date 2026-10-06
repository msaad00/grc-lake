"""SPRS score computation for CMMC Level 2 / NIST SP 800-171 Rev 2.

The Supplier Performance Risk System (SPRS) score starts at **110** when every
requirement is met. Each unmet requirement deducts its published weight (1, 3,
or 5). The minimum score is **-203**.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_jsonl
from security_lakehouse.pack_data import PACK_DATA_DIR

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


def build_sprs_report(lake_dir: str | Path) -> dict[str, Any]:
    """Compute SPRS from gold control tests for the tenant lake."""
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
    passing = {key for key, values in outcomes.items() if values == {"pass"}}
    unknown = set(_cmmc_sprs_metadata()) - failing - passing
    report = compute_sprs_score(failing_requirement_ids=failing)
    report.update(
        source="gold/control_tests.jsonl",
        requirements_met=len(passing),
        requirements_not_evaluated=len(unknown),
        assessment_complete=not unknown,
        score=report["score"] if not unknown else None,
    )
    return report
