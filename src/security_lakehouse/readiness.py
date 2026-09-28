"""Staged framework readiness gate.

A framework is "implemented" only after every gate below closes. The UI
shows the current stage so reviewers can see exactly what's blocking a
coverage claim.

Stages (advance left → right):
  source_pulled        official source fetched + sha256 + pulled_at populated
  mapped               every control has a reviewed control_id ↔ article mapping
  evidence_defined     every control declares an evidence_requirement (catalog)
  rule_versioned       every control declares an evaluation_rule (catalog)
  coverage_verified    mapping_coverage_pct ≥ 95 AND every prior gate is closed

The earliest unmet gate is reported per framework so the UI surface "what to
fix next" is unambiguous.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from security_lakehouse.catalog import load_control_catalog, load_framework_registry
from security_lakehouse.mappings import article_mapping_reviewed, load_control_article_mappings

STAGES = (
    "source_pulled",
    "mapped",
    "evidence_defined",
    "rule_versioned",
    "coverage_verified",
)

COVERAGE_THRESHOLD = 95.0


def build_readiness_view() -> list[dict[str, Any]]:
    """Return per-framework readiness state + the earliest unmet gate."""
    frameworks = load_framework_registry()
    controls = load_control_catalog()
    mappings = load_control_article_mappings()

    controls_by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls.values():
        controls_by_framework[str(control.get("framework_id") or "")].append(control)

    out: list[dict[str, Any]] = []
    for framework_id, framework in frameworks.items():
        framework_controls = controls_by_framework.get(framework_id, [])
        control_count = len(framework_controls)

        # Gate 1: source pulled
        source_pulled = bool(framework.get("source_sha256")) and bool(framework.get("pulled_at"))

        # Gate 2: every control mapped to ≥1 article
        if control_count == 0:
            mapped_count = 0
            mapped = False
        else:
            mapped_count = sum(
                1 for c in framework_controls if article_mapping_reviewed(mappings.get(str(c.get("control_id") or "")))
            )
            mapped = mapped_count == control_count

        # Gate 3: every control has evidence_requirement
        evidence_defined = control_count > 0 and all(
            str(c.get("evidence_requirement") or "").strip() for c in framework_controls
        )

        # Gate 4: every control has evaluation_rule
        rule_versioned = control_count > 0 and all(
            str(c.get("evaluation_rule") or "").strip() for c in framework_controls
        )

        # Gate 5: coverage threshold
        coverage_pct = (mapped_count / control_count * 100.0) if control_count else 0.0
        coverage_verified = (
            source_pulled and mapped and evidence_defined and rule_versioned and coverage_pct >= COVERAGE_THRESHOLD
        )

        gates = {
            "source_pulled": source_pulled,
            "mapped": mapped,
            "evidence_defined": evidence_defined,
            "rule_versioned": rule_versioned,
            "coverage_verified": coverage_verified,
        }
        earliest_unmet = next((stage for stage in STAGES if not gates[stage]), None)

        out.append(
            {
                "framework_id": framework_id,
                "name": framework.get("name"),
                "version": framework.get("version"),
                "control_count": control_count,
                "mapped_control_count": mapped_count,
                "coverage_pct": round(coverage_pct, 1),
                "gates": gates,
                "stage": earliest_unmet or "coverage_verified",
                "is_ready": gates["coverage_verified"],
            }
        )
    out.sort(key=lambda r: r["framework_id"])
    return out
