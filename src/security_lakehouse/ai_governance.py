"""AI governance evidence aggregation for inventory, lineage, and framework mapping.

Rolls up ``ai.model_inventory``, ``model.lineage``, agent runtime signals, and
public-repo ``ai_artifact`` evidence into a single headless-first status payload.
The local AIBOM store adds stable CycloneDX/SPDX interchange without changing
the event-backed inventory and lineage evidence model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.aibom import aibom_status, list_aibom_items
from security_lakehouse.asset_names import load_asset_names, with_asset_names
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.evidence_freshness import build_evidence_freshness, stale_control_ids
from security_lakehouse.io import read_jsonl
from security_lakehouse.mapping_review import effective_safeguards
from security_lakehouse.models import instant_sort_key
from security_lakehouse.programs import with_program_requirements
from security_lakehouse.readiness_coverage import FRAMEWORK_READY_MIN_COVERAGE_PCT, readiness_coverage
from security_lakehouse.safeguards import framework_mapping_coverage

INVENTORY_EVENT_TYPES = frozenset(
    {
        "ai.model_inventory",
        "model.inventory",
    }
)
LINEAGE_EVENT_TYPES = frozenset({"model.lineage"})
AGENT_EVENT_TYPES = frozenset({"runtime.tool_call"})
REPO_ARTIFACT_EVENT_TYPES = frozenset({"repository.ai_artifact"})

AI_ASSET_TYPES = frozenset({"ai_model", "ai_agent", "model"})

AI_FRAMEWORKS: tuple[tuple[str, str, str], ...] = (
    ("nist-ai-rmf", "NIST AI RMF", "NIST-AI-RMF"),
    ("iso-42001-2023", "ISO/IEC 42001", "ISO42001"),
    ("eu-ai-act-2024-1689", "EU AI Act", "EU-AI-ACT"),
)


def _control_ids(row: dict[str, Any]) -> list[str]:
    ids = row.get("control_ids") or row.get("controls") or []
    return [str(item) for item in ids]


def _asset_id(row: dict[str, Any]) -> str:
    entity = row.get("entity") or {}
    return str(row.get("asset_id") or entity.get("asset_id") or "")


def _asset_type(row: dict[str, Any]) -> str:
    entity = row.get("entity") or {}
    return str(row.get("asset_type") or entity.get("asset_type") or "")


def _asset_owner(row: dict[str, Any]) -> str:
    entity = row.get("entity") or {}
    return str(row.get("asset_owner") or entity.get("owner") or entity.get("asset_owner") or "")


def _environment(row: dict[str, Any]) -> str:
    entity = row.get("entity") or {}
    return str(row.get("environment") or entity.get("environment") or "")


def _attributes(row: dict[str, Any]) -> dict[str, Any]:
    attrs = row.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def _is_ai_event(row: dict[str, Any]) -> bool:
    event_type = str(row.get("event_type") or "")
    if event_type in INVENTORY_EVENT_TYPES | LINEAGE_EVENT_TYPES | AGENT_EVENT_TYPES | REPO_ARTIFACT_EVENT_TYPES:
        return True
    asset_type = _asset_type(row)
    return asset_type in AI_ASSET_TYPES


def _framework_control_ids(controls: list[dict[str, Any]], prefix: str) -> set[str]:
    return {str(row["control_id"]) for row in controls if str(row.get("control_id", "")).startswith(prefix)}


def _event_control_ids(events: list[dict[str, Any]], prefix: str) -> set[str]:
    found: set[str] = set()
    for row in events:
        for control_id in _control_ids(row):
            if control_id.startswith(prefix):
                found.add(control_id)
    return found


def _framework_rows(
    *,
    controls: list[dict[str, Any]],
    events: list[dict[str, Any]],
    mapping_coverage: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Per-pack AI posture.

    Requirement and mapping counts come from the safeguard coverage the
    Frameworks page reads. The score is the pass rate over controls with a
    verdict or evidence in this lake, and ``None`` when there are none.
    """
    mapping_coverage = mapping_coverage if mapping_coverage is not None else framework_mapping_coverage()
    coverage = mapping_coverage["frameworks"]
    catalog = with_program_requirements(load_control_catalog())
    freshness = build_evidence_freshness(events)
    stale = stale_control_ids(
        freshness, required_types={key: row.get("required_evidence_types") or [] for key, row in catalog.items()}
    )
    evidenced = {str(control_id) for row in freshness for control_id in row["control_ids"]}
    rows: list[dict[str, Any]] = []
    for framework_id, label, prefix in AI_FRAMEWORKS:
        pack = coverage.get(framework_id, {})
        catalog_ids = {
            control_id for control_id, control in catalog.items() if control.get("framework_id") == framework_id
        }
        verdict_ids = _framework_control_ids(controls, prefix)
        event_ids = _event_control_ids(events, prefix)
        with_evidence = verdict_ids | event_ids
        passing = {
            str(row["control_id"])
            for row in controls
            if str(row.get("control_id", "")).startswith(prefix)
            and str(row.get("status", "")).lower() in {"pass", "passed", "ready"}
            and str(row["control_id"]) in catalog_ids
            and str(row["control_id"]) not in stale
            and str(row["control_id"]) in evidenced
        }
        failing_ids = {
            str(row["control_id"])
            for row in controls
            if str(row.get("control_id", "")) in catalog_ids
            and str(row.get("status", "")).lower() in {"fail", "failed", "open"}
        }
        failing = len(failing_ids)
        # Missing, stale, unknown, or non-catalog records cannot fill the gate's
        # numerator. Their observed population remains visible separately.
        evaluated = len(((passing | failing_ids) & evidenced) - stale)
        catalog_count = int(pack.get("controls") or 0)
        coverage_pct, sufficient = readiness_coverage(evaluated, catalog_count)
        # Evidence availability, not a successful control verdict.
        evidence_pct = round(100 * len(passing | event_ids) / max(len(with_evidence), 1), 1)
        score = round(100 * len(passing) / len(with_evidence)) if with_evidence else None
        rows.append(
            {
                "framework_id": framework_id,
                "label": label,
                "requirements": int(pack.get("controls") or 0),
                "mapped_requirements": int(pack.get("covered") or 0),
                "mapped_pct": float(pack.get("coverage_pct") or 0.0),
                "reviewed_requirements": int(pack.get("reviewed") or 0),
                "reviewed_pct": float(pack.get("reviewed_pct") or 0.0),
                "maintainer_reviewed_requirements": int(pack.get("maintainer_reviewed") or 0),
                "org_reviewed_requirements": int(pack.get("org_reviewed") or 0),
                "contextual_mapping_count": int(pack.get("contextual_mappings") or 0),
                "review_log_verified": bool(mapping_coverage["review_log_verified"]),
                "controls_with_evidence": len(with_evidence),
                "evaluated_control_count": evaluated,
                "catalog_control_count": catalog_count,
                "coverage_pct": coverage_pct,
                "coverage_sufficient": sufficient,
                "unknown_control_count": len(with_evidence - catalog_ids),
                "evidence_pct": evidence_pct,
                "failing_controls": failing,
                "passing_controls": len(passing),
                "unevaluated_controls": max(0, len(with_evidence) - len(passing) - failing),
                "score": score,
            }
        )
    return rows


def _framework_score(frameworks: list[dict[str, Any]]) -> int:
    """Fresh passing controls over the observed control scope."""
    total = sum(int(row.get("controls_with_evidence") or 0) for row in frameworks)
    passing = sum(int(row.get("passing_controls") or 0) for row in frameworks)
    return round(100 * passing / total) if total else 0


def _inventory_items(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_asset: dict[str, dict[str, Any]] = {}
    for row in events:
        if not _is_ai_event(row):
            continue
        asset_id = _asset_id(row)
        if not asset_id:
            continue
        asset_type = _asset_type(row)
        if asset_type not in AI_ASSET_TYPES and str(row.get("event_type") or "") not in INVENTORY_EVENT_TYPES:
            continue
        attrs = _attributes(row)
        item = by_asset.setdefault(
            asset_id,
            {
                "asset_id": asset_id,
                "asset_type": asset_type or "ai_model",
                "owner": _asset_owner(row),
                "environment": _environment(row),
                "model_card": False,
                "lineage_complete": False,
                "last_seen_at": str(row.get("event_time") or ""),
                "sources": [],
                "control_ids": [],
                "event_types": [],
            },
        )
        event_type = str(row.get("event_type") or "")
        if event_type and event_type not in item["event_types"]:
            item["event_types"].append(event_type)
        source = str(row.get("source") or "")
        if source and source not in item["sources"]:
            item["sources"].append(source)
        for control_id in _control_ids(row):
            if control_id not in item["control_ids"]:
                item["control_ids"].append(control_id)
        if attrs.get("model_card"):
            item["model_card"] = True
        if attrs.get("lineage_complete"):
            item["lineage_complete"] = True
        event_time = str(row.get("event_time") or "")
        if instant_sort_key(event_time) > instant_sort_key(item["last_seen_at"]):
            item["last_seen_at"] = event_time
        if not item["owner"]:
            item["owner"] = _asset_owner(row)
        if not item["environment"]:
            item["environment"] = _environment(row)
    return sorted(by_asset.values(), key=lambda row: row["asset_id"])


def _aibom_inventory_items(*, lake: Path) -> list[dict[str, Any]]:
    rows = []
    for item in list_aibom_items(lake=lake):
        rows.append(
            {
                "asset_id": str(item.get("id") or item.get("name")),
                "asset_type": "model" if item.get("type") == "machine-learning-model" else str(item.get("type")),
                "owner": "",
                "environment": "",
                "model_card": bool(item.get("model_card")),
                "lineage_complete": False,
                "last_seen_at": "",
                "sources": [str(item.get("source_format") or "aibom")],
                "control_ids": [],
                "event_types": ["aibom.inventory"],
            }
        )
    return rows


def build_ai_governance_status(*, lake: Path) -> dict[str, Any]:
    """Aggregate AI inventory, lineage, artifacts, and framework coverage."""
    events = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True)
    controls = read_jsonl(lake / "gold" / "control_posture.jsonl", missing_ok=True)
    ai_events = [row for row in events if _is_ai_event(row)]

    inventory_events = [row for row in ai_events if str(row.get("event_type") or "") in INVENTORY_EVENT_TYPES]
    lineage_events = [row for row in ai_events if str(row.get("event_type") or "") in LINEAGE_EVENT_TYPES]
    agent_events = [row for row in ai_events if str(row.get("event_type") or "") in AGENT_EVENT_TYPES]
    repo_artifacts = [row for row in ai_events if str(row.get("event_type") or "") in REPO_ARTIFACT_EVENT_TYPES]

    inventory_by_id = {row["asset_id"]: row for row in _aibom_inventory_items(lake=lake)}
    inventory_by_id.update({row["asset_id"]: row for row in _inventory_items(ai_events)})
    inventory = sorted(inventory_by_id.values(), key=lambda row: row["asset_id"])
    models = [row for row in inventory if row["asset_type"] in {"ai_model", "model"}]
    agents = [row for row in inventory if row["asset_type"] == "ai_agent"]
    with_model_card = sum(1 for row in inventory if row["model_card"])
    with_lineage = sum(1 for row in inventory if row["lineage_complete"] or "model.lineage" in row["event_types"])

    model_cards = with_model_card + len(repo_artifacts)
    mapping_coverage = framework_mapping_coverage(effective_safeguards(lake))
    frameworks = _framework_rows(controls=controls, events=events, mapping_coverage=mapping_coverage)

    gaps: list[dict[str, str]] = []
    if not inventory_events and not inventory:
        gaps.append(
            {
                "id": "model_inventory",
                "label": "No ai.model_inventory events in the lake",
                "href": "/console/connectors",
            }
        )
    if not lineage_events and not with_lineage:
        gaps.append(
            {
                "id": "model_lineage",
                "label": "No model.lineage events or lineage_complete inventory signals",
                "href": "/console/evidence",
            }
        )
    if model_cards == 0:
        gaps.append(
            {
                "id": "model_cards",
                "label": "No model cards or repo ai_artifact evidence",
                "href": "/console/evidence",
            }
        )
    if not agent_events and not agents:
        gaps.append(
            {
                "id": "agent_governance",
                "label": "No AI agent runtime governance events",
                "href": "/console/controls",
            }
        )

    framework_ready = sum(1 for row in frameworks if row["score"] == 100 and row["coverage_sufficient"])
    observed_frameworks = [row for row in frameworks if row["controls_with_evidence"] > 0]
    sufficient_coverage = bool(observed_frameworks) and all(row["coverage_sufficient"] for row in observed_frameworks)
    inventory_score = round(
        100
        * (
            (1 if inventory_events else 0)
            + (1 if lineage_events or with_lineage else 0)
            + (1 if model_cards else 0)
            + (1 if agent_events or agents else 0)
        )
        / 4
    )
    framework_score = _framework_score(frameworks)
    governance_score = round(inventory_score * 0.55 + framework_score * 0.45)
    state = (
        "governed"
        if governance_score >= 85 and not gaps and sufficient_coverage
        else ("on_track" if governance_score >= 60 else "needs_work")
    )

    return {
        "state": state,
        "state_reason": (
            "Framework coverage meets the threshold; the state also reflects inventory signals and the composite score."
            if sufficient_coverage
            else f"Insufficient framework coverage: current evaluated evidence must cover at least {FRAMEWORK_READY_MIN_COVERAGE_PCT:g}% of each observed AI framework's catalog."
        ),
        "coverage_sufficient": sufficient_coverage,
        "coverage_scope": "observed_ai_frameworks",
        "coverage_min_pct": FRAMEWORK_READY_MIN_COVERAGE_PCT,
        "frameworks_observed": len(observed_frameworks),
        "governance_score": governance_score,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "inventory": {
            "total": len(inventory),
            "models": len(models),
            "agents": len(agents),
            "with_model_card": with_model_card,
            "with_lineage": with_lineage,
        },
        "events": {
            "model_inventory": len(inventory_events),
            "model_lineage": len(lineage_events),
            "agent_runtime": len(agent_events),
            "repo_artifacts": len(repo_artifacts),
        },
        "artifacts": {
            "model_cards": model_cards,
            "repo_audit_signals": len(repo_artifacts),
        },
        "frameworks": frameworks,
        "review_log_verified": mapping_coverage["review_log_verified"],
        "frameworks_ready": framework_ready,
        "frameworks_total": len(frameworks),
        "gaps": gaps,
        "evidence_loops": {
            "inventory_events": bool(inventory_events),
            "lineage_events": bool(lineage_events or with_lineage),
            "model_cards": model_cards > 0,
            "agent_governance": bool(agent_events or agents),
        },
        "aibom": aibom_status(lake=lake),
    }


def list_ai_inventory(*, lake: Path, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Return paginated AI model/agent inventory rows from normalized events."""
    events = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True)
    ai_events = [row for row in events if _is_ai_event(row)]
    by_id = {row["asset_id"]: row for row in _aibom_inventory_items(lake=lake)}
    by_id.update({row["asset_id"]: row for row in _inventory_items(ai_events)})
    items = sorted(by_id.values(), key=lambda row: row["asset_id"])
    start = max(offset, 0)
    end = start + max(limit, 1)
    return with_asset_names(items[start:end], load_asset_names(lake))


__all__ = ["build_ai_governance_status", "list_ai_inventory"]
