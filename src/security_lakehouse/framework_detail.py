"""Composed framework drill-down view.

The framework page needs more than registry metadata: reviewers need to see the
chain from framework source to local controls, rules, evidence, and data
sources. This module builds that read object without storing derived state.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.evidence_hints import enabled_connector_ids, resolve_connector_hints
from security_lakehouse.framework_provenance import build_framework_view
from security_lakehouse.generations import generation_reader
from security_lakehouse.io import read_jsonl
from security_lakehouse.jsontypes import JsonObject
from security_lakehouse.mappings import load_control_article_mappings


def _latest(values: list[str | None]) -> str | None:
    present = [value for value in values if value]
    return max(present) if present else None


def _source_rollups(evidence: list[JsonObject], freshness: list[JsonObject]) -> list[JsonObject]:
    freshness_by_event = {str(row.get("event_id") or ""): row for row in freshness}
    by_source: dict[str, list[JsonObject]] = defaultdict(list)
    for event in evidence:
        by_source[str(event.get("source") or "unknown")].append(event)

    out: list[JsonObject] = []
    for source, rows in by_source.items():
        related_freshness = [freshness_by_event.get(str(row.get("event_id") or "")) for row in rows]
        statuses = [str(row.get("status") or "unknown") for row in related_freshness if row]
        expired = statuses.count("expired")
        stale = statuses.count("stale")
        fresh = statuses.count("fresh")
        out.append(
            {
                "source": source,
                "event_count": len(rows),
                "fresh_count": fresh,
                "stale_count": stale,
                "expired_count": expired,
                "latest_evidence_at": _latest([str(row.get("evidence_collected_at") or "") for row in rows]),
            }
        )
    return sorted(out, key=lambda row: (-int(row["event_count"]), str(row["source"])))


@generation_reader
def build_framework_detail(framework_id: str, lake_dir: str | Path) -> JsonObject | None:
    """Return framework -> controls -> rules -> evidence -> source detail."""
    framework_id = str(framework_id or "").strip()
    lake = Path(lake_dir)
    frameworks = {str(row.get("framework_id") or ""): row for row in build_framework_view()}
    framework = frameworks.get(framework_id)
    if framework is None:
        return None

    catalog = load_control_catalog()
    mappings = load_control_article_mappings()
    posture_by_control = {
        str(row.get("control_id") or ""): row for row in read_jsonl(lake / "gold" / "control_posture.jsonl")
    }
    tests_by_control = {
        str(row.get("control_id") or ""): row for row in read_jsonl(lake / "gold" / "control_tests.jsonl")
    }
    evidence = read_jsonl(lake / "silver" / "normalized_events.jsonl")
    freshness = read_jsonl(lake / "gold" / "evidence_freshness.jsonl")
    configured_connectors = enabled_connector_ids(lake)
    connector_catalog = load_connector_catalog()

    evidence_by_control: dict[str, list[JsonObject]] = defaultdict(list)
    freshness_by_control: dict[str, list[JsonObject]] = defaultdict(list)
    for row in evidence:
        for control_id in row.get("control_ids") or []:
            evidence_by_control[str(control_id)].append(row)
    for row in freshness:
        for control_id in row.get("control_ids") or []:
            freshness_by_control[str(control_id)].append(row)

    control_rows: list[JsonObject] = []
    for control in catalog.values():
        if str(control.get("framework_id") or "") != framework_id:
            continue
        control_id = str(control.get("control_id") or "")
        posture = posture_by_control.get(control_id)
        test = tests_by_control.get(control_id)
        control_evidence = evidence_by_control.get(control_id, [])
        control_freshness = freshness_by_control.get(control_id, [])
        mapping = mappings.get(control_id, {})
        articles = mapping.get("articles") or []
        article_ids = [str(article.get("article_id") or "") for article in articles]
        connector_hints = resolve_connector_hints(
            framework_id=framework_id,
            control=control,
            article_ids=article_ids,
            enabled_connector_ids=configured_connectors,
            connector_catalog=connector_catalog,
        )
        control_rows.append(
            {
                "control_id": control_id,
                "title": control.get("title"),
                "owner": control.get("owner"),
                "risk_domain": control.get("risk_domain"),
                "frequency": control.get("frequency"),
                "implementation_status": control.get("implementation_status"),
                "evidence_requirement": control.get("evidence_requirement"),
                "evaluation_rule": control.get("evaluation_rule"),
                "official_source_ref": control.get("official_source_ref"),
                "articles": articles,
                "connector_hints": connector_hints,
                "posture": {
                    "status": (posture or {}).get("status") or "not_evaluated",
                    "risk_score": (posture or {}).get("risk_score"),
                    "evidence_coverage": (posture or {}).get("evidence_coverage"),
                    "open_event_count": (posture or {}).get("open_event_count", 0),
                    "rule_reasons": (posture or {}).get("rule_reasons") or [],
                },
                "test": {
                    "result": (test or {}).get("result") or "not_run",
                    "confidence_score": (test or {}).get("confidence_score"),
                    "freshness_status": (test or {}).get("freshness_status"),
                    "required_evidence_types": (test or {}).get("required_evidence_types") or [],
                    "observed_evidence_types": (test or {}).get("observed_evidence_types") or [],
                    "next_action": (test or {}).get("next_action"),
                },
                "evidence": {
                    "count": len(control_evidence),
                    "latest_evidence_at": _latest(
                        [str(row.get("evidence_collected_at") or "") for row in control_evidence]
                    ),
                    "freshness": {
                        "fresh": sum(1 for row in control_freshness if row.get("status") == "fresh"),
                        "stale": sum(1 for row in control_freshness if row.get("status") == "stale"),
                        "expired": sum(1 for row in control_freshness if row.get("status") == "expired"),
                    },
                    "sources": _source_rollups(control_evidence, control_freshness),
                },
            }
        )

    control_rows.sort(key=lambda row: str(row["control_id"]))
    framework_evidence: list[JsonObject] = []
    for row in control_rows:
        framework_evidence.extend(evidence_by_control.get(str(row["control_id"]), []))
    framework_evidence = list(
        {(str(row.get("source") or ""), str(row.get("event_id") or "")): row for row in framework_evidence}.values()
    )
    recommended = {hint["connector_id"] for row in control_rows for hint in row.get("connector_hints") or []}
    configured_recommended = {
        hint["connector_id"]
        for row in control_rows
        for hint in row.get("connector_hints") or []
        if hint.get("configured")
    }
    return {
        "framework": framework,
        "summary": {
            "control_count": len(control_rows),
            "mapped_control_count": sum(1 for row in control_rows if row["articles"]),
            "passing_control_count": sum(1 for row in control_rows if row["posture"]["status"] == "pass"),
            "failing_control_count": sum(1 for row in control_rows if row["posture"]["status"] == "fail"),
            "evidence_count": len(framework_evidence),
            "source_count": len({source["source"] for row in control_rows for source in row["evidence"]["sources"]}),
            "recommended_connector_count": len(recommended),
            "configured_recommended_connector_count": len(configured_recommended),
        },
        "controls": control_rows,
        "sources": _source_rollups(framework_evidence, freshness),
    }


def page_framework_detail(
    detail: JsonObject, *, limit: int = 20, offset: int = 0, include_details: bool = False
) -> JsonObject:
    """Bound response detail while retaining full framework counts."""
    if not 1 <= limit <= 100 or offset < 0:
        raise ValueError("limit must be 1..100 and offset must be nonnegative")
    rows = detail["controls"]
    page = rows[offset : offset + limit]
    if not include_details:
        page = [
            {
                **{key: row.get(key) for key in ("control_id", "title", "owner", "evaluation_rule", "posture")},
                "evidence": {
                    key: row.get("evidence", {}).get(key) for key in ("count", "latest_evidence_at", "freshness")
                },
            }
            for row in page
        ]
    return {
        "framework": detail["framework"],
        "summary": detail["summary"],
        "controls": page,
        "pagination": {
            "count": len(rows),
            "returned": len(page),
            "limit": limit,
            "offset": offset,
            "next_offset": offset + len(page) if offset + len(page) < len(rows) else None,
        },
        "detail_level": "full" if include_details else "compact",
    }
