"""Connector evidence hints — link controls to recommended data sources."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.pack_data import PACK_DATA_DIR

JsonObject = dict[str, Any]

HINTS_PATH = PACK_DATA_DIR / "evidence_connector_hints.json"

_DOMAIN_RATIONALE = {
    "identity": "Identity and access controls are evidenced from IdP and cloud IAM posture.",
    "monitoring": "Monitoring controls need audit logs, SIEM detections, or telemetry streams.",
    "controls-operations": "Operational controls map to cloud posture and configuration evidence.",
    "governance": "Governance controls use policy attestations, tickets, and documented approvals.",
    "risk-management": "Risk management controls use assessments, tickets, and audit exports.",
    "change-management": "Change controls are evidenced from VCS, CI, and deployment posture.",
    "vendor-risk": "Vendor controls use diligence questionnaires and third-party attestations.",
    "availability": "Availability controls use cloud service health and runtime telemetry.",
    "confidentiality": "Confidentiality controls use encryption posture and data-store evidence.",
    "processing-integrity": "Processing integrity controls use pipeline and repo governance evidence.",
    "privacy": "Privacy controls use IdP roster and policy acknowledgment evidence.",
    "ai-governance": "AI governance controls use model gateway logs and governance artifacts.",
}


@lru_cache(maxsize=1)
def _hints_payload() -> JsonObject:
    return json.loads(HINTS_PATH.read_text(encoding="utf-8"))


def _family_key(framework_id: str, article_ids: list[str]) -> str | None:
    if not article_ids:
        return None
    article_id = str(article_ids[0])
    if framework_id == "cmmc-2-level2":
        parts = article_id.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else None
    if framework_id == "cis-aws" or framework_id == "cis_aws":
        return article_id.split(".", 1)[0]
    if framework_id == "iso-27701-2025":
        return ".".join(article_id.split(".")[:3])
    if framework_id == "nist-800-171-rev3":
        return ".".join(article_id.split(".")[:2])
    if framework_id == "nis2-2022-2555":
        return article_id
    if framework_id == "dora-2022-2554":
        return article_id.split(".", 1)[0]
    if framework_id == "fedramp-moderate":
        token = article_id.split("-", 1)[0].upper()
        return token if token.isalpha() else None
    return None


def _ordered_connector_ids(
    *,
    framework_id: str,
    risk_domain: str,
    article_ids: list[str],
    asset_types: list[str],
) -> list[tuple[str, str]]:
    """Return (connector_id, priority) pairs in recommendation order."""
    payload = _hints_payload()
    seen: set[str] = set()
    ordered: list[tuple[str, str]] = []

    def add_many(ids: list[str], priority: str) -> None:
        for connector_id in ids:
            if connector_id in seen:
                continue
            seen.add(connector_id)
            ordered.append((connector_id, priority))

    family = _family_key(framework_id, article_ids)
    family_map = payload.get("framework_family_connectors", {}).get(framework_id, {})
    if family and family in family_map:
        add_many(list(family_map[family]), "primary")

    domain_map = payload.get("risk_domain_connectors", {}).get(risk_domain, {})
    add_many(list(domain_map.get("primary", [])), "primary")
    add_many(list(domain_map.get("secondary", [])), "secondary")

    asset_map = payload.get("asset_type_connectors", {})
    for asset_type in asset_types:
        add_many(list(asset_map.get(str(asset_type), [])), "secondary")

    return ordered[:6]


def resolve_connector_hints(
    *,
    framework_id: str,
    control: JsonObject,
    article_ids: list[str],
    enabled_connector_ids: set[str] | None = None,
) -> list[JsonObject]:
    """Return recommended connectors for a control with configured state."""
    catalog = load_connector_catalog()
    enabled = enabled_connector_ids or set()
    risk_domain = str(control.get("risk_domain") or "governance")
    asset_types = [str(item) for item in control.get("asset_types") or []]
    rationale = _DOMAIN_RATIONALE.get(risk_domain, "Connect sources that prove this control in your environment.")

    hints: list[JsonObject] = []
    for connector_id, priority in _ordered_connector_ids(
        framework_id=framework_id,
        risk_domain=risk_domain,
        article_ids=article_ids,
        asset_types=asset_types,
    ):
        entry = catalog.get(connector_id)
        if entry is None:
            continue
        hints.append(
            {
                "connector_id": connector_id,
                "name": entry.get("name") or connector_id,
                "vendor": entry.get("vendor") or "",
                "category": entry.get("category") or "",
                "priority": priority,
                "configured": connector_id in enabled,
                "production_status": entry.get("production_status") or "",
                "evidence_types": list(entry.get("evidence_types") or []),
                "setup_hint": entry.get("setup_hint") or "",
                "rationale": rationale,
            }
        )
    return hints


def enabled_connector_ids(lake_dir: str | Path) -> set[str]:
    from security_lakehouse.connector_state import build_catalog_view

    return {
        str(row.get("connector_id") or "")
        for row in build_catalog_view(Path(lake_dir))
        if str(row.get("state") or "") == "enabled"
    }
