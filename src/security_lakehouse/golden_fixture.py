"""Unified golden demo fixture for the console dashboard.

Ships one canonical mockup company (``golden``) whose raw evidence covers all
33 SOC 2 common-criteria controls plus four representative NIST AI RMF
subcategories — 37 controls total on the workbench dashboard without live
connectors — plus a handful of repository-governance events for one public repo.

``mockup_companies/golden/raw/security_events.jsonl`` is generated from this
module (``grc-lake fixtures write-golden``); a test keeps the two
identical. Asset IDs are stable identifiers; each asset also carries a
human-readable ``asset_name`` that the console shows instead of the ID.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.fixtures import FIXTURES_DIR
from security_lakehouse.validation import validate_raw_events

GOLDEN_COMPANY = "golden"
GOLDEN_TENANT_ID = "acme-golden"

GOLDEN_NIST_CONTROLS: tuple[str, ...] = (
    "NIST-AI-RMF-MAP-1.5",
    "NIST-AI-RMF-MEASURE-2.7",
    "NIST-AI-RMF-GOVERN-1.2",
    "NIST-AI-RMF-MANAGE-2.3",
)

_EVENT_TYPES = (
    "cloud.config",
    "iam.access_review",
    "monitoring.audit",
    "monitoring.detection",
    "scm.branch_protection",
    "scanner.dependency",
    "model.lineage",
    "runtime.inference",
)
# Source follows the event, so a model-drift alert never appears to come from AWS Config.
_SOURCE_BY_EVENT = {
    "cloud.config": "aws_config",
    "iam.access_review": "okta",
    "monitoring.audit": "audit_log",
    "monitoring.detection": "siem",
    "scm.branch_protection": "github",
    "scanner.dependency": "github",
    "model.lineage": "model_registry",
    "runtime.inference": "runtime_gateway",
}
# Asset type follows the event so the demo never shows, say, a branch-protection check on a "model".
_ASSET_TYPE_BY_EVENT = {
    "cloud.config": "data_store",
    "iam.access_review": "iam_role",
    "monitoring.audit": "audit_trail",
    "monitoring.detection": "audit_trail",
    "scm.branch_protection": "repository",
    "scanner.dependency": "repository",
    "model.lineage": "model",
    "runtime.inference": "agent",
}
_STATUSES = ("passed", "open", "passed", "open", "blocked", "passed", "open", "passed")

# AI assets keep the model/agent IDs the demo has always used.
_AI_ASSET_IDS = {
    6: "golden:model:risk-scorer",
    7: "golden:agent:triage-agent",
    14: "golden:model:support-assistant",
    15: "golden:agent:ops-copilot",
    22: "golden:model:fraud-detector",
    23: "golden:agent:ticket-router",
    30: "golden:model:doc-summarizer",
    31: "golden:agent:release-helper",
}

# One display name per golden control row, in control order. Each name fits the
# row's asset type (see ``_ASSET_TYPE_BY_EVENT``).
_ASSET_NAMES = (
    "Customer records bucket",
    "Production admin role",
    "Cloud audit trail",
    "Threat detection feed",
    "payments-api repository",
    "billing-worker repository",
    "Risk scorer model",
    "Triage agent",
    "Billing database",
    "CI deploy role",
    "Identity provider system log",
    "SIEM detection rules",
    "web-console repository",
    "mobile-app repository",
    "Support assistant model",
    "Ops copilot agent",
    "Analytics warehouse",
    "Support read-only role",
    "Source control audit log",
    "Endpoint alert stream",
    "infra-terraform repository",
    "data-ingest repository",
    "Fraud detector model",
    "Ticket router agent",
    "Backup vault",
    "Break-glass admin role",
    "Kubernetes API audit log",
    "Web firewall alert stream",
    "auth-service repository",
    "docs-site repository",
    "Doc summarizer model",
    "Release helper agent",
    "Log archive bucket",
    "ML platform role",
    "Model evaluation audit log",
    "Model drift alert stream",
    "ml-pipelines repository",
)

_REPO_ASSET = {
    "asset_id": "github:repo:acme/model-service",
    "asset_name": "acme/model-service repository",
    "asset_type": "repository",
    "asset_owner": "acme",
}
_REPO_TIME = "2026-05-24T12:00:00Z"


def _repository_events(tenant_id: str) -> list[dict[str, Any]]:
    """Public-repo and repo-governance evidence for the demo's one source repository."""
    public = {**_REPO_ASSET, "environment": "public", "repo": "acme/model-service"}
    repo_id = _REPO_ASSET["asset_id"]
    return [
        {
            "event_id": "repo-code-graph",
            "tenant_id": tenant_id,
            "event_time": _REPO_TIME,
            "source": "github-public-repo",
            "event_type": "repository.code_graph",
            "entity": dict(public),
            "severity": "info",
            "status": "observed",
            "controls": [],
            "evidence": {
                "evidence_id": "ev-code-graph",
                "evidence_ref": "https://github.com/acme/model-service",
                "collected_at": _REPO_TIME,
            },
            "attributes": {
                "nodes": [
                    {"id": repo_id, "kind": "repository", "label": "acme/model-service"},
                    {"id": f"{repo_id}:dir:.github", "kind": "directory", "label": ".github"},
                    {"id": f"{repo_id}:signal:ci_workflow", "kind": "evidence_signal", "label": "ci_workflow"},
                ],
                "edges": [
                    {"source": repo_id, "target": f"{repo_id}:dir:.github", "kind": "contains"},
                    {"source": repo_id, "target": f"{repo_id}:signal:ci_workflow", "kind": "has_signal"},
                ],
                "counts": {"signals": 1},
            },
        },
        {
            "event_id": "repo-codeowners",
            "tenant_id": tenant_id,
            "event_time": _REPO_TIME,
            "source": "github-public-repo",
            "event_type": "repository.codeowners",
            "entity": dict(public),
            "severity": "info",
            "status": "observed",
            "controls": ["SOC2-CC6.1"],
            "evidence": {"evidence_id": "ev-codeowners"},
            "attributes": {"paths": [".github/CODEOWNERS"], "path_count": 1},
        },
        {
            "event_id": "repo-auth-gap",
            "tenant_id": tenant_id,
            "event_time": _REPO_TIME,
            "source": "github-public-repo",
            "event_type": "repository.authenticated_signal_gap",
            "entity": dict(public),
            "severity": "info",
            "status": "requires_authenticated_connector",
            "controls": [],
            "evidence": {"evidence_id": "ev-auth-gap"},
            "attributes": {"requires_authenticated_connector": ["branch_protection_rules"]},
        },
        {
            "event_id": "repo-branch",
            "tenant_id": tenant_id,
            "event_time": _REPO_TIME,
            "source": "github-repo-governance",
            "event_type": "repository.governance.branch_protection",
            "entity": {**_REPO_ASSET, "environment": "prod", "repo": "acme/model-service", "provider": "github"},
            "severity": "info",
            "status": "observed",
            "controls": ["SOC2-CC6.1", "ISO27001-A.5.15"],
            "evidence": {
                "evidence_id": "ev-branch",
                "evidence_ref": "https://api.github.com/repos/acme/model-service",
                "collected_at": _REPO_TIME,
            },
            "attributes": {
                "governance": {
                    "available": True,
                    "required_pull_request_reviews": {"required_approving_review_count": 2},
                    "required_status_checks": {"contexts": ["quality", "web"]},
                }
            },
        },
    ]


def golden_control_ids() -> list[str]:
    """Return the 37 control IDs the golden fixture is designed to populate."""
    catalog = load_control_catalog()
    soc2 = sorted(control_id for control_id in catalog if control_id.startswith("SOC2-CC"))
    missing = [control_id for control_id in GOLDEN_NIST_CONTROLS if control_id not in catalog]
    if missing:
        raise ValueError(f"golden fixture references unknown controls: {missing}")
    if len(soc2) != 33:
        raise ValueError(f"expected 33 SOC 2 controls in catalog, found {len(soc2)}")
    return soc2 + list(GOLDEN_NIST_CONTROLS)


def build_golden_events(
    *, tenant_id: str = GOLDEN_TENANT_ID, base_time: datetime | None = None
) -> list[dict[str, Any]]:
    """Synthesize one validated raw event per golden control ID."""
    base = (base_time or datetime(2026, 6, 30, 12, 0, 0, tzinfo=UTC)).astimezone(UTC)
    control_ids = golden_control_ids()
    if len(control_ids) != len(_ASSET_NAMES):
        raise ValueError(f"golden fixture has {len(_ASSET_NAMES)} asset names for {len(control_ids)} controls")
    rows: list[dict[str, Any]] = []
    for index, control_id in enumerate(control_ids):
        status = _STATUSES[index % len(_STATUSES)]
        severity = (
            "critical" if status in {"open", "blocked"} and index % 5 == 0 else "high" if status == "open" else "info"
        )
        event_time = base + timedelta(minutes=index)
        collected = event_time + timedelta(minutes=1)
        event_type = _EVENT_TYPES[index % len(_EVENT_TYPES)]
        asset_type = _ASSET_TYPE_BY_EVENT[event_type]
        rows.append(
            {
                "tenant_id": tenant_id,
                "event_id": f"golden-{index + 1:03d}",
                "event_time": event_time.isoformat().replace("+00:00", "Z"),
                "event_type": event_type,
                "source": _SOURCE_BY_EVENT[event_type],
                "severity": severity,
                "status": status,
                "entity": {
                    "asset_id": _AI_ASSET_IDS.get(index, f"golden:asset:{control_id.lower()}"),
                    "asset_name": _ASSET_NAMES[index],
                    "asset_type": asset_type,
                    "environment": "prod",
                    "owner": "security-platform",
                },
                "controls": [control_id],
                "evidence": {
                    "collected_at": collected.isoformat().replace("+00:00", "Z"),
                    "evidence_id": f"ev-golden-{index + 1:03d}",
                    "uri": f"s3://acme-golden-evidence/{control_id}/golden-{index + 1:03d}.json",
                },
                "attributes": {
                    "fixture": GOLDEN_COMPANY,
                    "control_id": control_id,
                    "demo": True,
                },
            }
        )
    errors = validate_raw_events(rows)
    if errors:
        raise ValueError("; ".join(errors))
    return rows


def build_golden_fixture_rows(*, tenant_id: str = GOLDEN_TENANT_ID) -> list[dict[str, Any]]:
    """Every row of the committed golden fixture: control events, then repository events."""
    rows = build_golden_events(tenant_id=tenant_id) + _repository_events(tenant_id)
    errors = validate_raw_events(rows)
    if errors:
        raise ValueError("; ".join(errors))
    return rows


def render_golden_fixture() -> str:
    """The exact text of ``mockup_companies/golden/raw/security_events.jsonl``."""
    return "\n".join(json.dumps(row, separators=(",", ":")) for row in build_golden_fixture_rows()) + "\n"


def golden_fixture_path(root: Path | None = None) -> Path:
    """Path to ``mockup_companies/golden/raw/security_events.jsonl``."""
    return (root or FIXTURES_DIR) / GOLDEN_COMPANY / "raw" / "security_events.jsonl"


def write_golden_fixture(*, root: Path | None = None) -> Path:
    """Write the golden JSONL fixture and return its path."""
    path = golden_fixture_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_golden_fixture(), encoding="utf-8")
    return path


def golden_fixture_summary() -> dict[str, Any]:
    """Return control coverage metadata for CLI and tests."""
    control_ids = golden_control_ids()
    return {
        "company": GOLDEN_COMPANY,
        "tenant_id": GOLDEN_TENANT_ID,
        "control_count": len(control_ids),
        "soc2_control_count": 33,
        "nist_ai_control_count": len(GOLDEN_NIST_CONTROLS),
        "controls": control_ids,
    }
