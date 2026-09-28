"""Transport-agnostic ``/api/v1`` contract for headless humans and agents.

Both deployment modes build their versioned responses from this module:

- the zero-dependency stdlib server (:mod:`security_lakehouse.server`)
- the optional FastAPI server (:mod:`security_lakehouse.server_app`)

Keeping the envelope, collection controls, and route table here means the
agent-facing contract cannot drift between local mode and server mode.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Mapping
from http import HTTPStatus
from pathlib import Path
from typing import Any

from security_lakehouse.ai_governance import build_ai_governance_status, list_ai_inventory
from security_lakehouse.assessment import (
    SnapshotWrittenHook,
    build_current_posture,
    posture_as_of,
    verify_snapshot_chain,
    write_assessment_snapshot,
)
from security_lakehouse.asset_names import load_asset_names, with_asset_names
from security_lakehouse.connector_runner import ConnectorSyncError, run_connector_sync
from security_lakehouse.connector_state import (
    LOCAL_ONLY_OPTIONS as _LOCAL_ONLY_OPTIONS,
)
from security_lakehouse.connector_state import (
    append_config_event,
    build_catalog_view,
    configure_payload_error,
    enablement_probe_error,
    latest_config,
    list_runs,
    resolve_configure_payload,
    run_discovery,
    run_probe,
)
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.framework_detail import build_framework_detail
from security_lakehouse.framework_provenance import build_framework_view
from security_lakehouse.generations import generation_identity, generation_reader
from security_lakehouse.graph import (
    analyze_coverage,
    build_compliance_graph,
    build_framework_crosswalk,
    build_repository_graph,
)
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.io import read_jsonl, resolve_path
from security_lakehouse.lake_eval import list_eval_runs, run_lake_eval
from security_lakehouse.lake_scale import connector_materialize_on_sync
from security_lakehouse.mapping_review import (
    MappingReviewError,
    effective_safeguards,
    list_decisions,
    list_review_items,
    record_decisions,
    review_progress,
    verify_review_log,
)
from security_lakehouse.mappings import (
    build_framework_equivalence,
    build_reviewed_crosswalk,
    load_control_article_mappings,
)
from security_lakehouse.oscal import build_assessment_results, build_component_definition
from security_lakehouse.readiness import build_readiness_view
from security_lakehouse.safeguards import (
    PENDING_STATES,
    REVIEW_STATE_LABELS,
    coverage_by_family,
    coverage_by_framework,
)
from security_lakehouse.tracking import ALLOWED_STATES, append_event, latest_state, list_events, verify_tracking_chain
from security_lakehouse.trust_share import create_share, list_shares, revoke_share
from security_lakehouse.verification import verify_event
from security_lakehouse.workflows import (
    action_catalog,
    approve_workflow_run,
    get_workflow,
    get_workflow_run,
    list_workflows,
    reject_workflow_run,
    retry_workflow_run,
    run_action,
    run_workflow,
    save_workflow,
)
from security_lakehouse.workflows import (
    list_runs as list_workflow_runs,
)

API_VERSION = "v1"

Params = Mapping[str, list[str]]
JsonObject = dict[str, Any]


def envelope(resource: str, data: Any, *, meta: JsonObject | None = None) -> JsonObject:
    """Wrap a payload in the stable v1 envelope."""
    return {
        "data": data,
        "meta": {"api_version": API_VERSION, "resource": resource, **(meta or {})},
        "errors": [],
    }


def error_envelope(code: str, detail: str, *, resource: str = "unknown") -> JsonObject:
    """Build the v1 error envelope."""
    return {
        "data": None,
        "meta": {"api_version": API_VERSION, "resource": resource},
        "errors": [{"code": code, "detail": detail}],
    }


def list_snapshots(lake_dir: str | Path) -> list[JsonObject]:
    """Summarize point-in-time assessment snapshots written to the gold zone."""
    snapshots_dir = Path(lake_dir) / "gold" / "snapshots"
    if not snapshots_dir.is_dir():
        return []
    out: list[JsonObject] = []
    for path in sorted(snapshots_dir.glob("assessment-*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        posture = payload.get("posture") or {}
        out.append(
            {
                "snapshot_id": path.stem,
                "snapshot_path": str(path),
                "evaluated_at": payload.get("evaluated_at"),
                "reason": payload.get("snapshot_reason") or "manual",
                "assessment_hash": payload.get("assessment_hash"),
                "posture_score": posture.get("score"),
                "open_violation_count": posture.get("open_violation_count"),
                "critical_violation_count": posture.get("critical_violation_count"),
            }
        )
    return out


def _ccf_coverage(lake: Path) -> JsonObject:
    effective = effective_safeguards(lake)
    return {
        "families": coverage_by_family(effective),
        "frameworks": coverage_by_framework(effective),
        "review_log_verified": bool(effective["review_log_verified"]),
    }


# Route -> (resource name, loader) for endpoints returning a single object.
SINGLETON_LOADERS: dict[str, tuple[str, Callable[[Path], Any]]] = {
    "/api/v1/healthz": ("healthz", lambda _lake: {"ok": True, "service": "trustops-assessment"}),
    "/api/v1/ingestion/status": ("ingestion.status", build_ingestion_status),
    "/api/v1/posture/current": ("posture.current", build_current_posture),
    "/api/v1/graph/coverage": ("graph.coverage", analyze_coverage),
    "/api/v1/platform/ai-governance": ("platform.ai-governance", lambda lake: build_ai_governance_status(lake=lake)),
    "/api/v1/repo-graph": ("repo-graph", build_repository_graph),
    "/api/v1/graph": ("graph", build_compliance_graph),
    # Crosswalk and equivalence are computed from the control catalog and the
    # curated mapping files, not from the lake, so they ignore the lake path.
    "/api/v1/crosswalk": ("crosswalk", lambda _lake: build_framework_crosswalk()),
    "/api/v1/crosswalk/reviewed": ("crosswalk.reviewed", lambda _lake: build_reviewed_crosswalk()),
    "/api/v1/mappings/equivalence": ("mappings.equivalence", lambda _lake: build_framework_equivalence()),
    # CCF coverage and the OSCAL component definition read the shipped safeguards
    # with this lake's org review decisions layered on (mapping_review).
    "/api/v1/ccf/coverage": ("ccf.coverage", _ccf_coverage),
    "/api/v1/oscal/component-definition": (
        "oscal.component-definition",
        lambda lake: build_component_definition(lake_dir=lake),
    ),
}

# Route -> (resource name, loader) for endpoints returning a row collection.
COLLECTION_LOADERS: dict[str, tuple[str, Callable[[Path], list[JsonObject]]]] = {
    "/api/v1/controls": (
        "controls",
        lambda lake: read_jsonl(lake / "gold" / "control_posture.jsonl", missing_ok=True, base_dir=lake),
    ),
    "/api/v1/control-tests": (
        "control-tests",
        lambda lake: read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True, base_dir=lake),
    ),
    "/api/v1/evidence": (
        "evidence",
        lambda lake: with_asset_names(
            read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True, base_dir=lake),
            load_asset_names(lake),
        ),
    ),
    "/api/v1/evidence/freshness": (
        "evidence.freshness",
        lambda lake: read_jsonl(lake / "gold" / "evidence_freshness.jsonl", missing_ok=True, base_dir=lake),
    ),
    "/api/v1/assets": (
        "assets",
        lambda lake: read_jsonl(lake / "gold" / "asset_risk.jsonl", missing_ok=True, base_dir=lake),
    ),
    "/api/v1/violations": ("violations", lambda lake: build_current_posture(lake)["violations"]),
    "/api/v1/snapshots": ("snapshots", list_snapshots),
    "/api/v1/ingestion/eval/runs": ("ingestion.eval.runs", list_eval_runs),
    "/api/v1/platform/ai-governance/inventory": (
        "platform.ai-governance.inventory",
        lambda lake: list_ai_inventory(lake=lake, limit=10_000, offset=0),
    ),
    "/api/v1/mappings": ("mappings", lambda _lake: list(load_control_article_mappings().values())),
    "/api/v1/frameworks": ("frameworks", lambda _lake: build_framework_view()),
    "/api/v1/readiness": ("readiness", lambda _lake: build_readiness_view()),
    "/api/v1/workflows": ("workflows", list_workflows),
    "/api/v1/workflows/actions": ("workflows.actions", lambda _lake: action_catalog()),
}

# Resources that also accept writes via handle_post.
_WRITABLE = {
    "/api/v1/snapshots": ["POST"],
    "/api/v1/ingestion/eval": ["POST"],
    "/api/v1/scheduler/tick": ["POST"],
    "/api/v1/trust-shares": ["POST"],
    "/api/v1/workflows": ["POST"],
}


def _suffix_match(path: str, prefix: str, suffix: str) -> str | None:
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    rest = path[len(prefix) : -len(suffix)]
    return rest or None


def _workflow_id_match(path: str) -> str | None:
    """Match /api/v1/workflows/<id>, excluding the sibling routes.

    ``actions`` and ``runs`` are route segments, not workflow ids, and a
    nested path is a different route -- so both are rejected here rather
    than being looked up as a workflow that will never exist.
    """
    prefix = "/api/v1/workflows/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :]
    if rest in {"", "actions", "runs"} or "/" in rest:
        return None
    return rest


def _workflow_run_id_match(path: str) -> str | None:
    """Match /api/v1/workflows/runs/<run_id>."""
    prefix = "/api/v1/workflows/runs/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :].strip("/")
    if not rest or "/" in rest:
        return None
    return rest


def _connector_action(path: str, action: str) -> str | None:
    return _suffix_match(path, "/api/v1/connectors/", f"/{action}")


def _connector_link_action(path: str, suffix: str) -> str | None:
    return _suffix_match(path, "/api/v1/connectors/", f"/link/{suffix}")


# Fail-closed default for any mutating route not explicitly scoped below. It is a
# scope no role in ROLE_SCOPES holds, so a POST path added to handle_post but
# forgotten here is denied (403) instead of quietly accepting the low `write`
# scope. Every path handle_post actually dispatches is enumerated below, so this
# is only ever reached by unknown routes.
_UNMAPPED_POST_SCOPE = "__unmapped_post__"


def required_post_scope(path: str) -> str:
    """Return the RBAC scope required to mutate a v1 route (fail-closed default)."""
    if path == "/api/v1/snapshots":
        return "snapshot"
    # Trust shares hand a reviewer a signed view of posture, so they carry the
    # same scope as writing a snapshot -- matching the pre-v1 route exactly.
    if path == "/api/v1/trust-shares":
        return "snapshot"
    if _suffix_match(path, "/api/v1/trust-shares/", "/revoke") is not None:
        return "snapshot"
    # Workflows split two ways and the split is deliberate: executing a saved
    # workflow is `workflow_run`, while defining one or ruling on a run that
    # paused for approval is `workflow_manage`. Flattening these would let a
    # runner approve its own run.
    if _suffix_match(path, "/api/v1/violations/", "/triage") is not None:
        return "write"
    if _suffix_match(path, "/api/v1/evidence/", "/verify") is not None:
        return "write"
    if path == "/api/v1/workflows":
        return "workflow_manage"
    if path == "/api/v1/workflows/actions/run":
        return "workflow_run"
    workflow_run_path = _suffix_match(path, "/api/v1/workflows/", "/run")
    if workflow_run_path is not None and workflow_run_path != "actions":
        return "workflow_run"
    if _suffix_match(path, "/api/v1/workflows/runs/", "/retry") is not None:
        return "workflow_run"
    if _suffix_match(path, "/api/v1/workflows/runs/", "/approve") is not None:
        return "workflow_manage"
    if _suffix_match(path, "/api/v1/workflows/runs/", "/reject") is not None:
        return "workflow_manage"
    if path == "/api/v1/mapping-reviews/decisions":
        return "mapping_review"
    if path == "/api/v1/ingestion/eval":
        return "connector_manage"
    if path == "/api/v1/scheduler/tick":
        return "connector_manage"
    if _connector_action(path, "configure") is not None:
        return "connector_manage"
    if _connector_action(path, "discover") is not None:
        return "connector_manage"
    if _connector_action(path, "probe") is not None:
        return "connector_manage"
    if _connector_action(path, "sync") is not None:
        return "connector_manage"
    if _connector_link_action(path, "start") is not None:
        return "connector_manage"
    if _connector_link_action(path, "complete") is not None:
        return "connector_manage"
    return _UNMAPPED_POST_SCOPE


# Typed write/read routes served only by the FastAPI server (``server_app``).
#
# ``SINGLETON_LOADERS`` / ``COLLECTION_LOADERS`` above cover the lake-backed
# read surface that both deployment modes share. The remediation workflow,
# tagging, saved views, and insights routes are stateful (database-backed) and
# live only in server mode, so they are not in the loader tables -- yet they are
# the verbs an agent needs to *act*. Enumerating them here keeps the
# self-describing ``GET /api/v1`` catalog honest about the full contract.
#
# Paths, methods, and scopes are kept in lockstep with the ``@app.<verb>``
# decorators and their ``Depends(_require_*)`` defaults in ``server_app``.
EXTENDED_RESOURCES: list[JsonObject] = [
    {
        "resource": "mapping-reviews.queue",
        "path": "/api/v1/mapping-reviews/queue",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": [
            "framework_id",
            "family",
            "safeguard_id",
            "status",
            "q",
            "limit",
            "offset",
            "cursor",
            "sort",
        ],
    },
    {
        "resource": "mapping-reviews.decisions",
        "path": "/api/v1/mapping-reviews/decisions",
        "kind": "collection",
        "methods": ["GET", "POST"],
        # POST also requires a signed-in console session in server mode: bearer
        # API keys (agents, CI, MCP) may list but never decide.
        "scopes": ["read", "mapping_review"],
        "query": ["safeguard_id", "control_id", "framework_id", "reviewer", "decision", "limit", "offset", "sort"],
    },
    {
        "resource": "mapping-reviews.summary",
        "path": "/api/v1/mapping-reviews/summary",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "workflows",
        "path": "/api/v1/workflows/{workflow_id}",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["workflow_id"],
    },
    {
        "resource": "workflows.runs",
        "path": "/api/v1/workflows/{workflow_id}/runs",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["workflow_id"],
    },
    {
        "resource": "workflows.run",
        "path": "/api/v1/workflows/{workflow_id}/run",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["workflow_run"],
        "path_params": ["workflow_id"],
    },
    {
        "resource": "workflows.actions",
        "path": "/api/v1/workflows/actions/run",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["workflow_run"],
    },
    {
        "resource": "workflows.run",
        "path": "/api/v1/workflows/runs/{run_id}",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["run_id"],
    },
    {
        "resource": "workflows.run",
        "path": "/api/v1/workflows/runs/{run_id}/retry",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["workflow_run"],
        "path_params": ["run_id"],
    },
    {
        "resource": "workflows.run",
        "path": "/api/v1/workflows/runs/{run_id}/approve",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["workflow_manage"],
        "path_params": ["run_id"],
    },
    {
        "resource": "workflows.run",
        "path": "/api/v1/workflows/runs/{run_id}/reject",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["workflow_manage"],
        "path_params": ["run_id"],
    },
    {
        "resource": "violations.tracking",
        "path": "/api/v1/violations/{violation_id}/tracking",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["violation_id"],
    },
    {
        "resource": "violations.triage",
        "path": "/api/v1/violations/{violation_id}/triage",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["write"],
        "path_params": ["violation_id"],
    },
    {
        "resource": "evidence.verify",
        "path": "/api/v1/evidence/{event_id}/verify",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["write"],
        "path_params": ["event_id"],
    },
    {
        "resource": "trust-shares",
        "path": "/api/v1/trust-shares",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "snapshot"],
        "query": ["include_revoked", "limit", "offset", "sort"],
    },
    {
        "resource": "trust-shares",
        "path": "/api/v1/trust-shares/{share_id}/revoke",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["snapshot"],
        "path_params": ["share_id"],
    },
    {
        "resource": "agent-runs",
        "path": "/api/v1/agent-runs",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "write"],
        "query": ["limit", "harness", "status"],
    },
    {
        "resource": "agent-runs",
        "path": "/api/v1/agent-runs/{run_id}",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["run_id"],
    },
    {
        "resource": "agent-runs.decisions",
        "path": "/api/v1/agent-runs/{run_id}/decisions/{decision_index}/approve",
        "kind": "action",
        "methods": ["POST"],
        "scopes": ["write"],
        "path_params": ["run_id", "decision_index"],
    },
    {
        "resource": "remediation.tasks",
        "path": "/api/v1/remediation/tasks",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "write"],
    },
    {
        "resource": "remediation.tasks",
        "path": "/api/v1/remediation/tasks/{task_id}",
        "kind": "singleton",
        "methods": ["GET", "PATCH"],
        "scopes": ["read", "write"],
        "path_params": ["task_id"],
    },
    {
        "resource": "remediation.evidence-requests",
        "path": "/api/v1/remediation/evidence-requests",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "evidence_request"],
    },
    {
        "resource": "remediation.evidence-requests",
        "path": "/api/v1/remediation/evidence-requests/{request_id}",
        "kind": "singleton",
        "methods": ["PATCH"],
        "scopes": ["evidence_request"],
        "path_params": ["request_id"],
    },
    {
        "resource": "remediation.exceptions",
        "path": "/api/v1/remediation/exceptions",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "control_manage"],
    },
    {
        "resource": "remediation.exceptions",
        "path": "/api/v1/remediation/exceptions/{exception_id}",
        "kind": "singleton",
        "methods": ["DELETE"],
        "scopes": ["control_manage"],
        "path_params": ["exception_id"],
    },
    {
        "resource": "gov-compliance.sprs",
        "path": "/api/v1/gov-compliance/sprs",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "gov-compliance.poam",
        "path": "/api/v1/gov-compliance/poam",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "write"],
    },
    {
        "resource": "gov-compliance.poam",
        "path": "/api/v1/gov-compliance/poam/{item_id}",
        "kind": "singleton",
        "methods": ["PATCH"],
        "scopes": ["write"],
        "path_params": ["item_id"],
    },
    {
        "resource": "gov-compliance.poam.sync",
        "path": "/api/v1/gov-compliance/poam/sync",
        "kind": "action",
        "methods": ["POST"],
        "scopes": ["write"],
    },
    {
        "resource": "risks",
        "path": "/api/v1/risks",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "write"],
    },
    {
        "resource": "risks",
        "path": "/api/v1/risks/{risk_id}",
        "kind": "singleton",
        "methods": ["PATCH", "DELETE"],
        "scopes": ["write"],
        "path_params": ["risk_id"],
    },
    {
        "resource": "access-reviews",
        "path": "/api/v1/access-reviews",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "control_manage"],
    },
    {
        "resource": "policy-templates",
        "path": "/api/v1/policy-templates",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "policy-templates",
        "path": "/api/v1/policy-templates/{template_id}",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["template_id"],
    },
    {
        "resource": "policies",
        "path": "/api/v1/policies",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "control_manage"],
    },
    {
        "resource": "policies.coverage",
        "path": "/api/v1/policies/coverage",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "policies.attestation-summary",
        "path": "/api/v1/policies/attestation-summary",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "policies",
        "path": "/api/v1/policies/{document_id}",
        "kind": "singleton",
        "methods": ["GET", "PATCH"],
        "scopes": ["read", "control_manage"],
        "path_params": ["document_id"],
    },
    {
        "resource": "policies",
        "path": "/api/v1/policies/{document_id}/publish",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["control_manage"],
        "path_params": ["document_id"],
    },
    {
        "resource": "policies.acknowledgments",
        "path": "/api/v1/policies/{document_id}/acknowledgments",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read"],
        "path_params": ["document_id"],
    },
    {
        "resource": "access-reviews.coverage",
        "path": "/api/v1/access-reviews/coverage",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "controls.remediation",
        "path": "/api/v1/controls/{control_id}/remediation",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["control_id"],
    },
    {
        "resource": "access-reviews",
        "path": "/api/v1/access-reviews/{campaign_id}",
        "kind": "singleton",
        "methods": ["GET", "PATCH"],
        "scopes": ["read", "control_manage"],
        "path_params": ["campaign_id"],
    },
    {
        "resource": "access-reviews.items",
        "path": "/api/v1/access-reviews/{campaign_id}/items",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "control_manage"],
        "path_params": ["campaign_id"],
    },
    {
        "resource": "access-reviews",
        "path": "/api/v1/access-reviews/{campaign_id}/seed",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["control_manage"],
        "path_params": ["campaign_id"],
    },
    {
        "resource": "access-reviews.items",
        "path": "/api/v1/access-reviews/items/{item_id}/decision",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["control_manage"],
        "path_params": ["item_id"],
    },
    {
        "resource": "vendor-questionnaires",
        "path": "/api/v1/vendor-questionnaires",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "vendor-questionnaires",
        "path": "/api/v1/vendor-questionnaires/{template_id}",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["template_id"],
    },
    {
        "resource": "vendor-assessments",
        "path": "/api/v1/vendor-assessments",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "control_manage"],
    },
    {
        "resource": "vendor-assessments",
        "path": "/api/v1/vendor-assessments/{assessment_id}",
        "kind": "singleton",
        "methods": ["GET", "PATCH"],
        "scopes": ["read", "control_manage"],
        "path_params": ["assessment_id"],
    },
    {
        "resource": "vendor-assessments",
        "path": "/api/v1/vendor-assessments/{assessment_id}/submit",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["control_manage"],
        "path_params": ["assessment_id"],
    },
    {
        "resource": "tags",
        "path": "/api/v1/tags",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "write"],
    },
    {
        "resource": "tags",
        "path": "/api/v1/tags/{tag_id}",
        "kind": "singleton",
        "methods": ["DELETE"],
        "scopes": ["write"],
        "path_params": ["tag_id"],
    },
    {
        "resource": "tags.attach",
        "path": "/api/v1/tags/attach",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["write"],
    },
    {
        "resource": "tags.detach",
        "path": "/api/v1/tags/detach",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["write"],
    },
    {
        "resource": "tags.for",
        "path": "/api/v1/tags/for",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": ["entity_type", "entity_id"],
    },
    {
        "resource": "tags.entities",
        "path": "/api/v1/tags/entities",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": ["tag_id", "entity_type"],
    },
    {
        "resource": "saved-views",
        "path": "/api/v1/saved-views",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "write"],
    },
    {
        "resource": "saved-views",
        "path": "/api/v1/saved-views/{view_id}",
        "kind": "singleton",
        "methods": ["DELETE"],
        "scopes": ["write"],
        "path_params": ["view_id"],
    },
    {
        "resource": "insights.timeseries",
        "path": "/api/v1/insights/timeseries",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": ["limit"],
    },
    {
        "resource": "insights.remediation",
        "path": "/api/v1/insights/remediation",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "insights.framework-trends",
        "path": "/api/v1/insights/framework-trends",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": ["limit"],
    },
    {
        "resource": "insights.sla-heatmap",
        "path": "/api/v1/insights/sla-heatmap",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "insights.capture",
        "path": "/api/v1/insights/capture",
        "kind": "singleton",
        "methods": ["POST"],
        "scopes": ["write"],
    },
    {
        "resource": "platform.poc-readiness",
        "path": "/api/v1/platform/poc-readiness",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["auth_admin"],
    },
    {
        "resource": "platform.audit-readiness",
        "path": "/api/v1/platform/audit-readiness",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "platform.jobs",
        "path": "/api/v1/platform/jobs",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "platform.ai-governance",
        "path": "/api/v1/platform/ai-governance",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "platform.ai-governance.inventory",
        "path": "/api/v1/platform/ai-governance/inventory",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": ["limit", "offset"],
    },
    {
        "resource": "evidence.freshness.summary",
        "path": "/api/v1/evidence/freshness/summary",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
    },
    {
        "resource": "evidence.freshness.escalate",
        "path": "/api/v1/evidence/freshness/escalate",
        "kind": "action",
        "methods": ["POST"],
        "scopes": ["write"],
    },
    {
        "resource": "evidence.freshness.request",
        "path": "/api/v1/evidence/freshness/request",
        "kind": "action",
        "methods": ["POST"],
        "scopes": ["evidence_request"],
    },
    {
        "resource": "snapshots.detail",
        "path": "/api/v1/snapshots/{snapshot_id}",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["snapshot_id"],
    },
    {
        "resource": "audit-log",
        "path": "/api/v1/audit-log",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "query_params": ["category", "actor", "limit", "include_requests"],
    },
    {
        "resource": "webhooks",
        "path": "/api/v1/webhooks",
        "kind": "collection",
        "methods": ["GET", "POST"],
        "scopes": ["read", "connector_manage"],
        "query_params": ["enabled", "event_type", "limit", "offset"],
    },
    {
        "resource": "webhooks",
        "path": "/api/v1/webhooks/{subscription_id}",
        "kind": "singleton",
        "methods": ["GET", "PATCH", "DELETE"],
        "scopes": ["read", "connector_manage"],
        "path_params": ["subscription_id"],
    },
    {
        "resource": "webhooks.deliveries",
        "path": "/api/v1/webhooks/{subscription_id}/deliveries",
        "kind": "collection",
        "methods": ["GET"],
        "scopes": ["read"],
        "path_params": ["subscription_id"],
    },
]


def resource_catalog() -> list[JsonObject]:
    """Self-describing list of v1 resources, for headless/agent discovery."""
    catalog: list[JsonObject] = []
    catalog.extend(
        [
            {
                "resource": "connectors",
                "path": "/api/v1/connectors",
                "kind": "collection",
                "methods": ["GET"],
                "scopes": ["read"],
            },
            {
                "resource": "connector.runs",
                "path": "/api/v1/connectors/{connector_id}/runs",
                "kind": "collection",
                "methods": ["GET"],
                "scopes": ["read"],
                "path_params": ["connector_id"],
            },
            {
                "resource": "connector.configure",
                "path": "/api/v1/connectors/{connector_id}/configure",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
                "path_params": ["connector_id"],
            },
            {
                "resource": "connector.discover",
                "path": "/api/v1/connectors/{connector_id}/discover",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
                "path_params": ["connector_id"],
            },
            {
                "resource": "connector.probe",
                "path": "/api/v1/connectors/{connector_id}/probe",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
                "path_params": ["connector_id"],
            },
            {
                "resource": "connector.sync",
                "path": "/api/v1/connectors/{connector_id}/sync",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
                "path_params": ["connector_id"],
            },
            {
                "resource": "ingestion.eval",
                "path": "/api/v1/ingestion/eval",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
            },
            {
                "resource": "scheduler.tick",
                "path": "/api/v1/scheduler/tick",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
            },
            {
                "resource": "connector.link.start",
                "path": "/api/v1/connectors/{connector_id}/link/start",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
                "path_params": ["connector_id"],
            },
            {
                "resource": "connector.link.complete",
                "path": "/api/v1/connectors/{connector_id}/link/complete",
                "kind": "action",
                "methods": ["POST"],
                "scopes": ["connector_manage"],
                "path_params": ["connector_id"],
            },
        ]
    )
    catalog.append(
        {
            "resource": "framework.detail",
            "path": "/api/v1/frameworks/{framework_id}/detail",
            "kind": "singleton",
            "methods": ["GET"],
            "path_params": ["framework_id"],
        }
    )
    catalog.append(
        {
            "resource": "posture.as_of",
            "path": "/api/v1/posture/as-of",
            "kind": "singleton",
            "methods": ["GET"],
            "query": ["as_of"],
        }
    )
    catalog.append(
        {
            "resource": "snapshots.integrity",
            "path": "/api/v1/snapshots/integrity",
            "kind": "singleton",
            "methods": ["GET"],
        }
    )
    catalog.append(
        {
            "resource": "snapshots.export",
            "path": "/api/v1/snapshots/{snapshot_id}/export.pdf",
            "kind": "action",
            "methods": ["GET"],
            "scopes": ["read"],
            "path_params": ["snapshot_id"],
        }
    )
    catalog.append(
        {
            "resource": "tracking.integrity",
            "path": "/api/v1/tracking/integrity",
            "kind": "singleton",
            "methods": ["GET"],
        }
    )
    catalog.append(
        {
            "resource": "catalog.bundle",
            "path": "/api/v1/catalog/bundle",
            "kind": "singleton",
            "methods": ["GET"],
            "query": ["as_of", "full"],
        }
    )
    catalog.append(
        {
            "resource": "controls.as_of",
            "path": "/api/v1/controls/as-of",
            "kind": "singleton",
            "methods": ["GET"],
            "query": ["as_of"],
        }
    )
    catalog.append(
        {
            "resource": "control.history",
            "path": "/api/v1/controls/{control_id}/history",
            "kind": "singleton",
            "methods": ["GET"],
            "path_params": ["control_id"],
        }
    )
    catalog.append(
        {
            "resource": "oscal.assessment-results",
            "path": "/api/v1/oscal/assessment-results",
            "kind": "singleton",
            "methods": ["GET"],
            "query": ["snapshot_id"],
        }
    )
    for path, (name, _loader) in SINGLETON_LOADERS.items():
        catalog.append({"resource": name, "path": path, "kind": "singleton", "methods": ["GET"]})
    for path, (name, _loader) in COLLECTION_LOADERS.items():
        catalog.append(
            {
                "resource": name,
                "path": path,
                "kind": "collection",
                "methods": ["GET", *_WRITABLE.get(path, [])],
                "query": ["limit", "offset", "sort", "<field>=<value>"],
            }
        )
    catalog.extend(dict(entry) for entry in EXTENDED_RESOURCES)

    # A path can be described twice -- once generated from a loader table and
    # once hand-written in EXTENDED_RESOURCES to carry its scopes. Merge rather
    # than emit both, with the hand-written entry winning on conflict, so the
    # catalog stays a set of paths.
    merged: dict[str, JsonObject] = {}
    for row in catalog:
        path = str(row["path"])
        merged[path] = {**merged.get(path, {}), **row}
    return sorted(merged.values(), key=lambda row: row["path"])


# Response envelope shared by every v1 route, referenced by the generated spec.
_ENVELOPE_SCHEMA: JsonObject = {
    "type": "object",
    "required": ["data", "meta", "errors"],
    "properties": {
        "data": {"nullable": True, "description": "Resource payload; a list for collections."},
        "meta": {
            "type": "object",
            "properties": {
                "api_version": {"type": "string"},
                "resource": {"type": "string"},
                "count": {"type": "integer"},
                "returned": {"type": "integer"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
        },
        "errors": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"code": {"type": "string"}, "detail": {"type": "string"}},
            },
        },
    },
}


def openapi_paths() -> JsonObject:
    """OpenAPI path items for routes served through the ``/api/v1/{rest}`` catch-all.

    FastAPI can only describe decorated routes, so the core read surface --
    violations, controls, evidence, posture, snapshots, workflows and the rest --
    collapses into a single ``/api/v1/{rest}`` entry in the generated schema. A
    client generated from that spec cannot fetch posture at all. These are built
    from :func:`resource_catalog`, which is the same source the runtime dispatches
    from, so the two cannot drift apart.
    """
    paths: JsonObject = {}
    for row in resource_catalog():
        path = str(row["path"])
        resource = str(row["resource"])
        collection = row.get("kind") == "collection"

        parameters: list[JsonObject] = [
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            }
            for name in row.get("path_params", [])
        ]
        for name in row.get("query", []):
            if name.startswith("<"):  # `<field>=<value>` documents ad-hoc filters
                continue
            schema = {"type": "integer"} if name in {"limit", "offset"} else {"type": "string"}
            parameters.append({"name": name, "in": "query", "required": False, "schema": schema})

        item: JsonObject = {}
        for method in row.get("methods", ["GET"]):
            operation: JsonObject = {
                "summary": f"{'List' if collection and method == 'GET' else method.title()} {resource}",
                "operationId": f"{method.lower()}_{resource.replace('.', '_').replace('-', '_')}",
                "tags": [resource.split(".")[0]],
                "responses": {
                    "200": {
                        "description": "v1 envelope",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/V1Envelope"}}},
                    }
                },
            }
            if parameters and method == "GET":
                operation["parameters"] = parameters
            if scopes := row.get("scopes"):
                operation["description"] = f"Requires scope: {', '.join(scopes)}."
            item[method.lower()] = operation
        paths[path] = item
    return paths


def merge_openapi(spec: JsonObject) -> JsonObject:
    """Fold the catch-all-served routes into a FastAPI-generated schema."""
    paths = dict(spec.get("paths") or {})
    # The catch-all itself documents nothing and implies a route that takes an
    # arbitrary path segment, which is worse than absent.
    paths.pop("/api/v1/{rest}", None)
    paths.pop("/api/{rest}", None)
    for path, item in openapi_paths().items():
        paths.setdefault(path, item)
    spec["paths"] = paths

    components = dict(spec.get("components") or {})
    schemas = dict(components.get("schemas") or {})
    schemas.setdefault("V1Envelope", _ENVELOPE_SCHEMA)
    components["schemas"] = schemas
    spec["components"] = components
    return spec


def index_payload() -> JsonObject:
    """Return the self-describing v1 contract index."""
    return {
        "api_version": API_VERSION,
        "resources": resource_catalog(),
        "collection_controls": {
            "limit": "1-1000 (default 100)",
            "offset": ">= 0",
            "sort": "field, or -field for descending",
            "filters": "any field=value (comma-separated values = OR)",
        },
        "auth": {
            "api_key": "Authorization: Bearer <token>",
            "session": "httpOnly cookie via OIDC/SAML SSO",
            "methods_endpoint": "/api/v1/auth/methods",
        },
        "streams": ["/api/v1/stream"],
        "openapi": "/openapi.json",
        "docs": "/docs",
    }


def filter_collection(rows: list[JsonObject], params: Params) -> tuple[list[JsonObject], dict[str, list[str]]]:
    """Apply ``field=value`` query filters (comma-separated, list-field aware)."""
    reserved = {"limit", "offset", "sort", "cursor"}
    filters = {
        key: [value for raw in values for value in raw.split(",") if value]
        for key, values in params.items()
        if key not in reserved
    }
    if not filters:
        return rows, {}

    def matches(row: JsonObject) -> bool:
        for field, expected_values in filters.items():
            actual = row.get(field)
            if actual is None:
                return False
            if isinstance(actual, list):
                actual_values = {str(item) for item in actual}
                if not any(expected in actual_values for expected in expected_values):
                    return False
            elif str(actual) not in expected_values:
                return False
        return True

    return [row for row in rows if matches(row)], filters


def sort_collection(rows: list[JsonObject], params: Params) -> tuple[list[JsonObject], str | None]:
    """Apply ``sort=field`` / ``sort=-field`` ordering; ``None`` values sort last."""
    sort = (params.get("sort") or [None])[0]
    if not sort:
        return rows, None
    reverse = sort.startswith("-")
    field = sort[1:] if reverse else sort
    if not field:
        raise ValueError("sort must name a field, optionally prefixed with '-'")
    sortable = [row for row in rows if row.get(field) is not None]
    missing = [row for row in rows if row.get(field) is None]

    def sort_key(row: JsonObject) -> tuple[int, float | str]:
        value = row[field]
        if isinstance(value, int | float):
            return (0, float(value))
        return (1, str(value))

    return sorted(sortable, key=sort_key, reverse=reverse) + missing, sort


def encode_cursor(offset: int) -> str:
    """Encode a next-page start ``offset`` into an opaque base64 cursor.

    The cursor today is an *offset cursor*: it carries the absolute start
    offset of the next page as base64-encoded JSON (``{"offset": N}``). This
    keeps the public contract opaque so callers treat it as a token to follow
    rather than a number to compute, while a future revision can switch the
    payload to a keyset/streaming position over the SQL mart without changing
    the wire shape. The applied limit/sort/filters are not embedded — the page
    boundary is the offset; callers should keep limit/sort/filters stable
    across pages (the existing ``meta`` echoes them back for that purpose).
    """
    raw = json.dumps({"offset": offset}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: str) -> int:
    """Decode an opaque cursor produced by :func:`encode_cursor` to an offset.

    Raises ``ValueError`` (the same path as a bad ``limit``/``offset``) when the
    cursor is not valid base64, not JSON, or does not carry a non-negative
    integer ``offset``.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        payload = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeError) as exc:
        raise ValueError("invalid cursor") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid cursor")
    offset = payload.get("offset")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("invalid cursor")
    return offset


def paginate_collection(rows: list[JsonObject], params: Params) -> tuple[list[JsonObject], int, int]:
    """Apply ``limit`` (1-1000, default 100) and a start offset.

    The start offset comes from an opaque ``cursor`` when present (see
    :func:`encode_cursor`); ``cursor`` takes precedence over a raw ``offset``
    when both are supplied. Otherwise it falls back to ``offset`` (>=0,
    default 0). An invalid cursor raises ``ValueError`` like a bad limit/offset.
    """
    try:
        limit = int((params.get("limit") or ["100"])[0])
    except ValueError as exc:
        raise ValueError("limit and offset must be integers") from exc
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    cursor_values = params.get("cursor") or []
    if cursor_values and cursor_values[0]:
        offset = decode_cursor(cursor_values[0])
    else:
        try:
            offset = int((params.get("offset") or ["0"])[0])
        except ValueError as exc:
            raise ValueError("limit and offset must be integers") from exc
        if offset < 0:
            raise ValueError("offset must be greater than or equal to 0")
    return rows[offset : offset + limit], limit, offset


def collection_response(resource: str, rows: list[JsonObject], params: Params) -> JsonObject:
    """Filter, sort, and paginate ``rows`` into a v1 collection envelope.

    The ``meta`` always includes ``next_cursor``: an opaque cursor for the next
    page when more filtered rows remain (``offset + limit < count``), else
    ``None``. The offset/limit/count/returned/sort/filters fields are unchanged,
    so offset-based pagination keeps working exactly as before.
    """
    filtered_rows, applied_filters = filter_collection(rows, params)
    sorted_rows, sort = sort_collection(filtered_rows, params)
    page_rows, limit, offset = paginate_collection(sorted_rows, params)
    count = len(filtered_rows)
    next_offset = offset + limit
    next_cursor = encode_cursor(next_offset) if next_offset < count else None
    return envelope(
        resource,
        page_rows,
        meta={
            "count": count,
            "returned": len(page_rows),
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "filters": applied_filters,
            "next_cursor": next_cursor,
        },
    )


@generation_reader
def handle_get(path: str, params: Params, lake_dir: str | Path) -> tuple[HTTPStatus, JsonObject]:
    """Resolve a v1 GET against one pinned assessment generation."""
    status, body = _handle_get(path, params, lake_dir)
    generation = generation_identity(lake_dir)
    if generation is not None:
        body["meta"]["generation"] = generation
    return status, body


def _handle_get(path: str, params: Params, lake_dir: str | Path) -> tuple[HTTPStatus, JsonObject]:
    lake = resolve_path(lake_dir)
    if path == "/api/v1":
        return HTTPStatus.OK, envelope("index", index_payload())
    if path == "/api/v1/connectors":
        rows = build_catalog_view(lake)
        return HTTPStatus.OK, collection_response("connectors", rows, params)
    connector_runs = _suffix_match(path, "/api/v1/connectors/", "/runs")
    if connector_runs is not None:
        rows = list_runs(lake, connector_runs)
        try:
            body = collection_response("connector.runs", rows, params)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request parameters", resource="connector.runs"
            )
        body["meta"]["connector_id"] = connector_runs
        return HTTPStatus.OK, body
    if path.startswith("/api/v1/frameworks/") and path.endswith("/detail"):
        framework_id = path[len("/api/v1/frameworks/") : -len("/detail")]
        detail = build_framework_detail(framework_id, lake)
        if detail is None:
            return HTTPStatus.NOT_FOUND, error_envelope("not_found", "unknown framework", resource="framework.detail")
        return HTTPStatus.OK, envelope("framework.detail", detail)
    if path == "/api/v1/snapshots/integrity":
        return HTTPStatus.OK, envelope("snapshots.integrity", verify_snapshot_chain(lake))
    if path == "/api/v1/tracking/integrity":
        return HTTPStatus.OK, envelope("tracking.integrity", verify_tracking_chain(lake))
    if path == "/api/v1/catalog/bundle":
        from security_lakehouse.catalog_versions import bundle_summary, compute_bundle

        as_of_values = params.get("as_of") or []
        as_of = as_of_values[0] if as_of_values else None
        full = (params.get("full") or [""])[0] in ("1", "true", "yes")
        try:
            data = compute_bundle(as_of=as_of) if full else bundle_summary(as_of=as_of)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", f"invalid 'as_of' value: {as_of!r}", resource="catalog.bundle"
            )
        return HTTPStatus.OK, envelope("catalog.bundle", data)
    if path == "/api/v1/controls/as-of":
        from security_lakehouse.catalog_versions import controls_as_of

        as_of_values = params.get("as_of") or []
        as_of = as_of_values[0] if as_of_values else ""
        if not as_of:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "query parameter 'as_of' is required", resource="controls.as_of"
            )
        try:
            controls = controls_as_of(as_of)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", f"invalid 'as_of' value: {as_of!r}", resource="controls.as_of"
            )
        return HTTPStatus.OK, envelope(
            "controls.as_of", {"as_of": as_of, "control_count": len(controls), "controls": list(controls.values())}
        )
    if path.startswith("/api/v1/controls/") and path.endswith("/history"):
        from security_lakehouse.catalog_versions import control_history

        control_id = path[len("/api/v1/controls/") : -len("/history")]
        versions = control_history(control_id)
        if not versions:
            return HTTPStatus.NOT_FOUND, error_envelope(
                "not_found", f"unknown control {control_id}", resource="control.history"
            )
        return HTTPStatus.OK, envelope("control.history", {"control_id": control_id, "versions": versions})
    tracking = _suffix_match(path, "/api/v1/violations/", "/tracking")
    if tracking is not None:
        current = latest_state(lake, violation_id=tracking)
        return HTTPStatus.OK, envelope(
            "violations.tracking",
            {
                "violation_id": tracking,
                "current_state": (current or {}).get("state", "open"),
                "events": list_events(lake, violation_id=tracking),
            },
        )
    workflow_run_id = _workflow_run_id_match(path)
    if workflow_run_id is not None:
        run = get_workflow_run(lake, workflow_run_id)
        if run is None:
            return HTTPStatus.NOT_FOUND, error_envelope(
                "not_found", f"unknown run {workflow_run_id}", resource="workflows.run"
            )
        return HTTPStatus.OK, envelope("workflows.run", run)
    workflow_runs_for = _suffix_match(path, "/api/v1/workflows/", "/runs")
    if workflow_runs_for is not None and workflow_runs_for != "actions":
        runs = list_workflow_runs(lake, workflow_runs_for)
        return HTTPStatus.OK, envelope(
            "workflows.runs", runs, meta={"workflow_id": workflow_runs_for, "count": len(runs)}
        )
    workflow_id = _workflow_id_match(path)
    if workflow_id is not None:
        workflow = get_workflow(lake, workflow_id)
        if workflow is None:
            return HTTPStatus.NOT_FOUND, error_envelope(
                "not_found", f"unknown workflow {workflow_id}", resource="workflows"
            )
        return HTTPStatus.OK, envelope("workflows", workflow)
    if path == "/api/v1/trust-shares":
        include_revoked = (params.get("include_revoked") or ["false"])[0].lower() in {"1", "true", "yes"}
        shares = list_shares(lake, include_revoked=include_revoked)
        try:
            return HTTPStatus.OK, collection_response("trust-shares", shares, params)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request parameters", resource="trust-shares"
            )
    if path == "/api/v1/posture/as-of":
        as_of_values = params.get("as_of") or []
        as_of = as_of_values[0] if as_of_values else ""
        if not as_of:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "query parameter 'as_of' is required", resource="posture.as_of"
            )
        try:
            data = posture_as_of(lake, as_of=as_of)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", f"invalid 'as_of' value: {as_of!r}", resource="posture.as_of"
            )
        return HTTPStatus.OK, envelope("posture.as_of", data)
    if path.startswith("/api/v1/mapping-reviews/"):
        return _mapping_review_get(path, params, lake)
    if path == "/api/v1/oscal/assessment-results":
        snapshot_values = params.get("snapshot_id") or []
        snapshot_id = snapshot_values[0] if snapshot_values else None
        try:
            data = build_assessment_results(lake, snapshot_id=snapshot_id)
        except FileNotFoundError:
            return HTTPStatus.NOT_FOUND, error_envelope(
                "not_found", f"unknown snapshot {snapshot_id!r}", resource="oscal.assessment-results"
            )
        return HTTPStatus.OK, envelope("oscal.assessment-results", data)
    singleton = SINGLETON_LOADERS.get(path)
    if singleton is not None:
        resource, loader = singleton
        return HTTPStatus.OK, envelope(resource, loader(lake))
    collection = COLLECTION_LOADERS.get(path)
    if collection is not None:
        resource, loader = collection
        try:
            return HTTPStatus.OK, collection_response(resource, loader(lake), params)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request parameters", resource=resource
            )
    return HTTPStatus.NOT_FOUND, error_envelope("not_found", "unknown route")


MAPPING_REVIEW_DECISIONS_PATH = "/api/v1/mapping-reviews/decisions"
_QUEUE_STATUS_ALIASES = {"pending": PENDING_STATES}


def _mapping_review_queue_rows(lake: Path, params: Params) -> tuple[list[JsonObject], dict[str, list[str]]]:
    """Apply the queue's own filters (status, family, q) before the generic ones.

    The queue defaults to pending mappings (proposed or needs changes);
    ``status=all`` lists every mapping. ``family`` is an alias for
    ``risk_domain`` and ``q`` searches ids and titles.
    """
    rest = {key: list(values) for key, values in params.items()}
    raw_status = rest.pop("status", None) or rest.pop("review_state", None) or ["pending"]
    wanted: set[str] = set()
    for value in (part.strip() for raw in raw_status for part in raw.split(",")):
        if not value:
            continue
        if value == "all":
            wanted = set(REVIEW_STATE_LABELS)
            break
        if value in _QUEUE_STATUS_ALIASES:
            wanted |= _QUEUE_STATUS_ALIASES[value]
        elif value in REVIEW_STATE_LABELS:
            wanted.add(value)
        else:
            raise ValueError(f"unknown status {value!r}")
    if "family" in rest:
        rest["risk_domain"] = rest.pop("family")
    query = " ".join(rest.pop("q", [])).strip().lower()
    rows = [row for row in list_review_items(lake) if row["review_state"] in wanted]
    if query:
        fields = ("safeguard_id", "safeguard_title", "control_id", "control_title", "framework_id")
        rows = [row for row in rows if query in " ".join(str(row.get(field) or "") for field in fields).lower()]
    return rows, rest


def _mapping_review_get(path: str, params: Params, lake: Path) -> tuple[HTTPStatus, JsonObject]:
    if path == "/api/v1/mapping-reviews/queue":
        try:
            rows, rest = _mapping_review_queue_rows(lake, params)
            return HTTPStatus.OK, collection_response("mapping-reviews.queue", rows, rest)
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", str(exc), resource="mapping-reviews.queue")
    if path == MAPPING_REVIEW_DECISIONS_PATH:
        try:
            return HTTPStatus.OK, collection_response("mapping-reviews.decisions", list_decisions(lake), params)
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", str(exc), resource="mapping-reviews.decisions")
    if path == "/api/v1/mapping-reviews/summary":
        log = verify_review_log(lake)
        return HTTPStatus.OK, envelope("mapping-reviews.summary", {**review_progress(lake), "decision_log": log})
    return HTTPStatus.NOT_FOUND, error_envelope("not_found", "unknown route")


def record_mapping_review(
    payload: JsonObject,
    lake: Path,
    *,
    reviewer: str,
    auth_method: str,
    reviewer_id: str | None = None,
    reviewer_role: str | None = None,
) -> tuple[HTTPStatus, JsonObject]:
    """Record one org review decision over one or more mappings.

    The caller supplies the reviewer: server mode passes the authenticated
    user, never a value from the request body.
    """
    resource = "mapping-reviews.decisions"
    items = payload.get("items")
    if not isinstance(items, list):
        return HTTPStatus.BAD_REQUEST, error_envelope(
            "bad_request", "items must be a list of mappings", resource=resource
        )
    try:
        records = record_decisions(
            lake,
            items=items,
            decision=str(payload.get("decision") or ""),
            rationale=str(payload.get("rationale") or ""),
            reviewer=reviewer,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            auth_method=auth_method,
            evidence_ref=payload.get("evidence_ref") if isinstance(payload.get("evidence_ref"), str) else None,
        )
    except MappingReviewError as exc:
        return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", str(exc), resource=resource)
    return HTTPStatus.CREATED, envelope(
        resource,
        records,
        meta={"recorded": len(records), "batch_id": records[0]["batch_id"] if records else None},
    )


# `fixture_dir` points the connector runner at a directory of canned evidence
# instead of a live API. That is a local development affordance: over HTTP it is
# a file-read primitive, because the runner reads fixed filenames (users.json,
# logs.json, ...) from wherever it points and ingests them into the evidence
# lake, where they become readable at `read` scope. Verified: a file planted
# outside the lake reached bronze/raw_events.jsonl through the configure+sync
# API. The CLI and local seeding paths still accept it. The key set is
# single-sourced from connector_state so the boundary reject and the
# forward-merge strip cannot drift apart.
def _reject_local_only_options(options: JsonObject | None, *, resource: str) -> JsonObject | None:
    for name in _LOCAL_ONLY_OPTIONS:
        if options and name in options:
            return error_envelope(
                "bad_request",
                f"{name} cannot be set over the API; it is a local-only option",
                resource=resource,
            )
    return None


def handle_post(
    path: str,
    body: JsonObject | None,
    lake_dir: str | Path,
    *,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> tuple[HTTPStatus, JsonObject]:
    """Resolve a v1 POST into an ``(status, body)`` pair.

    ``on_snapshot_written`` reaches every route that can write an assessment
    snapshot: ``/api/v1/snapshots`` directly, and ``/api/v1/workflows/{id}/run``,
    ``/api/v1/workflows/actions/run``, and ``/api/v1/scheduler/tick``
    indirectly whenever they execute an ``action.snapshot`` workflow node (see
    :func:`security_lakehouse.workflows.run_action`). It is ``None`` for local
    mode (:mod:`security_lakehouse.server`), which has no DB/tenant context to
    dispatch webhooks with, and supplied by server mode
    (:mod:`security_lakehouse.server_app`) so all of these routes dispatch
    ``assessment.completed``/``finding.created``/``control.failed`` events —
    including a cron-scheduled snapshot fired via ``scheduler tick``, not only
    an interactively-triggered one.
    """
    lake = resolve_path(lake_dir)
    payload = body or {}
    if path == MAPPING_REVIEW_DECISIONS_PATH:
        # Local mode has no authenticated principal, so the reviewer is named in
        # the body and the record says it was unauthenticated. Server mode serves
        # the path from its own route with the signed-in user as reviewer; this
        # guard keeps that true even if route registration order ever changes.
        if in_server_mode():
            return HTTPStatus.FORBIDDEN, error_envelope(
                "forbidden",
                "mapping review decisions require a signed-in console session",
                resource="mapping-reviews.decisions",
            )
        return record_mapping_review(
            payload,
            lake,
            reviewer=str(payload.get("reviewer") or ""),
            auth_method="local-unauthenticated",
        )
    if path == "/api/v1/snapshots":
        reason = str(payload.get("reason") or "api_request")
        snapshot_path = write_assessment_snapshot(lake, reason=reason, on_snapshot_written=on_snapshot_written)
        return HTTPStatus.CREATED, envelope("snapshots", {"snapshot_path": str(snapshot_path), "reason": reason})
    triage = _suffix_match(path, "/api/v1/violations/", "/triage")
    if triage is not None:
        state = str(payload.get("state") or "").lower()
        if state not in ALLOWED_STATES:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", f"state must be one of {sorted(ALLOWED_STATES)}", resource="violations.triage"
            )
        record = append_event(
            lake,
            violation_id=triage,
            actor=str(payload.get("actor") or "anonymous"),
            state=state,
            assignee=payload.get("assignee"),
            due_at=payload.get("due_at"),
            note=payload.get("note"),
            idempotency_key=payload.get("idempotency_key"),
        )
        return HTTPStatus.CREATED, envelope("violations.triage", record)
    verify = _suffix_match(path, "/api/v1/evidence/", "/verify")
    if verify is not None:
        return HTTPStatus.CREATED, envelope("evidence.verify", verify_event(lake, verify))
    if path == "/api/v1/workflows":
        try:
            record = save_workflow(
                lake,
                workflow_id=payload.get("workflow_id"),
                name=str(payload.get("name") or ""),
                description=str(payload.get("description") or ""),
                nodes=payload.get("nodes") or [],
                edges=payload.get("edges") or [],
                actor=str(payload.get("actor") or "console"),
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid request", resource="workflows")
        return HTTPStatus.CREATED, envelope("workflows", record)
    if path == "/api/v1/workflows/actions/run":
        try:
            output = run_action(
                lake,
                node_type=str(payload.get("node_type") or ""),
                params=payload.get("params") or {},
                on_snapshot_written=on_snapshot_written,
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request", resource="workflows.actions"
            )
        return HTTPStatus.CREATED, envelope("workflows.actions", output)
    workflow_to_run = _suffix_match(path, "/api/v1/workflows/", "/run")
    if workflow_to_run is not None and workflow_to_run != "actions":
        try:
            run = run_workflow(
                lake,
                workflow_id=workflow_to_run,
                actor=str(payload.get("actor") or "console"),
                dry_run=bool(payload.get("dry_run")),
                on_snapshot_written=on_snapshot_written,
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid request", resource="workflows.run")
        return HTTPStatus.CREATED, envelope("workflows.run", run)
    workflow_retry = _suffix_match(path, "/api/v1/workflows/runs/", "/retry")
    if workflow_retry is not None:
        try:
            run = retry_workflow_run(lake, run_id=workflow_retry, actor=str(payload.get("actor") or "console"))
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid request", resource="workflows.run")
        return HTTPStatus.CREATED, envelope("workflows.run", run)
    workflow_approve = _suffix_match(path, "/api/v1/workflows/runs/", "/approve")
    if workflow_approve is not None:
        try:
            run = approve_workflow_run(
                lake,
                run_id=workflow_approve,
                actor=str(payload.get("actor") or "console"),
                note=str(payload.get("note") or ""),
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid request", resource="workflows.run")
        return HTTPStatus.CREATED, envelope("workflows.run", run)
    workflow_reject = _suffix_match(path, "/api/v1/workflows/runs/", "/reject")
    if workflow_reject is not None:
        try:
            run = reject_workflow_run(
                lake,
                run_id=workflow_reject,
                actor=str(payload.get("actor") or "console"),
                note=str(payload.get("note") or ""),
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid request", resource="workflows.run")
        return HTTPStatus.CREATED, envelope("workflows.run", run)
    if path == "/api/v1/trust-shares":
        try:
            share = create_share(
                lake,
                role=str(payload.get("role") or "auditor"),
                scope=str(payload.get("scope") or "posture_full"),
                expires_in_hours=int(payload.get("expires_in_hours") or 24),
                created_by=str(payload.get("created_by") or "console"),
                framework_id=payload.get("framework_id"),
                sensitivity_ceiling=str(payload.get("sensitivity_ceiling") or "public"),
                idempotency_key=payload.get("idempotency_key"),
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid request", resource="trust-shares")
        return HTTPStatus.CREATED, envelope("trust-shares", share)
    revoke = _suffix_match(path, "/api/v1/trust-shares/", "/revoke")
    if revoke is not None:
        revoked = revoke_share(lake, revoke)
        if revoked is None:
            return HTTPStatus.NOT_FOUND, error_envelope("not_found", f"unknown share {revoke}", resource="trust-shares")
        return HTTPStatus.CREATED, envelope("trust-shares", revoked)
    configure = _connector_action(path, "configure")
    if configure is not None:
        rejection = _reject_local_only_options(payload.get("options"), resource="connector.configure")
        if rejection is not None:
            return HTTPStatus.BAD_REQUEST, rejection
        state = str(payload.get("state") or "enabled").lower()
        credentials, options = resolve_configure_payload(
            lake,
            connector_id=configure,
            credentials=payload.get("credentials") if "credentials" in payload else None,
            options=payload.get("options") if "options" in payload else None,
        )
        error = configure_payload_error(
            connector_id=configure,
            state=state,
            credentials=credentials,
            options=options,
        )
        if error:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", error, resource="connector.configure")
        error = enablement_probe_error(
            lake,
            connector_id=configure,
            state=state,
            credentials=credentials,
            options=options,
        )
        if error:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", error, resource="connector.configure")
        record = append_config_event(
            lake,
            connector_id=configure,
            state=state,
            actor=str(payload.get("actor") or "console"),
            credentials=credentials,
            options=options,
        )
        return HTTPStatus.CREATED, envelope("connector.configure", record)
    discover = _connector_action(path, "discover")
    if discover is not None:
        rejection = _reject_local_only_options(payload.get("options"), resource="connector.discover")
        if rejection is not None:
            return HTTPStatus.BAD_REQUEST, rejection
        record = run_discovery(
            lake,
            connector_id=discover,
            actor=str(payload.get("actor") or "console"),
            credentials=payload.get("credentials") if "credentials" in payload else None,
            options=payload.get("options") if "options" in payload else None,
        )
        return HTTPStatus.CREATED, envelope("connector.discover", record)
    probe = _connector_action(path, "probe")
    if probe is not None:
        rejection = _reject_local_only_options(payload.get("options"), resource="connector.probe")
        if rejection is not None:
            return HTTPStatus.BAD_REQUEST, rejection
        record = run_probe(
            lake,
            connector_id=probe,
            actor=str(payload.get("actor") or "console"),
            credentials=payload.get("credentials") if "credentials" in payload else None,
            options=payload.get("options") if "options" in payload else None,
        )
        return HTTPStatus.CREATED, envelope("connector.probe", record)
    sync = _connector_action(path, "sync")
    if sync is not None:
        if "materialize" in payload:
            materialize = bool(payload.get("materialize"))
        else:
            config = latest_config(lake, sync)
            materialize = connector_materialize_on_sync((config or {}).get("options") or {})
        try:
            result = run_connector_sync(
                lake,
                connector_id=sync,
                actor=str(payload.get("actor") or "console"),
                materialize=materialize,
            )
        except ConnectorSyncError:
            # The run is persisted with its outcome; surface a generic failure
            # here so no exception detail crosses the HTTP boundary. The reason
            # is available via GET /api/v1/connectors/{id}/runs.
            return HTTPStatus.BAD_GATEWAY, error_envelope(
                "sync_failed", "connector sync failed; see the connector runs for details", resource="connector.sync"
            )
        return HTTPStatus.CREATED, envelope(
            "connector.sync",
            {
                "connector_id": result.connector_id,
                "result": result.result,
                "evidence_count": result.evidence_count,
                "materialized": result.materialized,
                "run": result.run,
            },
        )
    if path == "/api/v1/ingestion/eval":
        eval_result = run_lake_eval(lake, actor=str(payload.get("actor") or "console"))
        return (
            HTTPStatus.CREATED if eval_result.result == "ok" else HTTPStatus.INTERNAL_SERVER_ERROR,
            envelope(
                "ingestion.eval",
                {
                    "result": eval_result.result,
                    "mode": eval_result.mode,
                    "duration_ms": eval_result.duration_ms,
                    "error": eval_result.error,
                    "strategy": eval_result.strategy,
                    "pipeline": eval_result.pipeline.__dict__ if eval_result.pipeline else None,
                },
            ),
        )
    if path == "/api/v1/scheduler/tick":
        from security_lakehouse.scheduler import tick

        fired = tick(lake, on_snapshot_written=on_snapshot_written)
        return HTTPStatus.CREATED, envelope("scheduler.tick", {"fired": fired, "count": len(fired)})
    link_start = _connector_link_action(path, "start")
    if link_start is not None:
        from security_lakehouse.cloud_linking import start_cloud_link

        public_url = str(payload.get("public_url") or "").strip() or None
        tenant_id = str(payload.get("tenant_id") or "default")
        try:
            session = start_cloud_link(
                lake,
                link_start,
                tenant_id=tenant_id,
                public_url=public_url,
            )
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", str(exc), resource="connector.link.start")
        return HTTPStatus.CREATED, envelope("connector.link.start", session)
    link_complete = _connector_link_action(path, "complete")
    if link_complete is not None:
        from security_lakehouse.cloud_linking import complete_cloud_link, normalize_link_session_id

        session_id = normalize_link_session_id(str(payload.get("session_id") or ""))
        if not session_id:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "session_id is required", resource="connector.link.complete"
            )
        try:
            result = complete_cloud_link(
                lake,
                link_complete,
                session_id=session_id,
                actor=str(payload.get("actor") or "console"),
                role_arn=str(payload.get("role_arn") or "").strip() or None,
                subscription_id=str(payload.get("subscription_id") or "").strip() or None,
                project_id=str(payload.get("project_id") or "").strip() or None,
            )
        except KeyError:
            return HTTPStatus.NOT_FOUND, error_envelope(
                "not_found", "cloud link session not found", resource="connector.link.complete"
            )
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", str(exc), resource="connector.link.complete")
        return HTTPStatus.CREATED, envelope("connector.link.complete", result)
    return HTTPStatus.NOT_FOUND, error_envelope("not_found", "unknown route")
