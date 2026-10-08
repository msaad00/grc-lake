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
import copy
import json
from collections.abc import Callable, Mapping
from http import HTTPStatus
from pathlib import Path
from typing import Any

from security_lakehouse import strict_json
from security_lakehouse.ai_governance import build_ai_governance_status, list_ai_inventory
from security_lakehouse.assessment import (
    SnapshotIntegrityError,
    SnapshotWrittenHook,
    build_current_posture,
    load_snapshot,
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
    connector_state_reader,
    enablement_probe_error,
    latest_config,
    list_runs,
    resolve_configure_payload,
    run_discovery,
    run_probe,
)
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.framework_detail import build_framework_detail, page_framework_detail
from security_lakehouse.framework_provenance import build_framework_view
from security_lakehouse.generations import generation_identity, generation_reader, pinned_path
from security_lakehouse.graph import (
    analyze_coverage,
    build_compliance_graph,
    build_framework_crosswalk,
    build_repository_graph,
)
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.io import (
    iter_jsonl,
    iter_jsonl_slice,
    read_json,
    read_jsonl,
    resolve_path,
    validated_jsonl_count,
)
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
from security_lakehouse.projected_reads import read_projection
from security_lakehouse.readiness import build_readiness_view
from security_lakehouse.safeguards import (
    PENDING_STATES,
    REVIEW_STATE_LABELS,
    coverage_by_category,
    coverage_by_family,
    coverage_by_framework,
    mapping_review_report,
)
from security_lakehouse.tracking import ALLOWED_STATES, append_event, latest_state, list_events, verify_tracking_chain
from security_lakehouse.trust_share import create_share, list_shares, revoke_share
from security_lakehouse.verification import verify_event
from security_lakehouse.workflows import (
    ApprovalConflict,
    action_catalog,
    approve_workflow_run,
    get_workflow,
    get_workflow_run,
    list_workflows,
    reconcile_workflow_run,
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


def first_param(params: Params, key: str) -> str | None:
    """Return the first value of query parameter ``key``, or ``None`` when absent."""
    values = params.get(key)
    return values[0] if values else None


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
        "categories": coverage_by_category(effective),
        "families": coverage_by_family(effective),
        "frameworks": coverage_by_framework(effective),
        "review_log_verified": bool(effective["review_log_verified"]),
    }


def _ccf_assessment(lake: Path) -> JsonObject:
    path = lake / "gold" / "ccf_assessment.json"
    if pinned_path(path).is_file():
        return read_json(path, base_dir=lake)
    return {
        "schema_version": "trustops.ccf_assessment.v1",
        "status": "not_evaluated",
        "scope": "observed_assets",
        "population_completeness": "not_established",
        "safeguards": [],
        "asset_results": [],
        "requirements": [],
    }


def _ccf_assessment_summary(lake: Path) -> JsonObject:
    from security_lakehouse.ccf_queries import read_summary

    indexed = read_summary(lake)
    if indexed is not None:
        return indexed
    result = _ccf_assessment(lake)
    # Compatibility for generations created before the bounded SQL projection.
    result["asset_result_count"] = len(result.pop("asset_results"))
    return result


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
    "/api/v1/ccf/assessment": ("ccf.assessment", _ccf_assessment_summary),
    "/api/v1/oscal/component-definition": (
        "oscal.component-definition",
        lambda lake: build_component_definition(lake_dir=lake),
    ),
}

# Singletons whose list members page together when a caller sends limit, offset,
# or cursor: route -> (paged parts, loader returning the uncapped payload).
# Without those params a DEFAULT_PAGED route serves its first default-size page
# (meta.default_page); any other route serves the singleton payload unchanged.
PAGED_SINGLETONS: dict[str, tuple[tuple[str, ...], Callable[[Path], JsonObject]]] = {
    "/api/v1/graph": (("nodes", "edges"), build_compliance_graph),
    "/api/v1/repo-graph": (("nodes", "edges"), build_repository_graph),
    "/api/v1/graph/coverage": (
        ("assets", "orphans.controls", "orphans.frameworks", "orphans.assets"),
        lambda lake: analyze_coverage(lake, detail_limit=None),
    ),
}
DEFAULT_PAGED: frozenset[str] = frozenset({"/api/v1/graph", "/api/v1/repo-graph"})


# Route -> (resource name, loader) for endpoints returning a row collection.
def _violations_with_framework(lake: Path) -> list[JsonObject]:
    rows = build_current_posture(lake)["violations"]
    controls = {
        r["control_id"]: r for r in read_jsonl(lake / "gold/control_posture.jsonl", missing_ok=True, base_dir=lake)
    }
    return [{**row, "framework": controls.get(row["control_id"], {}).get("framework", "unknown")} for row in rows]


COLLECTION_LOADERS: dict[str, tuple[str, Callable[[Path], list[JsonObject]]]] = {
    "/api/v1/connector-runs": (
        "connector-runs",
        lambda lake: read_jsonl(lake / "gold" / "connector_runs.jsonl", missing_ok=True, base_dir=lake),
    ),
    "/api/v1/ccf/asset-results": ("ccf.asset-results", lambda lake: _ccf_assessment(lake)["asset_results"]),
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
            read_projection(lake / "silver" / "normalized_events.jsonl", None, missing_ok=True, base_dir=lake),
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
    "/api/v1/violations": ("violations", _violations_with_framework),
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
    if _suffix_match(path, "/api/v1/workflows/runs/", "/reconcile") is not None:
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
        "resource": "mapping-reviews.report",
        "path": "/api/v1/mapping-reviews/report",
        "kind": "singleton",
        "methods": ["GET"],
        "scopes": ["read"],
        "query": ["framework_id", "risk_domain"],
    },
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
        "path": "/api/v1/workflows/runs/{run_id}/reconcile",
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
        "resource": "agent-runs.decisions",
        "path": "/api/v1/agent-runs/{run_id}/decisions/{decision_index}/reconcile",
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
        entry: JsonObject = {"resource": name, "path": path, "kind": "singleton", "methods": ["GET"]}
        if path in PAGED_SINGLETONS:
            entry["query"] = ["limit", "offset", "cursor"]
            entry["paged_parts"] = list(PAGED_SINGLETONS[path][0])
            if path in DEFAULT_PAGED:
                entry["default_paged"] = True
        catalog.append(entry)
    for path, (name, _loader) in COLLECTION_LOADERS.items():
        catalog.append(
            {
                "resource": name,
                "path": path,
                "kind": "collection",
                "methods": ["GET", *_WRITABLE.get(path, [])],
                "query": ["limit", "offset", "cursor", "sort", "<field>=<value>"],
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
                "next_cursor": {
                    "type": "string",
                    "nullable": True,
                    "description": "Opaque cursor for the next page; null on the last page.",
                },
                "parts": {
                    "type": "object",
                    "description": "Per-list count and returned rows when an object payload is paged.",
                },
                "default_page": {
                    "type": "boolean",
                    "description": (
                        "True when the caller sent no limit, offset, or cursor and the route served "
                        "its first default-size page; follow next_cursor for the rest."
                    ),
                },
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
            if path == "/api/v1/scheduler/tick" and method == "POST":
                operation["responses"]["201"] = operation["responses"].pop("200")
                operation["responses"]["503"] = {
                    "description": "Stored scheduler state failed validation",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/V1Envelope"}}},
                }
            if parameters and method == "GET":
                operation["parameters"] = parameters
            if scopes := row.get("scopes"):
                operation["description"] = f"Requires scope: {', '.join(scopes)}."
            if row.get("default_paged") and method == "GET":
                note = (
                    f"Pages {' and '.join(row['paged_parts'])} together. Without limit, offset, or cursor it "
                    "serves the first page of 100 (meta.default_page); follow meta.next_cursor until null."
                )
                operation["description"] = f"{operation['description']} {note}" if "description" in operation else note
            item[method.lower()] = operation
        paths[path] = item
    return paths


def merge_openapi(spec: JsonObject) -> JsonObject:
    """Fold the catch-all-served routes into a FastAPI-generated schema."""
    spec = copy.deepcopy(spec)
    paths = dict(spec.get("paths") or {})
    # The catch-all itself documents nothing and implies a route that takes an
    # arbitrary path segment, which is worse than absent.
    paths.pop("/api/v1/{rest}", None)
    paths.pop("/api/{rest}", None)
    for path, item in openapi_paths().items():
        paths.setdefault(path, item)
    for path in (
        "/api/v1/ingestion/eval",
        "/api/v1/scheduler/tick",
        "/api/v1/snapshots",
        "/api/v1/connectors/{connector_id}/sync",
    ):
        operation = paths.get(path, {}).get("post")
        if operation is None:
            continue
        parameters = operation.setdefault("parameters", [])
        for header, schema in (
            ("Prefer", {"type": "string", "enum": ["respond-async"]}),
            ("Idempotency-Key", {"type": "string", "minLength": 1, "maxLength": 200}),
        ):
            if not any(item.get("name") == header and item.get("in") == "header" for item in parameters):
                parameters.append({"name": header, "in": "header", "required": False, "schema": schema})
        operation["responses"]["202"] = {
            "description": "Durable operation accepted. Poll Location; acceptance does not establish completion.",
            "headers": {"Location": {"schema": {"type": "string"}}, "Retry-After": {"schema": {"type": "integer"}}},
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/V1Envelope"}}},
        }
    # JSONResponse endpoints bypass FastAPI's response inference. Their common
    # wire envelope is still a real contract; domain data may remain generic.
    for path, item in paths.items():
        if not path.startswith("/api/v1/"):
            continue
        for operation in item.values():
            if not isinstance(operation, dict):
                continue
            for code, response in operation.get("responses", {}).items():
                content = response.get("content", {}).get("application/json")
                if str(code).startswith("2") and content is not None and not content.get("schema"):
                    content["schema"] = {"$ref": "#/components/schemas/V1Envelope"}
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
            "cursor": "opaque meta.next_cursor from the previous page; takes precedence over offset",
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
    filters = _collection_filters(params)
    if not filters:
        return rows, {}
    if rows:
        _reject_unknown_filters(filters, {key for row in rows for key in row})
    return [row for row in rows if _row_matches(row, filters)], filters


_PAGE_PARAMS = frozenset({"limit", "offset", "cursor"})


def _collection_filters(params: Params) -> dict[str, list[str]]:
    return {
        key: [value for raw in values for value in raw.split(",") if value]
        for key, values in params.items()
        if key not in _PAGE_PARAMS | {"sort"}
    }


def _reject_unknown_filters(filters: Mapping[str, list[str]], fields: set[str]) -> None:
    unknown = set(filters) - fields
    if unknown:
        raise ValueError("unknown filter field: " + ", ".join(sorted(unknown)))


def _row_matches(row: JsonObject, filters: Mapping[str, list[str]]) -> bool:
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


def sort_collection(rows: list[JsonObject], params: Params) -> tuple[list[JsonObject], str | None]:
    """Apply ``sort=field`` / ``sort=-field`` ordering; ``None`` values sort last."""
    sort = first_param(params, "sort")
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
    return collection_page_response(
        resource, page_rows, count=count, limit=limit, offset=offset, sort=sort, filters=applied_filters
    )


def collection_page_response(
    resource: str,
    page_rows: list[JsonObject] | JsonObject,
    *,
    count: int,
    limit: int,
    offset: int,
    sort: str | None,
    filters: dict[str, list[str]],
    returned: int | None = None,
    extra_meta: JsonObject | None = None,
) -> JsonObject:
    """Shared envelope for materialized, streamed, indexed, and object pages.

    ``page_rows`` is the page payload: a row list for collections, or an object
    whose list members were paged together (pass ``returned`` for those).
    """
    next_offset = offset + limit
    next_cursor = encode_cursor(next_offset) if next_offset < count else None
    return envelope(
        resource,
        page_rows,
        meta={
            "count": count,
            "returned": len(page_rows) if returned is None else returned,
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "filters": filters,
            "next_cursor": next_cursor,
            **(extra_meta or {}),
        },
    )


def wants_page(params: Params) -> bool:
    """True when a caller sent any of ``limit``, ``offset``, or ``cursor``."""
    return any(params.get(key) for key in _PAGE_PARAMS)


def paged_object_response(resource: str, data: JsonObject, parts: tuple[str, ...], params: Params) -> JsonObject:
    """Page the list members ``parts`` of an object payload with one cursor.

    Each part is sliced to the same ``[offset, offset + limit)`` window, so a
    caller that follows ``next_cursor`` until it is ``None`` and concatenates
    each part rebuilds the full lists in order. Every other member (summaries,
    counts) is repeated unchanged on each page. ``meta.count`` is the longest
    part, and ``meta.parts`` gives each part's own count and returned rows. A
    dotted part name (``orphans.assets``) addresses a list one level down.
    """
    _, limit, offset = paginate_collection([], params)
    page = {key: dict(value) if isinstance(value, dict) else value for key, value in data.items()}
    part_meta: JsonObject = {}
    for part in parts:
        parent_key, _, child_key = part.rpartition(".")
        target = page[parent_key] if parent_key else page
        rows = target[child_key]
        target[child_key] = rows[offset : offset + limit]
        part_meta[part] = {"count": len(rows), "returned": len(target[child_key])}
    return collection_page_response(
        resource,
        page,
        count=max((meta["count"] for meta in part_meta.values()), default=0),
        limit=limit,
        offset=offset,
        sort=None,
        filters={},
        returned=sum(meta["returned"] for meta in part_meta.values()),
        extra_meta={"parts": part_meta},
    )


EVIDENCE_PATH = Path("silver") / "normalized_events.jsonl"


def evidence_page_response(lake: Path, params: Params) -> JsonObject:
    """Page ``/api/v1/evidence`` by streaming the pinned silver file.

    Without filters, rows before the page are skipped unparsed and reading
    stops at the end of the page, so a page parses at most ``limit`` events.
    ``count`` comes from :func:`validated_jsonl_count`, which parses the whole
    file once per file version, keeping nothing, so an invalid row anywhere
    still fails the request as the materialized path did. With filters, one
    streaming pass counts matches and keeps only the page. A ``sort`` needs
    every row, so it falls back to the materialized collection path. Rows come
    in file order either way, matching the materialized path.
    """
    if first_param(params, "sort"):
        rows = with_asset_names(
            read_projection(lake / EVIDENCE_PATH, None, missing_ok=True, base_dir=lake), load_asset_names(lake)
        )
        return collection_response("evidence", rows, params)
    _, limit, offset = paginate_collection([], params)
    filters = _collection_filters(params)
    names = load_asset_names(lake)
    path = lake / EVIDENCE_PATH
    if not filters:
        count = validated_jsonl_count(path, missing_ok=True, base_dir=lake)
        window = list(iter_jsonl_slice(path, offset, offset + limit, missing_ok=True, base_dir=lake))
        return collection_page_response(
            "evidence",
            with_asset_names(window, names),
            count=count,
            limit=limit,
            offset=offset,
            sort=None,
            filters={},
        )
    page: list[JsonObject] = []
    fields: set[str] = set()
    count = 0
    for raw in iter_jsonl(path, missing_ok=True, base_dir=lake):
        (row,) = with_asset_names([raw], names)
        fields.update(row)
        if not _row_matches(row, filters):
            continue
        if offset <= count < offset + limit:
            page.append(row)
        count += 1
    if fields:
        _reject_unknown_filters(filters, fields)
    return collection_page_response(
        "evidence", page, count=count, limit=limit, offset=offset, sort=None, filters=filters
    )


@generation_reader
@connector_state_reader
def handle_get(
    path: str, params: Params, lake_dir: str | Path, *, share_lakes: tuple[Path, ...] = ()
) -> tuple[HTTPStatus, JsonObject]:
    """Resolve a v1 GET against one pinned assessment generation."""
    try:
        status, body = _handle_get(path, params, lake_dir, share_lakes=share_lakes)
        strict_json.validate(body)
    except strict_json.InvalidJSON:
        return HTTPStatus.SERVICE_UNAVAILABLE, error_envelope("invalid_stored_data", "stored data failed validation")
    historical = path == "/api/v1/oscal/assessment-results" and bool(params.get("snapshot_id"))
    if historical:
        # The successful export already verified this immutable snapshot. Errors
        # must not advertise the unrelated current generation either.
        generation = (
            load_snapshot(lake_dir, params["snapshot_id"][0]).get("generation") if status == HTTPStatus.OK else None
        )
    else:
        generation = generation_identity(lake_dir)
    if generation is not None:
        body["meta"]["generation"] = generation
    return status, body


def _handle_get(
    path: str, params: Params, lake_dir: str | Path, *, share_lakes: tuple[Path, ...] = ()
) -> tuple[HTTPStatus, JsonObject]:
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
        if any(key in params for key in ("limit", "offset", "include_details")):
            try:
                include = first_param(params, "include_details") or "false"
                if include not in {"true", "false"}:
                    raise ValueError("include_details must be true or false")
                detail = page_framework_detail(
                    detail,
                    limit=int(first_param(params, "limit") or "20"),
                    offset=int(first_param(params, "offset") or "0"),
                    include_details=include == "true",
                )
            except ValueError:
                return HTTPStatus.BAD_REQUEST, error_envelope(
                    "bad_request", "invalid framework page parameters", resource="framework.detail"
                )
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
        shares = list_shares(lake, include_revoked=include_revoked, additional_lakes=share_lakes)
        collection_params = {key: values for key, values in params.items() if key != "include_revoked"}
        try:
            return HTTPStatus.OK, collection_response("trust-shares", shares, collection_params)
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
        except SnapshotIntegrityError:
            return HTTPStatus.SERVICE_UNAVAILABLE, error_envelope(
                "invalid_stored_data", "stored data failed validation", resource="posture.as_of"
            )
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
        except ValueError:
            return HTTPStatus.CONFLICT, error_envelope(
                "assessment_unavailable",
                "Assessment integrity or historical detail is unavailable.",
                resource="oscal.assessment-results",
            )
        return HTTPStatus.OK, envelope("oscal.assessment-results", data)
    if path in {"/api/v1/ccf/assessment", "/api/v1/ccf/asset-results"}:
        from security_lakehouse.ccf_queries import CcfReadError, read_page

        try:
            if path.endswith("/assessment"):
                return HTTPStatus.OK, envelope("ccf.assessment", _ccf_assessment_summary(lake))
            _, filters = filter_collection([], params)
            _, sort = sort_collection([], params)
            _, limit, offset = paginate_collection([], params)
            indexed = read_page(lake, filters=filters, sort=sort, limit=limit, offset=offset)
            if indexed is not None:
                rows, count = indexed
                return HTTPStatus.OK, collection_page_response(
                    "ccf.asset-results",
                    rows,
                    count=count,
                    limit=limit,
                    offset=offset,
                    sort=sort,
                    filters=filters,
                )
        except CcfReadError:
            return HTTPStatus.CONFLICT, error_envelope(
                "assessment_unavailable",
                "CCF assessment projection is unavailable.",
                resource="ccf.assessment" if path.endswith("/assessment") else "ccf.asset-results",
            )
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request parameters", resource="ccf.asset-results"
            )
    paged = PAGED_SINGLETONS.get(path)
    requested_page = wants_page(params)
    if paged is not None and (requested_page or path in DEFAULT_PAGED):
        resource = SINGLETON_LOADERS[path][0]
        parts, full_loader = paged
        try:
            paginate_collection([], params)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request parameters", resource=resource
            )
        body = paged_object_response(resource, full_loader(lake), parts, params)
        if not requested_page:
            body["meta"]["default_page"] = True
        return HTTPStatus.OK, body
    singleton = SINGLETON_LOADERS.get(path)
    if singleton is not None:
        resource, loader = singleton
        return HTTPStatus.OK, envelope(resource, loader(lake))
    if path == "/api/v1/evidence":
        try:
            return HTTPStatus.OK, evidence_page_response(lake, params)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "invalid request parameters", resource="evidence"
            )
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


MAPPING_REVIEW_QUERY_INVALID = (
    "invalid mapping review query; status must be pending, proposed, needs_changes, rejected, "
    "org_reviewed, maintainer_reviewed, or all, and sort and cursor must come from a previous response"
)
MAPPING_REVIEW_DECISIONS_UNREADABLE = "the mapping review decision log could not be read"


def _mapping_review_get(path: str, params: Params, lake: Path) -> tuple[HTTPStatus, JsonObject]:
    if path == "/api/v1/mapping-reviews/report":
        report = mapping_review_report(
            effective_safeguards(lake),
            framework_id=first_param(params, "framework_id") or None,
            risk_domain=first_param(params, "risk_domain") or None,
        )
        return HTTPStatus.OK, envelope("mapping-reviews.report", report)
    if path == "/api/v1/mapping-reviews/queue":
        try:
            rows, rest = _mapping_review_queue_rows(lake, params)
            return HTTPStatus.OK, collection_response("mapping-reviews.queue", rows, rest)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", MAPPING_REVIEW_QUERY_INVALID, resource="mapping-reviews.queue"
            )
    if path == MAPPING_REVIEW_DECISIONS_PATH:
        try:
            return HTTPStatus.OK, collection_response("mapping-reviews.decisions", list_decisions(lake), params)
        except ValueError:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", MAPPING_REVIEW_DECISIONS_UNREADABLE, resource="mapping-reviews.decisions"
            )
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
    if options is not None and not isinstance(options, dict):
        return error_envelope("bad_request", "options must be an object", resource=resource)
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
    share_lakes: tuple[Path, ...] = (),
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
    payload = body if body is not None else {}
    try:
        strict_json.validate(payload)
        if not isinstance(payload, dict):
            raise ValueError("body must be a JSON object")
    except (ValueError, TypeError):
        return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", "invalid JSON body")
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
    workflow_reconcile = _suffix_match(path, "/api/v1/workflows/runs/", "/reconcile")
    if workflow_reconcile is not None:
        try:
            run = reconcile_workflow_run(
                lake,
                run_id=workflow_reconcile,
                actor=str(payload.get("actor") or ""),
                note=str(payload.get("note") or ""),
            )
        except ApprovalConflict:
            return HTTPStatus.CONFLICT, error_envelope(
                "conflict", "claim is active or not eligible for reconciliation", resource="workflows.run"
            )
        except (ValueError, TypeError):
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "independent reviewer and reconciliation reason required", resource="workflows.run"
            )
        return HTTPStatus.OK, envelope("workflows.run", run)
    workflow_retry = _suffix_match(path, "/api/v1/workflows/runs/", "/retry")
    if workflow_retry is not None:
        try:
            run = retry_workflow_run(lake, run_id=workflow_retry, actor=str(payload.get("actor") or "console"))
        except ApprovalConflict:
            return HTTPStatus.CONFLICT, error_envelope(
                "conflict", "interrupted approval requires reconciliation", resource="workflows.run"
            )
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
        except ApprovalConflict:
            return HTTPStatus.CONFLICT, error_envelope(
                "conflict", "approval state or workflow version changed", resource="workflows.run"
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
        except ApprovalConflict:
            return HTTPStatus.CONFLICT, error_envelope(
                "conflict", "approval state or workflow version changed", resource="workflows.run"
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
        revoked = revoke_share(lake, revoke, additional_lakes=share_lakes)
        if revoked is None:
            return HTTPStatus.NOT_FOUND, error_envelope("not_found", f"unknown share {revoke}", resource="trust-shares")
        return HTTPStatus.CREATED, envelope("trust-shares", revoked)
    configure = _connector_action(path, "configure")
    if configure is not None:
        if payload.get("credentials") is not None and not isinstance(payload["credentials"], dict):
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "credentials must be an object", resource="connector.configure"
            )
        if not isinstance(payload.get("state", "enabled"), str) or payload.get("state", "enabled").lower() not in {
            "enabled",
            "disabled",
        }:
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "state must be enabled or disabled", resource="connector.configure"
            )
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
                eval_result.to_dict(),
            ),
        )
    if path == "/api/v1/scheduler/tick":
        from security_lakehouse.scheduler import tick

        try:
            fired = tick(lake, on_snapshot_written=on_snapshot_written)
        except strict_json.InvalidJSON:
            return HTTPStatus.SERVICE_UNAVAILABLE, error_envelope(
                "invalid_stored_data", "stored data failed validation"
            )
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
        delegation = payload.get("delegation")
        if delegation is not None and not isinstance(delegation, dict):
            return HTTPStatus.BAD_REQUEST, error_envelope(
                "bad_request", "delegation must be an object", resource="connector.link.complete"
            )
        try:
            link_result = complete_cloud_link(
                lake,
                link_complete,
                session_id=session_id,
                actor=str(payload.get("actor") or "console"),
                role_arn=str(payload.get("role_arn") or "").strip() or None,
                subscription_id=str(payload.get("subscription_id") or "").strip() or None,
                project_id=str(payload.get("project_id") or "").strip() or None,
                delegation=delegation,
            )
        except KeyError:
            return HTTPStatus.NOT_FOUND, error_envelope(
                "not_found", "cloud link session not found", resource="connector.link.complete"
            )
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, error_envelope("bad_request", str(exc), resource="connector.link.complete")
        return HTTPStatus.CREATED, envelope("connector.link.complete", link_result)
    return HTTPStatus.NOT_FOUND, error_envelope("not_found", "unknown route")
