"""Shared ``/api/v1`` response envelope and mutation-scope contract.

Lower layers (auth middleware, the operation queue) depend on this module
instead of :mod:`security_lakehouse.api_v1`, which re-exports every name.
"""

from __future__ import annotations

from typing import Any

from security_lakehouse.jsontypes import JsonObject

API_VERSION = "v1"


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


def _suffix_match(path: str, prefix: str, suffix: str) -> str | None:
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    rest = path[len(prefix) : -len(suffix)]
    return rest or None


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
