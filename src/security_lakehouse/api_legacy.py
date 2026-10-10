"""Transport-agnostic legacy ``/api/*`` surface (UI-compatible, unversioned).

The Next.js console talks to these routes. Extracting the dispatch here — the
same pattern as :mod:`security_lakehouse.api_v1` — lets both the zero-dependency
stdlib server and the optional FastAPI server serve the *identical* surface, so
the console works the same in local mode and authenticated server mode.

Handlers return ``(HTTPStatus, body)``. Transports apply read redaction and
authenticate callers; this module centralizes route dispatch and mutation
scope requirements so local mode and server mode cannot drift.
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Any

from security_lakehouse import api_v1
from security_lakehouse.assessment import SnapshotWrittenHook, build_current_posture, write_assessment_snapshot
from security_lakehouse.asset_names import load_asset_names, with_asset_names
from security_lakehouse.audit_log import build_audit_log
from security_lakehouse.connector_state import (
    append_config_event,
    build_catalog_view,
    configure_payload_error,
    enablement_probe_error,
    list_runs,
    resolve_configure_payload,
    run_discovery,
    run_probe,
)
from security_lakehouse.framework_detail import build_framework_detail
from security_lakehouse.framework_provenance import build_framework_view
from security_lakehouse.generations import generation_reader
from security_lakehouse.graph import build_compliance_graph, build_framework_crosswalk, build_repository_graph
from security_lakehouse.io import read_jsonl, resolve_path
from security_lakehouse.mappings import (
    build_framework_equivalence,
    build_reviewed_crosswalk,
    load_control_article_mappings,
)
from security_lakehouse.readiness import build_readiness_view
from security_lakehouse.scheduler import tick as scheduler_tick
from security_lakehouse.tracking import ALLOWED_STATES, append_event, latest_state, list_events
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

AUDITOR_ROLE = "auditor"

Query = dict[str, list[str]]
Body = dict[str, Any]


def _first(query: Query, key: str) -> str | None:
    return api_v1.first_param(query, key)


def _suffix_match(path: str, prefix: str, suffix: str) -> str | None:
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    rest = path[len(prefix) : -len(suffix)]
    return rest or None


def _workflow_get_match(path: str) -> str | None:
    if not path.startswith("/api/workflows/"):
        return None
    rest = path[len("/api/workflows/") :]
    if rest in {"", "actions"} or rest.startswith("actions/") or "/" in rest:
        return None
    return rest


def _workflow_run_id_match(path: str) -> str | None:
    prefix = "/api/workflows/runs/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :].strip("/")
    if not rest or "/" in rest:
        return None
    return rest


def required_post_scope(path: str) -> str:
    """Return the RBAC scope required to mutate a legacy console route.

    Every legacy mutation has a v1 twin, so the v1 table is the single source
    of truth; ``/api/<rest>`` is scoped exactly like ``/api/v1/<rest>``.
    """
    prefix = "/api/"
    if not path.startswith(prefix) or path.startswith("/api/v1/"):
        return api_v1._UNMAPPED_POST_SCOPE
    return api_v1.required_post_scope("/api/v1/" + path[len(prefix) :])


@generation_reader
def handle_get(
    path: str, query: Query, lake_dir: str | Path, *, share_lakes: tuple[Path, ...] = ()
) -> tuple[HTTPStatus, Body]:
    """Resolve a legacy GET into ``(status, body)``. Auditor redaction is applied by the transport."""
    lake = resolve_path(lake_dir)
    if path == "/api/posture/current":
        return HTTPStatus.OK, build_current_posture(lake)
    if path == "/api/violations":
        posture = build_current_posture(lake, inline_violation_cap=None)
        framework = _first(query, "framework")
        control_id = _first(query, "control_id")
        violations = posture["violations"]
        if framework:
            control_frameworks = {
                row["control_id"]: row["framework"]
                for row in read_jsonl(lake / "gold" / "control_posture.jsonl", base_dir=lake)
            }
            violations = [row for row in violations if control_frameworks.get(row["control_id"]) == framework]
        if control_id:
            violations = [row for row in violations if row["control_id"] == control_id]
        return HTTPStatus.OK, {"count": len(violations), "violations": violations}
    if path == "/api/controls":
        control_id = _first(query, "control_id")
        controls = read_jsonl(lake / "gold" / "control_posture.jsonl", base_dir=lake)
        if control_id:
            controls = [row for row in controls if row["control_id"] == control_id]
        return HTTPStatus.OK, {"controls": controls}
    if path == "/api/control-tests":
        result = _first(query, "result")
        control_id = _first(query, "control_id")
        rows = read_jsonl(lake / "gold" / "control_tests.jsonl", base_dir=lake)
        if result:
            rows = [row for row in rows if row["result"] == result]
        if control_id:
            rows = [row for row in rows if row["control_id"] == control_id]
        return HTTPStatus.OK, {"count": len(rows), "control_tests": rows}
    if path == "/api/evidence":
        control_id = _first(query, "control_id")
        rows = read_jsonl(lake / "silver" / "normalized_events.jsonl", base_dir=lake)
        if control_id:
            rows = [row for row in rows if control_id in row["control_ids"]]
        rows = with_asset_names(rows, load_asset_names(lake))
        return HTTPStatus.OK, {"count": len(rows), "evidence": rows}
    if path == "/api/assets":
        return HTTPStatus.OK, {"assets": read_jsonl(lake / "gold" / "asset_risk.jsonl", base_dir=lake)}
    if path == "/api/snapshots":
        snapshots = api_v1.list_snapshots(lake)
        return HTTPStatus.OK, {"count": len(snapshots), "snapshots": snapshots}
    if path == "/api/connectors":
        view = build_catalog_view(lake)
        return HTTPStatus.OK, {"count": len(view), "connectors": view}
    if path == "/api/frameworks":
        view = build_framework_view()
        return HTTPStatus.OK, {"count": len(view), "frameworks": view}
    framework_detail = _suffix_match(path, "/api/frameworks/", "/detail")
    if framework_detail is not None:
        detail = build_framework_detail(framework_detail, lake)
        if detail is None:
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}
        return HTTPStatus.OK, detail
    if path == "/api/graph":
        return HTTPStatus.OK, build_compliance_graph(lake)
    if path == "/api/repo-graph":
        return HTTPStatus.OK, build_repository_graph(lake)
    if path == "/api/crosswalk":
        return HTTPStatus.OK, build_framework_crosswalk()
    if path == "/api/crosswalk/reviewed":
        return HTTPStatus.OK, build_reviewed_crosswalk()
    if path == "/api/mappings/equivalence":
        return HTTPStatus.OK, build_framework_equivalence()
    if path == "/api/mappings":
        mappings = load_control_article_mappings()
        return HTTPStatus.OK, {"count": len(mappings), "mappings": list(mappings.values())}
    if path == "/api/readiness":
        view = build_readiness_view()
        return HTTPStatus.OK, {"count": len(view), "frameworks": view}
    if path == "/api/workflows":
        rows = list_workflows(lake)
        return HTTPStatus.OK, {"count": len(rows), "workflows": rows}
    if path == "/api/workflows/actions":
        return HTTPStatus.OK, {"actions": action_catalog()}
    workflow_run_id = _workflow_run_id_match(path)
    if workflow_run_id is not None:
        run = get_workflow_run(lake, workflow_run_id)
        if run is None:
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}
        return HTTPStatus.OK, {"run": run}
    workflow_get = _workflow_get_match(path)
    if workflow_get is not None:
        workflow = get_workflow(lake, workflow_get)
        if workflow is None:
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}
        return HTTPStatus.OK, workflow
    workflow_runs = _suffix_match(path, "/api/workflows/", "/runs")
    if workflow_runs is not None and workflow_runs != "actions":
        return HTTPStatus.OK, {"workflow_id": workflow_runs, "runs": list_workflow_runs(lake, workflow_runs)}
    if path == "/api/trust-shares":
        include_revoked = (_first(query, "include_revoked") or "false").lower() in {"1", "true", "yes"}
        shares = list_shares(lake, include_revoked=include_revoked, additional_lakes=share_lakes)
        return HTTPStatus.OK, {"count": len(shares), "shares": shares}
    if path == "/api/audit-log":
        limit = int(_first(query, "limit") or "200")
        include_requests = (_first(query, "include_requests") or "false").lower() in {"1", "true", "yes"}
        entries = build_audit_log(
            lake,
            category=_first(query, "category"),
            actor=_first(query, "actor"),
            limit=max(1, min(limit, 1000)),
            include_requests=include_requests,
        )
        return HTTPStatus.OK, {"count": len(entries), "entries": entries}
    connector_runs = _suffix_match(path, "/api/connectors/", "/runs")
    if connector_runs is not None:
        return HTTPStatus.OK, {"connector_id": connector_runs, "runs": list_runs(lake, connector_runs)}
    tracking = _suffix_match(path, "/api/violations/", "/tracking")
    if tracking is not None:
        current = latest_state(lake, violation_id=tracking)
        return HTTPStatus.OK, {
            "violation_id": tracking,
            "current_state": (current or {}).get("state", "open"),
            "events": list_events(lake, violation_id=tracking),
        }
    return HTTPStatus.NOT_FOUND, {"error": "not_found"}


def handle_post(
    path: str,
    body: Body,
    lake_dir: str | Path,
    *,
    role: str = "",
    on_snapshot_written: SnapshotWrittenHook | None = None,
    share_lakes: tuple[Path, ...] = (),
) -> tuple[HTTPStatus, Body]:
    """Resolve a legacy POST into ``(status, body)``.

    ``on_snapshot_written`` mirrors ``api_v1.handle_post``'s parameter of the
    same name: forwarded to :func:`write_assessment_snapshot` for the
    ``/api/snapshots`` route so server mode's legacy (unversioned) surface
    dispatches webhook events too, not only ``/api/v1/snapshots``.
    """
    lake = resolve_path(lake_dir)
    if role == AUDITOR_ROLE:
        return HTTPStatus.FORBIDDEN, {"error": "forbidden", "reason": "auditor role is read-only"}
    body = body or {}
    if path == "/api/snapshots":
        reason = str(body.get("reason") or "api_request")
        snapshot_path = write_assessment_snapshot(lake, reason=reason, on_snapshot_written=on_snapshot_written)
        return HTTPStatus.CREATED, {"snapshot_path": str(snapshot_path), "reason": reason}
    triage = _suffix_match(path, "/api/violations/", "/triage")
    if triage is not None:
        state = str(body.get("state") or "").lower()
        if state not in ALLOWED_STATES:
            return HTTPStatus.BAD_REQUEST, {
                "error": "bad_request",
                "reason": f"state must be one of {sorted(ALLOWED_STATES)}",
            }
        record = append_event(
            lake,
            violation_id=triage,
            actor=str(body.get("actor") or "anonymous"),
            state=state,
            assignee=body.get("assignee"),
            due_at=body.get("due_at"),
            note=body.get("note"),
            idempotency_key=body.get("idempotency_key"),
        )
        return HTTPStatus.CREATED, {"event": record}
    verify = _suffix_match(path, "/api/evidence/", "/verify")
    if verify is not None:
        return HTTPStatus.OK, verify_event(lake, verify)
    configure = _suffix_match(path, "/api/connectors/", "/configure")
    if configure is not None:
        state = str(body.get("state") or "enabled").lower()
        credentials, options = resolve_configure_payload(
            lake,
            connector_id=configure,
            credentials=body.get("credentials") if "credentials" in body else None,
            options=body.get("options") if "options" in body else None,
        )
        error = configure_payload_error(
            connector_id=configure,
            state=state,
            credentials=credentials,
            options=options,
        )
        if error:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": error}
        error = enablement_probe_error(
            lake,
            connector_id=configure,
            state=state,
            credentials=credentials,
            options=options,
        )
        if error:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": error}
        record = append_config_event(
            lake,
            connector_id=configure,
            state=state,
            actor=str(body.get("actor") or "console"),
            credentials=credentials,
            options=options,
        )
        return HTTPStatus.CREATED, {"event": record}
    probe = _suffix_match(path, "/api/connectors/", "/probe")
    if probe is not None:
        record = run_probe(
            lake,
            connector_id=probe,
            actor=str(body.get("actor") or "console"),
            credentials=body.get("credentials") if "credentials" in body else None,
            options=body.get("options") if "options" in body else None,
        )
        return HTTPStatus.CREATED, {"run": record}
    discover = _suffix_match(path, "/api/connectors/", "/discover")
    if discover is not None:
        record = run_discovery(
            lake,
            connector_id=discover,
            actor=str(body.get("actor") or "console"),
            credentials=body.get("credentials") if "credentials" in body else None,
            options=body.get("options") if "options" in body else None,
        )
        return HTTPStatus.CREATED, {"run": record}
    if path == "/api/workflows":
        try:
            record = save_workflow(
                lake,
                workflow_id=body.get("workflow_id"),
                name=str(body.get("name") or ""),
                description=str(body.get("description") or ""),
                nodes=body.get("nodes") or [],
                edges=body.get("edges") or [],
                actor=str(body.get("actor") or "console"),
            )
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"workflow": record}
    if path == "/api/scheduler/tick":
        results = scheduler_tick(lake)
        return HTTPStatus.CREATED, {"fired": len(results), "results": results}
    if path == "/api/workflows/actions/run":
        try:
            output = run_action(lake, node_type=str(body.get("node_type") or ""), params=body.get("params") or {})
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"output": output}
    workflow_run = _suffix_match(path, "/api/workflows/", "/run")
    if workflow_run is not None and workflow_run != "actions":
        try:
            run = run_workflow(
                lake,
                workflow_id=workflow_run,
                actor=str(body.get("actor") or "console"),
                dry_run=bool(body.get("dry_run")),
            )
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"run": run}
    workflow_retry = _suffix_match(path, "/api/workflows/runs/", "/retry")
    if workflow_retry is not None:
        try:
            run = retry_workflow_run(lake, run_id=workflow_retry, actor=str(body.get("actor") or "console"))
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"run": run}
    workflow_approve = _suffix_match(path, "/api/workflows/runs/", "/approve")
    if workflow_approve is not None:
        try:
            run = approve_workflow_run(
                lake,
                run_id=workflow_approve,
                actor=str(body.get("actor") or "console"),
                note=str(body.get("note") or ""),
            )
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"run": run}
    workflow_reject = _suffix_match(path, "/api/workflows/runs/", "/reject")
    if workflow_reject is not None:
        try:
            run = reject_workflow_run(
                lake,
                run_id=workflow_reject,
                actor=str(body.get("actor") or "console"),
                note=str(body.get("note") or ""),
            )
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"run": run}
    if path == "/api/trust-shares":
        try:
            share = create_share(
                lake,
                role=str(body.get("role") or "auditor"),
                scope=str(body.get("scope") or "posture_full"),
                expires_in_hours=int(body.get("expires_in_hours") or 24),
                created_by=str(body.get("created_by") or "console"),
                framework_id=body.get("framework_id"),
                sensitivity_ceiling=str(body.get("sensitivity_ceiling") or "public"),
                idempotency_key=body.get("idempotency_key"),
            )
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "reason": "invalid request"}
        return HTTPStatus.CREATED, {"share": share}
    revoke = _suffix_match(path, "/api/trust-shares/", "/revoke")
    if revoke is not None:
        revoked = revoke_share(lake, revoke, additional_lakes=share_lakes)
        if revoked is None:
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}
        return HTTPStatus.CREATED, {"share": revoked}
    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
