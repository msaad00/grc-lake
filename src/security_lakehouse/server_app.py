"""Optional FastAPI server (``trustops[server]`` extra).

Server mode serves the same assessment engine and the same
:mod:`security_lakehouse.api_v1` contract as local mode, plus the platform
surface local mode cannot provide: an application-state database, bearer-token
authentication, and role-based access control.

Authentication is required by default. Start with ``require_auth=False`` (or set
``TRUSTOPS_ALLOW_INSECURE_NO_AUTH=1``) only for local development; every request
then runs as a synthetic admin. Local mode (:mod:`security_lakehouse.server`)
remains zero-dependency and unauthenticated by design.

Import this module only when the ``server`` extra is installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import secrets
import threading
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from security_lakehouse import api_legacy, api_v1, remediation_guidance, tenancy, trust_share
from security_lakehouse.assessment import SnapshotWrittenHook, build_current_posture, write_assessment_snapshot
from security_lakehouse.auth.api_key_session import ApiKeySessionError, exchange_api_key_for_browser_session
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.oidc import OIDCLoginError, build_oauth, complete_oidc_login, load_oidc_config
from security_lakehouse.auth.presentation import build_auth_methods_payload
from security_lakehouse.auth.rate_limit import RateLimitConfig
from security_lakehouse.auth.rate_limit_redis import RateLimiterBackend, build_rate_limiter
from security_lakehouse.auth.rbac import Identity, scopes_for_role
from security_lakehouse.auth.request_audit import AnonymousAuditSampler, append_request_audit, should_audit_request
from security_lakehouse.auth.saml import (
    SAML_REQUEST_COOKIE,
    SAML_REQUEST_MAX_AGE_SECONDS,
    AssertionReplayCache,
    SAMLLoginError,
    build_saml_auth,
    decode_saml_request_id,
    encode_saml_request_id,
    complete_saml_login,
    email_from_saml_assertion,
    groups_from_saml_assertion,
    load_saml_config,
    saml_request_data,
)
from security_lakehouse.auth.sessions import (
    SESSION_COOKIE,
    decode_session_cookie,
    encode_session_cookie,
    ensure_cookie_signing_configured,
)
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.dashboard import render_dashboard
from security_lakehouse.data_policy import normalize_sensitivity, redact_payload
from security_lakehouse.db import agent_runs as agent_runs_db
from security_lakehouse.db import metrics as metrics_db
from security_lakehouse.db import migrate, remediation, repository
from security_lakehouse.db import tags as tags_db
from security_lakehouse.db.base import DEFAULT_PAGE_LIMIT, clamp_limit, create_engine_for, session_factory
from security_lakehouse.db.models import REMEDIATION_PRIORITIES, USER_ROLES, User
from security_lakehouse.demo_links import build_demo_kit
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.io import resolve_path
from security_lakehouse.public_url import normalize_public_url
from security_lakehouse.server_routes.schemas.base import StrictModel as _StrictModel
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import access_reviews as access_review_services
from security_lakehouse.services import grc as grc_services
from security_lakehouse.services import policy_documents as policy_document_services
from security_lakehouse.services import vendor_risk as vendor_risk_services
from security_lakehouse.services import webhooks as webhook_services
from security_lakehouse.web import web_dist_dir, web_dist_index

_COOKIE_SECURE = os.environ.get("TRUSTOPS_COOKIE_SECURE", "true").lower() in {"1", "true", "yes", "on"}

_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    429: "rate_limited",
}

# Health probes are exempt from rate limiting so a limiter trip can never hide
# liveness from an orchestrator.
_RATE_LIMIT_EXEMPT = {"/api/healthz", "/api/v1/healthz"}


class _KnownCredentials:
    """Bounded set of bearer-token digests that have authenticated successfully.

    Only these earn a per-credential rate-limit bucket; any other presented
    token is charged to the client address, so rotating unauthenticated tokens
    cannot mint fresh budgets or flood the limiter's key map.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: OrderedDict[str, None] = OrderedDict()
        self._max = max_entries
        self._lock = threading.Lock()

    def __contains__(self, digest: object) -> bool:
        with self._lock:
            return digest in self._entries

    def add(self, digest: str) -> None:
        with self._lock:
            self._entries[digest] = None
            self._entries.move_to_end(digest)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def discard(self, digest: str) -> None:
        with self._lock:
            self._entries.pop(digest, None)


def _bearer_digest(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
    return None


def _rate_limit_key(request: Request, known: _KnownCredentials) -> str:
    """Bucket key: an authenticated credential's own bucket, else the client host.

    The bearer token is hashed so raw key material never lands in the limiter's
    in-memory map. Behind a reverse proxy the client host is whatever uvicorn
    resolves from its ``--forwarded-allow-ips`` / ``FORWARDED_ALLOW_IPS`` setting.
    """
    digest = _bearer_digest(request)
    if digest is not None and digest in known:
        return "k:" + digest
    client = request.client.host if request.client else "unknown"
    return "h:" + client


async def _json_object_body(request: Request) -> dict[str, Any]:
    """Parse a mutation body: empty or undecodable is no body; valid non-object JSON is a 400."""
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(body, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="request body must be a JSON object")
    return body


_LEGACY_ERROR_REASONS = {
    HTTPStatus.BAD_REQUEST: "invalid request",
    HTTPStatus.FORBIDDEN: "forbidden",
    HTTPStatus.NOT_FOUND: "not found",
}

# Scope dependencies are built once (module-level) and reused as route defaults.
_require_read = require_scope("read")
_require_write = require_scope("write")
_require_admin = require_scope("auth_admin")
_require_evidence_request = require_scope("evidence_request")
_require_control_manage = require_scope("control_manage")
# Webhook subscriptions carry a signing secret and an outbound destination for
# compliance events, so mutating them takes the same scope as managing an
# inbound connector (admin/security_admin only) — reading the (secret-free)
# list/detail is ordinary `read`.
_require_connector_manage = require_scope("connector_manage")


class CreateKeyRequest(_StrictModel):
    user_email: str = Field(min_length=3, max_length=320)
    name: str = Field(default="", max_length=80)
    expires_in_days: int | None = Field(default=None, ge=1, le=3660)


class UpdateUserRequest(_StrictModel):
    role: str | None = None
    is_active: bool | None = None
    display_name: str | None = Field(default=None, max_length=120)


class SessionFromKeyRequest(_StrictModel):
    api_key: str = Field(min_length=8, max_length=512)


class EscalateFreshnessRequest(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    statuses: list[str] = Field(default_factory=lambda: ["stale", "expired", "missing"])


class CreateInviteRequest(_StrictModel):
    email: str
    role: str = "contributor"

    @field_validator("role")
    @classmethod
    def _known_role(cls, value: str) -> str:
        if value not in USER_ROLES:
            raise ValueError(f"role must be one of {list(USER_ROLES)}")
        return value


class AcceptInviteRequest(_StrictModel):
    token: str
    display_name: str = ""


class SignupRequest(_StrictModel):
    org_slug: str
    org_name: str
    admin_email: str
    admin_name: str = ""
    plan_tier: str = "starter"


class CreateTaskRequest(_StrictModel):
    title: str
    description: str = ""
    control_id: str | None = None
    violation_id: str | None = None
    owner: str = ""
    priority: str = "medium"
    due_at: str | None = None


class UpdateTaskRequest(_StrictModel):
    title: str | None = None
    description: str | None = None
    owner: str | None = None
    status: str | None = None
    priority: str | None = None
    due_at: str | None = None
    resolution_note: str | None = None


class CreateEvidenceRequestRequest(_StrictModel):
    control_id: str
    requested_from: str = ""
    note: str = ""
    due_at: str | None = None


class EvidenceRequestStatusRequest(_StrictModel):
    status: str


class CreateExceptionRequest(_StrictModel):
    control_id: str
    reason: str = ""
    approved_by: str = ""
    expires_at: str | None = None


class CreateRiskRequest(_StrictModel):
    title: str
    description: str = ""
    category: str = ""
    severity: str = "medium"
    likelihood: str = "medium"
    impact: str = "medium"
    status: str = "open"
    treatment: str = ""
    owner: str = ""
    control_id: str | None = None
    asset_id: str | None = None
    due_at: str | None = None


class UpdateRiskRequest(_StrictModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    severity: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    status: str | None = None
    treatment: str | None = None
    owner: str | None = None
    control_id: str | None = None
    asset_id: str | None = None
    due_at: str | None = None


class CreateWebhookRequest(_StrictModel):
    url: str = Field(min_length=1, max_length=2048)
    event_types: list[str] = Field(min_length=1)
    secret: str | None = Field(default=None, min_length=16, max_length=255)
    description: str = Field(default="", max_length=255)
    enabled: bool = True


class UpdateWebhookRequest(_StrictModel):
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    event_types: list[str] | None = Field(default=None, min_length=1)
    secret: str | None = Field(default=None, min_length=16, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None


class AdoptPolicyTemplateRequest(_StrictModel):
    template_id: str
    variables: dict[str, Any] = {}
    owner: str = ""


class UpdatePolicyDocumentRequest(_StrictModel):
    title: str | None = None
    content: str | None = None
    owner: str | None = None
    variables: dict[str, Any] | None = None
    status: str | None = None


class RecordPolicyAcknowledgmentRequest(_StrictModel):
    user_email: str | None = None
    display_name: str = ""


class CreateCampaignRequest(_StrictModel):
    name: str
    description: str = ""
    scope: str = "all"
    control_id: str | None = None
    due_at: str | None = None


class CampaignStatusRequest(_StrictModel):
    status: str


class CreateVendorAssessmentRequest(_StrictModel):
    vendor_name: str
    template_id: str
    owner: str = ""
    control_id: str | None = None
    due_at: str | None = None


class UpdateVendorAssessmentRequest(_StrictModel):
    vendor_name: str | None = None
    owner: str | None = None
    control_id: str | None = None
    due_at: str | None = None
    responses: dict[str, Any] | None = None
    status: str | None = None


class AddReviewItemRequest(_StrictModel):
    subject_id: str
    subject_name: str = ""
    source: str = ""
    access_summary: str = ""


class ReviewDecisionRequest(_StrictModel):
    decision: str
    note: str = ""


class CreateTagRequest(_StrictModel):
    name: str
    color: str = ""


class AttachTagRequest(_StrictModel):
    tag_id: str
    entity_type: str
    entity_id: str


class CreateSavedViewRequest(_StrictModel):
    surface: str
    name: str
    filters: dict = {}


class CreateAgentRunRequest(_StrictModel):
    harness: str
    objective: str = ""
    role: str | None = None
    idempotency_key: str | None = None
    orchestrator: str = "sequential"
    use_model: bool = False
    max_context_chars: int | None = None
    max_fact_items: int | None = None
    max_output_tokens: int | None = None


class RejectAgentDecisionRequest(_StrictModel):
    reason: str = Field(default="", max_length=2000)


class ApproveAgentDecisionRequest(_StrictModel):
    note: str = ""


def _snapshot_written_hook(session: Session, tenant_id: str) -> SnapshotWrittenHook:
    """Build the ``write_assessment_snapshot`` hook that dispatches webhook events.

    Captures ``session``/``tenant_id`` by closure so ``assessment.py`` itself
    never needs to know about the application-state DB or tenancy; see
    ``assessment.write_assessment_snapshot`` for why the hook fires only after
    its chain lock is released.

    ``dispatch_snapshot_events``/``dispatch_event`` never commit or roll back
    ``session`` themselves (see ``services.webhooks.dispatch_event``) -- every
    caller of this hook must commit ``session`` itself afterward (once, atomic
    with whatever else that caller's own transaction is doing) or the staged
    delivery-log rows are silently discarded when the request-scoped session
    closes.
    """

    def _hook(
        snapshot_path: Path,
        assessment: dict[str, Any],
        new_violations: list[dict[str, Any]],
        newly_failing_controls: list[str],
    ) -> None:
        webhook_services.dispatch_snapshot_events(
            session,
            tenant_id,
            snapshot_path=snapshot_path,
            assessment=assessment,
            new_violations=new_violations,
            newly_failing_controls=newly_failing_controls,
        )

    return _hook


def _parse_dt(value: str | None) -> datetime | None:
    if value is None or value == "":
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid datetime: {value!r}") from exc


def _params(request: Request) -> dict[str, list[str]]:
    """Convert Starlette's query multidict into the ``api_v1`` param shape."""
    params: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        params.setdefault(key, []).append(value)
    return params


def _pagination(params: dict[str, list[str]]) -> tuple[int, int]:
    """Read ``limit``/``offset`` query params, clamped to a safe page window.

    A missing/invalid ``limit`` defaults to ``DEFAULT_PAGE_LIMIT`` so list
    endpoints are always bounded; an oversized one is capped server-side.
    """
    limit_raw = (params.get("limit") or [None])[0]
    offset_raw = (params.get("offset") or [None])[0]
    limit = clamp_limit(int(limit_raw)) if limit_raw and limit_raw.lstrip("-").isdigit() else DEFAULT_PAGE_LIMIT
    offset = int(offset_raw) if offset_raw and offset_raw.isdigit() else 0
    return limit, max(0, offset)


def _page_meta(limit: int, offset: int, count: int) -> dict[str, int]:
    """Envelope ``meta`` fields describing the returned page."""
    return {"count": count, "limit": limit, "offset": offset}


def _insecure_requested() -> bool:
    return os.environ.get("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", "").lower() in {"1", "true", "yes"}


def _production_env_blocked() -> bool:
    env = os.environ.get("TRUSTOPS_ENV", "").strip().lower()
    return env in {"production", "prod", "staging"}


def _assert_insecure_allowed() -> None:
    if _insecure_requested() and _production_env_blocked():
        raise RuntimeError("TRUSTOPS_ALLOW_INSECURE_NO_AUTH is forbidden when TRUSTOPS_ENV is production or staging")
    if _insecure_requested():
        logging.getLogger(__name__).warning(
            "TRUSTOPS_ALLOW_INSECURE_NO_AUTH is enabled: every request runs as synthetic admin"
        )


def _redact_payload(payload: object, identity: Identity) -> object:
    return redact_payload(payload, role=identity.role)


def _role_allowed_for_actor(requested_role: str, identity: Identity) -> bool:
    """Allow same or narrower read visibility, never role escalation."""
    visibility_rank = {"auditor": 0, "read_only": 1, "contributor": 1, "security_admin": 2, "admin": 2}
    return visibility_rank.get(requested_role, 99) <= visibility_rank.get(identity.role, -1)


def _safe_agent_lake_path(root_lake: Path, tenant_lake: Path) -> Path:
    """Resolve the tenant/account lake and ensure it stays under the server root."""
    root = root_lake.resolve()
    target = tenant_lake.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant lake is outside server root") from exc
    target.mkdir(parents=True, exist_ok=True)
    if not target.is_dir():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant lake is not a directory")
    return target


def _decision_payload(decision: dict[str, Any]) -> dict[str, Any]:
    payload = decision.get("payload")
    return payload if isinstance(payload, dict) else {}


def _payload_text(payload: dict[str, Any], key: str, default: str = "") -> str:
    value = payload.get(key)
    return str(value).strip() if value is not None else default


def _decision_reason(decision: dict[str, Any], *, note: str = "") -> str:
    reason = str(decision.get("reason") or "").strip()
    extra = note.strip()
    if reason and extra:
        return f"{reason}\n\nApproval note: {extra}"
    return reason or extra or "Approved agent harness proposal."


def _decision_priority(payload: dict[str, Any], default: str = "medium") -> str:
    value = str(payload.get("priority") or payload.get("severity") or default).lower()
    return value if value in REMEDIATION_PRIORITIES else default


def _execute_agent_decision(
    session: Session,
    *,
    lake: Path,
    identity: Identity,
    decision: dict[str, Any],
    note: str = "",
) -> dict[str, Any]:
    """Execute an allowlisted agent decision through TrustOps-native writes only."""
    action = str(decision.get("action") or "")
    payload = _decision_payload(decision)
    reason = _decision_reason(decision, note=note)

    if action == "create_evidence_request":
        control_id = _payload_text(payload, "control_id")
        requested_from = _payload_text(payload, "requested_from") or _payload_text(payload, "owner")
        try:
            req = remediation.create_evidence_request(
                session,
                tenant_id=identity.tenant_id,
                control_id=control_id,
                requested_from=requested_from,
                note=reason,
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return {
            "type": "evidence_request",
            "id": req.id,
            "control_id": req.control_id,
            "status": req.status,
        }

    if action == "create_remediation_task":
        control_id: str | None = _payload_text(payload, "control_id") or None
        title = _payload_text(payload, "title") or f"Remediate {control_id or 'agent finding'}"
        try:
            task = remediation.create_task(
                session,
                tenant_id=identity.tenant_id,
                title=title,
                description=reason,
                control_id=control_id,
                violation_id=_payload_text(payload, "violation_id") or None,
                owner=_payload_text(payload, "owner"),
                priority=_decision_priority(payload),
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return {"type": "remediation_task", "id": task.id, "control_id": task.control_id, "status": task.status}

    if action == "create_soc_case":
        event_id = _payload_text(payload, "event_id") or _payload_text(payload, "alert_id") or "unknown-event"
        severity = _decision_priority(payload, default="high")
        try:
            task = remediation.create_task(
                session,
                tenant_id=identity.tenant_id,
                title=f"SOC case: {event_id}",
                description=reason,
                violation_id=event_id,
                owner=_payload_text(payload, "owner"),
                priority=severity,
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return {"type": "remediation_task", "id": task.id, "violation_id": task.violation_id, "status": task.status}

    if action == "assign_owner":
        event_id = _payload_text(payload, "event_id") or _payload_text(payload, "control_id") or "agent finding"
        owner = _payload_text(payload, "owner")
        try:
            task = remediation.create_task(
                session,
                tenant_id=identity.tenant_id,
                title=f"Assign owner: {event_id}",
                description=reason,
                control_id=_payload_text(payload, "control_id") or None,
                violation_id=_payload_text(payload, "violation_id") or _payload_text(payload, "event_id") or None,
                owner=owner,
                priority=_decision_priority(payload),
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return {"type": "remediation_task", "id": task.id, "owner": task.owner, "status": task.status}

    if action == "freeze_snapshot":
        if not identity.has_scope("snapshot"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="snapshot scope required")
        snapshot_path = write_assessment_snapshot(
            lake, reason=reason, on_snapshot_written=_snapshot_written_hook(session, identity.tenant_id)
        )
        return {"type": "snapshot", "snapshot_path": str(snapshot_path)}

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"agent decision action is not executable: {action or 'missing'}",
    )


def _public_trust_summary(lake: Path, share: dict[str, object]) -> dict[str, object]:
    """Build the redacted, read-only posture an external token holder may see.

    Starts from the full posture, applies the *same* auditor-lens redaction the
    ``auditor`` role gets (owners/notes/actor/credentials → ``[redacted]``), then
    trims to a public summary: posture score/state and per-framework readiness
    with control counts only. Raw violations, asset/evidence internals, and any
    owner fields never reach the wire — only this summary leaves the lake.

    A share at the ``public`` sensitivity ceiling (customer-facing) also drops
    violation and stale-control counts; those appear only for shares issued
    above ``public`` (auditor review). Unknown ceilings fail closed to public.
    """
    ceiling = normalize_sensitivity(share.get("sensitivity_ceiling"), default="public")
    detailed = ceiling != "public"
    posture = build_current_posture(lake)
    auditor = Identity(
        user_id="public-trust-share",
        tenant_id="public",
        email="anonymous",
        role="auditor",
        scopes=scopes_for_role("auditor"),
    )
    redacted = _redact_payload(posture, auditor)
    if not isinstance(redacted, dict):
        redacted = {}
    posture_block = redacted.get("posture")
    posture_block = posture_block if isinstance(posture_block, dict) else {}
    frameworks_raw = redacted.get("frameworks")
    frameworks: list[dict[str, object]] = []
    if isinstance(frameworks_raw, list):
        for row in frameworks_raw:
            if not isinstance(row, dict):
                continue
            framework_row: dict[str, object] = {
                "framework": row.get("framework"),
                "score": row.get("score"),
                "state": row.get("state"),
                "control_count": row.get("control_count"),
            }
            if detailed:
                framework_row["failing_control_count"] = row.get("failing_control_count")
                framework_row["stale_control_count"] = row.get("stale_control_count")
            frameworks.append(framework_row)
    posture_summary: dict[str, object] = {
        "score": posture_block.get("score"),
        "state": posture_block.get("state"),
        "framework_count": posture_block.get("framework_count"),
        "control_count": posture_block.get("control_count"),
    }
    if detailed:
        for key in (
            "open_violation_count",
            "critical_violation_count",
            "high_violation_count",
            "stale_control_count",
        ):
            posture_summary[key] = posture_block.get(key)
    return {
        "schema_version": "trustops.public_trust.v1",
        "sensitivity": "public",
        "visibility": "external_reviewer",
        "redaction_policy": "trustops.public_summary.v1",
        "data_residency": "evidence never leaves this lake; only this summary is shared",
        "issued_by": share.get("created_by"),
        "scope": share.get("scope"),
        "role": share.get("role"),
        "sensitivity_ceiling": ceiling,
        "detail_level": "detailed" if detailed else "summary",
        "expires_at": share.get("expires_at"),
        "evaluated_at": redacted.get("evaluated_at"),
        "posture": posture_summary,
        "frameworks": frameworks,
    }


def _poc_step(
    *,
    step_id: str,
    label: str,
    ready: bool,
    detail: str,
    href: str | None = None,
    blocking: bool = True,
    skipped: bool = False,
) -> dict[str, object]:
    return {
        "id": step_id,
        "label": label,
        "status": "skipped" if skipped else ("ready" if ready else "needs_setup"),
        "detail": detail,
        "href": href,
        "blocking": blocking,
    }


def _onboarding_console_href(href: str | None) -> str | None:
    """Map admin console paths to workbench routes for the guided onboarding flow."""
    if not href:
        return None
    if href == "/console/connectors":
        return "/connectors?onboarding=1"
    if href == "/console/trust-center":
        return "/trust-center?onboarding=1"
    if href == "/console/agents":
        return "/agents?onboarding=1"
    if href == "/console/login":
        return "/auth?onboarding=1"
    if href.startswith("/console/"):
        return href.removeprefix("/console")
    return href


def _build_poc_readiness(
    *,
    app: FastAPI,
    lake: Path,
    identity: Identity,
    session: Session,
) -> dict[str, object]:
    """Return the tenant's readiness to host a shareable POC."""
    now = datetime.now(UTC)
    public_url = normalize_public_url(
        os.environ.get("TRUSTOPS_PUBLIC_URL")
        or os.environ.get("TRUSTOPS_BASE_URL")
        or os.environ.get("TRUSTOPS_APP_URL")
    )
    sso_configured = app.state.oauth is not None or app.state.saml_config is not None
    login_path = (
        "/api/v1/auth/saml/login"
        if app.state.saml_config is not None and app.state.oauth is None
        else "/api/v1/auth/login"
    )
    keys = repository.list_api_keys(session, tenant_id=identity.tenant_id)
    active_keys = [key for key in keys if key.is_active(now=now)]
    role_counts = {
        str(role): int(count)
        for role, count in session.execute(
            select(User.role, func.count())
            .where(User.tenant_id == identity.tenant_id, User.is_active.is_(True))
            .group_by(User.role)
        ).all()
    }
    ingestion = build_ingestion_status(lake)
    ingestion_summary = ingestion.get("summary") or {}
    active_shares = [share for share in trust_share.list_shares(lake) if not share.get("expired")]
    enabled_connectors = int(ingestion_summary.get("enabled_connectors") or 0)
    evidence_count = int(ingestion_summary.get("evidence_count") or 0)
    failed_connectors = int(ingestion_summary.get("failed_connectors") or 0)
    silent_connectors = int(ingestion_summary.get("silent_connectors") or 0)
    source_ready = enabled_connectors > 0 and evidence_count > 0 and failed_connectors == 0 and silent_connectors == 0
    local_mode = not bool(app.state.require_auth)
    human_access_ready = not local_mode and sso_configured
    headless_access_ready = len(active_keys) > 0
    agent_run_rows = agent_runs_db.list_agent_runs(session, tenant_id=identity.tenant_id, limit=100)
    completed_agent_runs = [row for row in agent_run_rows if row.status == "completed"]
    pending_agent_decisions = sum(
        1
        for row in agent_run_rows
        for decision in agent_runs_db.agent_run_decisions(row)
        if decision.get("status") == "proposed"
    )
    latest_agent_run_at = agent_run_rows[0].created_at.isoformat() if agent_run_rows else None

    if local_mode:
        human_access_detail = "Local mode — browser sign-in is off"
    elif sso_configured:
        human_access_detail = "SSO configured"
    else:
        human_access_detail = "Configure OIDC or SAML for browser login."

    steps = [
        _poc_step(
            step_id="human_access",
            label="Human access",
            ready=human_access_ready,
            skipped=local_mode,
            detail=human_access_detail,
            href="/console/login",
        ),
        _poc_step(
            step_id="headless_access",
            label="Agent/API access",
            ready=headless_access_ready,
            detail=f"{len(active_keys)} active API key(s)" if active_keys else "Issue an API key for headless clients.",
            href="/console/auth/#api-keys",
            blocking=False,
        ),
        _poc_step(
            step_id="source_sync",
            label="Source sync",
            ready=source_ready,
            detail=(
                f"{evidence_count} evidence row(s) from {enabled_connectors} enabled source(s)"
                if source_ready
                else "Connect, test, enable, and sync at least one source."
            ),
            href="/console/connectors",
        ),
        _poc_step(
            step_id="public_url",
            label="Public URL",
            ready=bool(public_url),
            detail=public_url or "Set the public URL so invite and share links work",
            href="/console/deploy/",
        ),
        _poc_step(
            step_id="trust_share",
            label="Trust share",
            ready=bool(active_shares),
            detail=f"{len(active_shares)} active share link(s)"
            if active_shares
            else "Create a scoped trust-center share.",
            href="/console/trust-center",
        ),
        _poc_step(
            step_id="agent_review",
            label="Agent review",
            ready=bool(completed_agent_runs),
            detail=(
                f"{len(completed_agent_runs)} completed run(s), {pending_agent_decisions} pending decision(s)"
                if completed_agent_runs
                else "Run a governed review to propose approval-gated next actions."
            ),
            href="/console/agents",
            blocking=False,
        ),
    ]
    blocking_ready = all(step["status"] == "ready" for step in steps if step["blocking"])
    # Local mode still lets people on this machine in, so it counts for internal use but never for sharing.
    any_access_ready = human_access_ready or headless_access_ready or local_mode
    state = "ready" if blocking_ready else ("internal_ready" if source_ready and any_access_ready else "needs_setup")
    next_step = next(
        (step for step in steps if step["status"] == "needs_setup"),
        next((step for step in steps if step["status"] != "ready"), None),
    )
    blocking_steps = [step for step in steps if step["blocking"]]
    completed_blocking = sum(1 for step in blocking_steps if step["status"] == "ready")
    onboarding_steps = [
        {**step, "console_href": _onboarding_console_href(str(step.get("href") or "") or None)} for step in steps
    ]
    demo_kit = build_demo_kit(
        public_url=public_url,
        sso_configured=sso_configured,
        require_auth=bool(app.state.require_auth),
        ingestion=ingestion,
        active_share_count=len(active_shares),
        shareable=state == "ready",
        login_path=login_path,
    )
    return {
        "state": state,
        "shareable": state == "ready",
        "public_url": public_url,
        "demo_kit": demo_kit,
        "workspace": {
            "tenant_id": identity.tenant_id,
            "workspace_id": identity.workspace_id or identity.tenant_id,
            "current_user": identity.email,
            "current_role": identity.role,
        },
        "access": {
            "require_auth": bool(app.state.require_auth),
            "browser_sso_configured": sso_configured,
            "active_api_keys": len(active_keys),
            "users_by_role": role_counts,
        },
        "connectors": {
            "enabled": enabled_connectors,
            "failed": failed_connectors,
            "silent": silent_connectors,
            "evidence_count": evidence_count,
            "source_count": int(ingestion_summary.get("source_count") or 0),
        },
        "trust_shares": {
            "active": len(active_shares),
        },
        "agents": {
            "runs": len(agent_run_rows),
            "completed": len(completed_agent_runs),
            "pending_decisions": pending_agent_decisions,
            "latest_run_at": latest_agent_run_at,
        },
        "ingestion": {
            "state": ingestion.get("state"),
            "posture_score": ingestion_summary.get("posture_score"),
            "open_violations": ingestion_summary.get("open_violations"),
            "recommended_actions": ingestion.get("recommended_actions") or [],
        },
        "steps": steps,
        "next_step": next_step,
        "onboarding": {
            "progress_percent": int(round(100 * completed_blocking / len(blocking_steps))) if blocking_steps else 100,
            "completed_blocking": completed_blocking,
            "blocking_total": len(blocking_steps),
            "current_step_id": next_step["id"] if next_step else None,
            "steps": onboarding_steps,
        },
    }


def _legacy_error_payload(status_code: HTTPStatus) -> dict[str, str]:
    """Return generic server-mode legacy API errors.

    The legacy dispatcher is shared with local mode and may call file, workflow,
    connector, or trust-share helpers. Server mode must not echo exception text
    or handler-produced error details to authenticated clients.
    """
    if status_code == HTTPStatus.BAD_REQUEST:
        error = "bad_request"
    elif status_code == HTTPStatus.FORBIDDEN:
        error = "forbidden"
    elif status_code == HTTPStatus.NOT_FOUND:
        error = "not_found"
    else:
        error = "internal_error"
    return {"error": error, "reason": _LEGACY_ERROR_REASONS.get(status_code, "internal server error")}


def _legacy_post_response(
    path: str,
    body: dict[str, object],
    lake: Path,
    identity: Identity,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> JSONResponse:
    """Dispatch a legacy POST with a fail-closed server-mode error boundary."""
    try:
        status_code, payload = api_legacy.handle_post(
            path, body, lake, role=identity.role, on_snapshot_written=on_snapshot_written
        )
    except Exception:  # noqa: BLE001 - do not expose internal exception text at the HTTP boundary
        return JSONResponse(_legacy_error_payload(HTTPStatus.INTERNAL_SERVER_ERROR), status_code=500)
    if status_code >= HTTPStatus.BAD_REQUEST:
        return JSONResponse(_legacy_error_payload(status_code), status_code=int(status_code))
    return JSONResponse(payload, status_code=int(status_code))


async def platform_event_stream(
    lake: Path,
    request: Request,
    *,
    tenant_id: str | None = None,
    sessionmaker=None,
    interval: float = 10.0,
) -> AsyncIterator[str]:
    """SSE frames for continuous eval: posture, freshness, audit-readiness, and AI governance on change."""
    last = {"posture": "", "freshness": "", "audit_readiness": "", "ai_governance": ""}
    while not await request.is_disconnected():
        emitted = False

        _status, body = await run_in_threadpool(api_v1.handle_get, "/api/v1/posture/current", {}, lake)
        posture_payload = json.dumps(body.get("data", {}), default=str, sort_keys=True)
        if posture_payload != last["posture"]:
            last["posture"] = posture_payload
            yield f"event: posture\ndata: {posture_payload}\n\n"
            emitted = True

        from security_lakehouse.evidence_freshness import build_freshness_summary
        from security_lakehouse.evidence_freshness_workflows import load_freshness_records

        records = await run_in_threadpool(load_freshness_records, str(lake))
        freshness_payload = json.dumps(build_freshness_summary(records), default=str, sort_keys=True)
        if freshness_payload != last["freshness"]:
            last["freshness"] = freshness_payload
            yield f"event: freshness\ndata: {freshness_payload}\n\n"
            emitted = True

        if tenant_id and sessionmaker is not None:

            def _audit_readiness() -> dict[str, object]:
                from security_lakehouse.audit_readiness import build_audit_readiness

                with sessionmaker() as session:
                    return build_audit_readiness(lake=lake, session=session, tenant_id=tenant_id)

            audit_data = await run_in_threadpool(_audit_readiness)
            audit_payload = json.dumps(audit_data, default=str, sort_keys=True)
            if audit_payload != last["audit_readiness"]:
                last["audit_readiness"] = audit_payload
                yield f"event: audit-readiness\ndata: {audit_payload}\n\n"
                emitted = True

        from security_lakehouse.ai_governance import build_ai_governance_status

        ai_data = await run_in_threadpool(build_ai_governance_status, lake=lake)
        ai_payload = json.dumps(ai_data, default=str, sort_keys=True)
        if ai_payload != last["ai_governance"]:
            last["ai_governance"] = ai_payload
            yield f"event: ai-governance\ndata: {ai_payload}\n\n"
            emitted = True

        if not emitted:
            yield ": ping\n\n"
        await asyncio.sleep(interval)


async def posture_event_stream(lake: Path, request: Request, *, interval: float = 10.0) -> AsyncIterator[str]:
    """Posture-only stream kept for narrow unit tests."""
    async for frame in platform_event_stream(lake, request, interval=interval):
        if frame.startswith("event: posture") or frame.startswith(": ping"):
            yield frame


def create_app(lake_dir: str | Path, *, require_auth: bool = True) -> FastAPI:
    """Build the server-mode ASGI app bound to a security data lake directory."""
    _assert_insecure_allowed()
    lake = resolve_path(lake_dir)
    dashboard = lake / "console.html"
    render_dashboard(lake, dashboard)
    web_dist = web_dist_dir() if web_dist_index() else None

    migrate.upgrade(lake)
    engine = create_engine_for(lake)

    app = FastAPI(
        title="TrustOps API",
        version=api_v1.API_VERSION,
        description=(
            "Open-source, headless-first trust operations for customer-owned "
            "evidence lakes. The same engine serves TrustOps Console and "
            "`/api/v1` for agents, CI, and runbooks. Discover the contract at "
            "`GET /api/v1`; browse it at `/docs`."
        ),
        openapi_tags=[
            {"name": "discovery", "description": "Self-describing index + health."},
            {"name": "auth", "description": "API keys, SSO (OIDC/SAML), sessions, RBAC."},
            {"name": "assessment", "description": "Posture, controls, evidence, violations, snapshots."},
            {"name": "agents", "description": "Human/headless agent harness runs and evaluations."},
            {"name": "remediation", "description": "Tasks, evidence requests, control exceptions."},
            {"name": "gov-compliance", "description": "POA&M tracking and SPRS scoring for CMMC programs."},
            {"name": "insights", "description": "Posture time-series and remediation metrics."},
            {"name": "tags", "description": "Cross-entity tags and saved views."},
            {"name": "webhooks", "description": "Outbound event subscriptions (findings, assessments, controls)."},
        ],
    )
    app.state.sessionmaker = session_factory(engine)
    app.state.require_auth = require_auth and not _insecure_requested()
    if app.state.require_auth:
        ensure_cookie_signing_configured()
    app.state.rate_limiter = build_rate_limiter(RateLimitConfig.from_env(dict(os.environ)), dict(os.environ))
    app.state.rate_limit_known_credentials = _KnownCredentials()
    app.state.anonymous_audit_sampler = AnonymousAuditSampler()

    def lake_for(identity: Identity) -> Path:
        """Resolve the per-request lake for ``identity`` so one tenant can never
        read another tenant's compliance evidence.

        Each tenant reads ``<root>/tenants/<id>``; a flat lake at the root (the
        CLI/fixtures layout) is served only to the single tenant of a
        single-tenant deployment (or the synthetic insecure tenant). Resolved per
        request — not snapshotted at startup — so a tenant provisioned after the
        server boots still binds correctly, and a second tenant fails closed.
        """
        if app.state.require_auth:
            with app.state.sessionmaker() as session:
                tenant_ids = repository.list_tenant_ids(session)
        else:
            tenant_ids = []
        bound = tenancy.resolve_bound_tenant(lake, require_auth=app.state.require_auth, tenant_ids=tenant_ids)
        return tenancy.tenant_lake(lake, identity.tenant_id, bound_tenant=bound)

    # OIDC SSO is optional; the OAuth client + signed session middleware are only
    # wired when an identity provider is configured via the environment.
    app.state.oidc_config = load_oidc_config()
    app.state.oauth = None
    app.state.saml_config = load_saml_config()
    app.state.saml_auth_factory = build_saml_auth
    app.state.saml_replay_cache = AssertionReplayCache()
    if app.state.oidc_config is not None:
        from starlette.middleware.sessions import SessionMiddleware

        secret = os.environ.get("TRUSTOPS_SESSION_SECRET", "").strip()
        if not secret:
            raise RuntimeError("TRUSTOPS_SESSION_SECRET is required when OIDC SSO is configured")
        app.add_middleware(SessionMiddleware, secret_key=secret, same_site="lax", https_only=_COOKIE_SECURE)
        app.state.oauth = build_oauth(app.state.oidc_config)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-XSS-Protection", "0")
        if _COOKIE_SECURE:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.middleware("http")
    async def _record_request_audit(request: Request, call_next):
        correlation_id = str(uuid.uuid4())
        response = await call_next(request)
        path = request.url.path
        # Audit authorization decisions on the secured API surfaces only; health is open.
        identity = getattr(request.state, "identity", None)
        if (
            path.startswith("/api/")
            and path not in {"/api/healthz", "/api/v1/healthz"}
            and should_audit_request(
                app.state.anonymous_audit_sampler,
                identity=identity,
                method=request.method,
                status_code=response.status_code,
                client_host=request.client.host if request.client else "unknown",
            )
        ):
            # Offload the synchronous append so the audit write never blocks the
            # event loop on every authenticated request.
            await run_in_threadpool(
                append_request_audit,
                lake,
                method=request.method,
                route=path,
                status_code=response.status_code,
                decision="allow" if response.status_code < 400 else "deny",
                correlation_id=correlation_id,
                identity=identity,
            )
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    # Registered last so it wraps outermost: a throttled request is shed here
    # before it reaches the audit threadpool write or a route handler.
    @app.middleware("http")
    async def _rate_limit(request: Request, call_next):
        limiter: RateLimiterBackend = app.state.rate_limiter
        known: _KnownCredentials = app.state.rate_limit_known_credentials
        path = request.url.path
        if limiter.enabled and path.startswith("/api/") and path not in _RATE_LIMIT_EXEMPT:
            allowed, retry_after = limiter.check(_rate_limit_key(request, known))
            if not allowed:
                response = JSONResponse(
                    api_v1.error_envelope("rate_limited", "rate limit exceeded; slow down and retry"),
                    status_code=int(HTTPStatus.TOO_MANY_REQUESTS),
                )
                response.headers["Retry-After"] = str(max(1, math.ceil(retry_after)))
                return response
        response = await call_next(request)
        digest = _bearer_digest(request)
        if digest is not None:
            identity = getattr(request.state, "identity", None)
            if response.status_code == HTTPStatus.UNAUTHORIZED:
                known.discard(digest)
            elif identity is not None and getattr(identity, "api_key_id", None):
                known.add(digest)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def _error_envelope(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _ERROR_CODES.get(exc.status_code, "error")
        return JSONResponse(
            api_v1.error_envelope(code, str(exc.detail)),
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_envelope(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Body/query validation (incl. unknown fields) returns the same v1 error
        # envelope as the rest of the surface, naming each offending field, so an
        # agent gets one consistent, machine-parsable error shape.
        parts = [f"{'.'.join(str(p) for p in err.get('loc', []))}: {err.get('msg')}" for err in exc.errors()]
        detail = "; ".join(parts) or "invalid request"
        return JSONResponse(
            api_v1.error_envelope("unprocessable_entity", detail),
            status_code=422,
        )

    from security_lakehouse.server_routes.routers.gov_compliance import build_gov_compliance_router

    app.include_router(build_gov_compliance_router(lake_for=lake_for))

    from security_lakehouse.server_routes.routers.scim import build_scim_router

    app.include_router(build_scim_router())

    from security_lakehouse.server_routes.routers.billing import build_billing_router

    app.include_router(build_billing_router())

    # --- open health checks (registered before the authenticated catch-all) ---
    @app.get("/api/healthz")
    def healthz() -> dict[str, object]:
        return {"ok": True, "service": "trustops-assessment"}

    @app.get("/api/v1/healthz", tags=["discovery"])
    def v1_healthz() -> JSONResponse:
        _status, body = api_v1.handle_get("/api/v1/healthz", {}, lake)
        return JSONResponse(body, status_code=int(_status))

    # --- public trust center (UNAUTHENTICATED, token-scoped) ---
    # The consumption side of trust shares: an external reviewer holding a
    # scoped/expiring/revocable token reaches a redacted, read-only posture
    # without any internal-grade access. Registered before the authenticated
    # catch-alls so it is never shadowed, and carries NO auth dependency. A
    # miss/expired/revoked token returns a generic 404 (no detail leak). The
    # request-audit middleware records the access as anonymous public.
    @app.get("/api/public/trust/{token}", tags=["discovery"])
    def public_trust(token: str) -> JSONResponse:
        if app.state.require_auth:
            with app.state.sessionmaker() as session:
                tenant_ids = repository.list_tenant_ids(session)
        else:
            tenant_ids = []
        bound = tenancy.resolve_bound_tenant(lake, require_auth=app.state.require_auth, tenant_ids=tenant_ids)
        resolved = trust_share.resolve_share_from_root(
            lake,
            token,
            tenant_ids=tenant_ids,
            bound_tenant=bound,
        )
        if resolved is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        share, tenant_lake = resolved
        return JSONResponse(_public_trust_summary(tenant_lake, share))

    @app.get("/api/v1/connectors/aws-posture/link/template.yaml", tags=["connectors"])
    def aws_link_template() -> Response:
        from security_lakehouse.cloud_linking import aws_template_bytes

        return Response(
            content=aws_template_bytes(),
            media_type="application/x-yaml",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/api/v1/connectors/aws-posture/link/terraform.tf", tags=["connectors"])
    def aws_link_terraform_template() -> Response:
        from security_lakehouse.cloud_linking import aws_terraform_bytes

        return Response(
            content=aws_terraform_bytes(),
            media_type="text/plain; charset=utf-8",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/api/v1/connectors/gcp-posture/link/template.tf", tags=["connectors"])
    def gcp_link_template() -> Response:
        from security_lakehouse.cloud_linking import gcp_template_bytes

        return Response(
            content=gcp_template_bytes(),
            media_type="text/plain; charset=utf-8",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/api/v1/connectors/azure-posture/link/callback", tags=["connectors"])
    def azure_link_callback(
        request: Request,
        state: str = "",
        tenant: str = "",
        admin_consent: str | None = None,
    ) -> RedirectResponse:
        from security_lakehouse.cloud_linking import (
            azure_callback_redirect,
            get_cloud_link_session,
            issue_cloud_link_redirect_token,
            normalize_link_session_id,
            record_azure_consent,
        )

        session_id = normalize_link_session_id(state or "")
        if session_id is None or get_cloud_link_session(lake, session_id) is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid cloud link session")
        consented = str(admin_consent or "").lower() in {"true", "1", "yes"}
        azure_tenant = (tenant or "").strip()
        if consented and azure_tenant:
            record_azure_consent(
                lake,
                session_id=session_id,
                azure_tenant_id=azure_tenant,
                admin_consent=True,
            )
        elif session_id:
            record_azure_consent(
                lake,
                session_id=session_id,
                azure_tenant_id=azure_tenant or "unknown",
                admin_consent=False,
            )
        redirect_token = issue_cloud_link_redirect_token(lake, session_id=session_id)
        redirect_path = azure_callback_redirect(session_id=redirect_token, public_url=None)
        return RedirectResponse(
            url=redirect_path,
            status_code=status.HTTP_302_FOUND,
        )

    @app.get("/api/v1", tags=["discovery"])
    def v1_index(_identity: Identity = Depends(_require_read)) -> JSONResponse:
        # Self-describing contract so headless agents can enumerate the surface.
        return JSONResponse(
            api_v1.envelope(
                "index",
                api_v1.index_payload(),
            )
        )

    # --- continuous-eval live stream (SSE) ---
    # Pushes posture, evidence freshness, and audit-readiness updates so the
    # console audit room stays live without polling.
    @app.get("/api/v1/stream")
    async def stream(request: Request, identity: Identity = Depends(_require_read)) -> StreamingResponse:
        return StreamingResponse(
            platform_event_stream(
                lake_for(identity),
                request,
                tenant_id=identity.tenant_id,
                sessionmaker=app.state.sessionmaker,
            ),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    # --- SSO (OIDC) ---
    @app.get("/api/v1/auth/login")
    async def sso_login(request: Request):
        if app.state.oauth is None:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="OIDC SSO is not configured")
        redirect_uri = os.environ.get("TRUSTOPS_OIDC_REDIRECT_URL") or str(request.url_for("sso_callback"))
        return await app.state.oauth.oidc.authorize_redirect(request, redirect_uri)

    @app.get("/api/v1/auth/callback", name="sso_callback")
    async def sso_callback(request: Request, session: Session = Depends(get_session)):
        if app.state.oauth is None:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="OIDC SSO is not configured")
        try:
            token = await app.state.oauth.oidc.authorize_access_token(request)
        except Exception:  # noqa: BLE001 - authlib surfaces several OAuth error types
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OIDC token exchange failed") from None
        email = (token.get("userinfo") or {}).get("email", "")
        email_verified = (token.get("userinfo") or {}).get("email_verified")
        userinfo = token.get("userinfo") or {}
        from security_lakehouse.auth.idp_roles import extract_claim_values

        oidc_config = app.state.oidc_config
        claim_values = extract_claim_values(userinfo, oidc_config.role_claim) if oidc_config else []
        try:
            _user, sess_token = complete_oidc_login(
                session,
                config=oidc_config,
                email=email,
                email_verified=email_verified,
                idp_claim_values=claim_values,
            )
        except OIDCLoginError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="OIDC login rejected") from None
        session.commit()
        response = RedirectResponse(url="/console", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            SESSION_COOKIE,
            encode_session_cookie(sess_token),
            httponly=True,
            secure=_COOKIE_SECURE,
            samesite="lax",
            path="/",
        )
        return response

    @app.post("/api/v1/auth/logout")
    def sso_logout(request: Request, session: Session = Depends(get_session)) -> JSONResponse:
        cookie_raw = request.cookies.get(SESSION_COOKIE)
        if cookie_raw:
            session_token = decode_session_cookie(cookie_raw)
            if session_token:
                repository.revoke_user_session(session, session_token, now=datetime.now(UTC))
                session.commit()
        response = JSONResponse(api_v1.envelope("auth.logout", {"ok": True}))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # --- SSO (SAML) ---
    @app.get("/api/v1/auth/saml/login")
    def saml_login(request: Request):
        if app.state.saml_config is None:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="SAML SSO is not configured")
        auth = app.state.saml_auth_factory(
            app.state.saml_config,
            saml_request_data(
                scheme=request.url.scheme,
                host=request.url.netloc,
                port=request.url.port,
                path=request.url.path,
                query=dict(request.query_params),
            ),
        )
        response = RedirectResponse(url=auth.login(), status_code=status.HTTP_302_FOUND)
        # The IdP returns the user with a cross-site POST, which drops a Lax cookie.
        response.set_cookie(
            SAML_REQUEST_COOKIE,
            encode_saml_request_id(auth.get_last_request_id()),
            max_age=SAML_REQUEST_MAX_AGE_SECONDS,
            httponly=True,
            secure=True,
            samesite="none",
            path="/api/v1/auth/saml",
        )
        return response

    @app.get("/api/v1/auth/saml/metadata")
    def saml_metadata(request: Request):
        if app.state.saml_config is None:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="SAML SSO is not configured")
        auth = app.state.saml_auth_factory(
            app.state.saml_config,
            saml_request_data(
                scheme=request.url.scheme,
                host=request.url.netloc,
                port=request.url.port,
                path=request.url.path,
                query=dict(request.query_params),
            ),
        )
        metadata = auth.get_settings().get_sp_metadata()
        errors = auth.get_settings().validate_metadata(metadata)
        if errors:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="invalid SAML metadata")
        return HTMLResponse(metadata, media_type="application/xml")

    @app.post("/api/v1/auth/saml/acs")
    async def saml_acs(request: Request, session: Session = Depends(get_session)):
        if app.state.saml_config is None:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="SAML SSO is not configured")
        body = await request.body()
        auth = app.state.saml_auth_factory(
            app.state.saml_config,
            saml_request_data(
                scheme=request.url.scheme,
                host=request.url.netloc,
                port=request.url.port,
                path=request.url.path,
                query=dict(request.query_params),
                body=body,
            ),
        )
        saml_config = app.state.saml_config
        request_id = decode_saml_request_id(request.cookies.get(SAML_REQUEST_COOKIE))
        if request_id is None and not saml_config.allow_idp_initiated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="SAML response rejected")
        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        if errors or not auth.is_authenticated():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="SAML response rejected")
        # python3-saml only compares InResponseTo when the response carries one.
        if request_id is not None and auth.get_last_response_in_response_to() != request_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="SAML response rejected")
        assertion_id = auth.get_last_assertion_id()
        if not assertion_id or not app.state.saml_replay_cache.check_and_store(
            str(assertion_id), not_on_or_after=auth.get_last_assertion_not_on_or_after()
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="SAML response rejected")
        try:
            claim_values = groups_from_saml_assertion(
                auth,
                attribute_name=saml_config.role_attribute,
            )
            _user, sess_token = complete_saml_login(
                session,
                config=saml_config,
                email=email_from_saml_assertion(auth),
                idp_claim_values=claim_values,
            )
        except SAMLLoginError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="SAML login rejected") from None
        session.commit()
        response = RedirectResponse(url="/console", status_code=status.HTTP_302_FOUND)
        response.delete_cookie(SAML_REQUEST_COOKIE, path="/api/v1/auth/saml", secure=True, samesite="none")
        response.set_cookie(
            SESSION_COOKIE,
            encode_session_cookie(sess_token),
            httponly=True,
            secure=_COOKIE_SECURE,
            samesite="lax",
            path="/",
        )
        return response

    # --- auth surface ---
    @app.get("/api/v1/auth/methods")
    def auth_methods() -> JSONResponse:
        return JSONResponse(
            api_v1.envelope(
                "auth.methods",
                build_auth_methods_payload(
                    require_auth=bool(app.state.require_auth),
                    oidc_config=app.state.oidc_config,
                    saml_config=app.state.saml_config,
                ),
            )
        )

    @app.get("/api/v1/auth/whoami")
    def whoami(identity: Identity = Depends(_require_read)) -> JSONResponse:
        return JSONResponse(
            api_v1.envelope(
                "auth.whoami",
                {
                    "user_id": identity.user_id,
                    "tenant_id": identity.tenant_id,
                    "email": identity.email,
                    "role": identity.role,
                    "scopes": sorted(identity.scopes),
                },
            )
        )

    @app.get("/api/v1/auth/keys")
    def list_keys(
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        keys = repository.list_api_keys(session, tenant_id=identity.tenant_id)
        rows = [
            {
                "id": key.id,
                "name": key.name,
                "prefix": key.prefix,
                "user_email": key.user.email,
                "role": key.role,
                "created_at": key.created_at.isoformat() if key.created_at else None,
                "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "revoked": key.revoked_at is not None,
            }
            for key in keys
        ]
        return JSONResponse(api_v1.envelope("auth.keys", rows, meta={"count": len(rows)}))

    @app.post("/api/v1/auth/keys", status_code=status.HTTP_201_CREATED)
    def create_key(
        body: CreateKeyRequest,
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        user = repository.get_user_by_email(session, tenant_id=identity.tenant_id, email=body.user_email)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found in tenant")
        from security_lakehouse.commercial.limits import UsageLimitError, assert_within_limit
        from security_lakehouse.db.models import Tenant

        tenant = session.get(Tenant, identity.tenant_id)
        if tenant is not None:
            try:
                assert_within_limit(session, tenant=tenant, resource="api_keys")
            except UsageLimitError as exc:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        expires_at = None
        if body.expires_in_days is not None:
            expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)
        key, token = repository.create_api_key(
            session, tenant_id=identity.tenant_id, user_id=user.id, name=body.name, expires_at=expires_at
        )
        session.commit()
        return JSONResponse(
            api_v1.envelope(
                "auth.keys",
                {
                    "id": key.id,
                    "name": key.name,
                    "prefix": key.prefix,
                    "user_email": user.email,
                    "role": key.role,
                    "created_at": key.created_at.isoformat() if key.created_at else None,
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                    "revoked": key.revoked_at is not None,
                    "token": token,
                },
            ),
            status_code=status.HTTP_201_CREATED,
        )

    @app.delete("/api/v1/auth/keys/{key_id}")
    def revoke_key(
        key_id: str,
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        revoked = repository.revoke_api_key(session, tenant_id=identity.tenant_id, key_id=key_id, now=datetime.now(UTC))
        if not revoked:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="key not found or already revoked")
        session.commit()
        return JSONResponse(api_v1.envelope("auth.keys", {"id": key_id, "revoked": True}))

    @app.get("/api/v1/auth/users")
    def list_users(
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.auth.users_admin import list_tenant_users, user_to_dict

        rows = list_tenant_users(session, tenant_id=identity.tenant_id)
        data = [user_to_dict(row) for row in rows]
        return JSONResponse(api_v1.envelope("auth.users", data, meta={"count": len(data)}))

    @app.patch("/api/v1/auth/users/{user_id}")
    def update_user(
        user_id: str,
        body: UpdateUserRequest,
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.auth.users_admin import UserAdminError, update_tenant_user, user_to_dict

        try:
            row = update_tenant_user(
                session,
                tenant_id=identity.tenant_id,
                user_id=user_id,
                actor_user_id=identity.user_id,
                role=body.role,
                is_active=body.is_active,
                display_name=body.display_name,
            )
        except UserAdminError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("auth.users", user_to_dict(row)))

    @app.post("/api/v1/auth/session-from-key")
    def session_from_key(
        body: SessionFromKeyRequest,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Exchange a valid API key for a browser session cookie."""
        try:
            user, sess_token = exchange_api_key_for_browser_session(session, raw_token=body.api_key)
        except ApiKeySessionError as exc:
            detail = str(exc)
            code = status.HTTP_403_FORBIDDEN if detail == "user is disabled" else status.HTTP_401_UNAUTHORIZED
            raise HTTPException(status_code=code, detail=detail) from exc
        session.commit()
        response = JSONResponse(
            api_v1.envelope(
                "auth.session",
                {
                    "user_id": user.id,
                    "tenant_id": user.tenant_id,
                    "email": user.email,
                    "role": user.role,
                    "scopes": sorted(scopes_for_role(user.role)),
                },
            )
        )
        response.set_cookie(
            SESSION_COOKIE,
            encode_session_cookie(sess_token),
            httponly=True,
            secure=_COOKIE_SECURE,
            samesite="lax",
            path="/",
        )
        return response

    # --- commercial hosted: pricing, signup, invites, usage, SCIM ---
    @app.get("/api/v1/platform/pricing", tags=["commercial"])
    def platform_pricing() -> JSONResponse:
        from security_lakehouse.commercial import pricing as pricing_services

        return JSONResponse(api_v1.envelope("platform.pricing", pricing_services.pricing_payload()))

    @app.post("/api/v1/signup", status_code=status.HTTP_201_CREATED, tags=["commercial"])
    def self_serve_signup(
        request: Request,
        body: SignupRequest,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.commercial import signup as signup_services

        if not signup_services.self_serve_signup_enabled():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="self-serve signup requires TRUSTOPS_COMMERCIAL_HOSTED=1 and TRUSTOPS_SELF_SERVE_SIGNUP=1",
            )
        secret = request.headers.get("X-TrustOps-Signup-Secret")
        if not signup_services.verify_signup_secret(secret):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid signup secret")
        try:
            data = signup_services.create_workspace(
                session,
                org_slug=body.org_slug,
                org_name=body.org_name,
                admin_email=body.admin_email,
                admin_name=body.admin_name,
                plan_tier=body.plan_tier,
            )
        except ValueError as exc:
            detail = str(exc)
            if "TRUSTOPS_" in detail or "self-serve signup requires" in detail:
                raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=detail) from exc
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("signup", data), status_code=status.HTTP_201_CREATED)

    @app.get("/api/v1/platform/usage", tags=["commercial"])
    def platform_usage(
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.commercial import limits as limit_services
        from security_lakehouse.commercial.email import commercial_hosted_enabled
        from security_lakehouse.db.models import Tenant

        if not commercial_hosted_enabled():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="plan usage requires commercial hosting"
            )
        tenant = session.get(Tenant, identity.tenant_id)
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
        return JSONResponse(api_v1.envelope("platform.usage", limit_services.usage_summary(session, tenant=tenant)))

    @app.get("/api/v1/invites", tags=["commercial"])
    def list_invites_route(
        request: Request,
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.commercial import invites as invite_services

        params = _params(request)
        limit_raw = (params.get("limit") or ["100"])[0]
        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 100
        rows = invite_services.list_invites(session, tenant_id=identity.tenant_id, limit=limit)
        data = [invite_services.invite_to_dict(row) for row in rows]
        return JSONResponse(api_v1.envelope("invites", data, meta={"count": len(data)}))

    @app.post("/api/v1/invites", status_code=status.HTTP_201_CREATED, tags=["commercial"])
    def create_invite_route(
        body: CreateInviteRequest,
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.commercial import invites as invite_services
        from security_lakehouse.commercial.limits import UsageLimitError

        try:
            row, _token = invite_services.create_invite(
                session,
                tenant_id=identity.tenant_id,
                email=body.email,
                role=body.role,
                invited_by=identity.email,
            )
        except UsageLimitError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            detail = str(exc)
            code = (
                status.HTTP_501_NOT_IMPLEMENTED
                if "TRUSTOPS_COMMERCIAL_HOSTED" in detail
                else status.HTTP_400_BAD_REQUEST
            )
            raise HTTPException(status_code=code, detail=detail) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("invites", invite_services.invite_to_dict(row)),
            status_code=status.HTTP_201_CREATED,
        )

    @app.post("/api/v1/invites/accept", tags=["commercial"])
    def accept_invite_route(body: AcceptInviteRequest, session: Session = Depends(get_session)) -> JSONResponse:
        from security_lakehouse.commercial import invites as invite_services
        from security_lakehouse.commercial.limits import UsageLimitError

        try:
            data = invite_services.accept_invite(session, token=body.token, display_name=body.display_name)
        except UsageLimitError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except invite_services.InviteConflictError as exc:
            session.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except invite_services.InviteExpiredError as exc:
            session.commit()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except ValueError as exc:
            detail = str(exc)
            if "TRUSTOPS_COMMERCIAL_HOSTED" in detail:
                raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=detail) from exc
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("invites.accept", data))

    @app.get("/api/v1/platform/scim", tags=["commercial"])
    def scim_platform_config(identity: Identity = Depends(_require_admin)) -> JSONResponse:
        from security_lakehouse.commercial import scim as scim_services

        return JSONResponse(api_v1.envelope("platform.scim", scim_services.scim_config()))

    @app.get("/api/v1/evidence/freshness/summary", tags=["platform"])
    def evidence_freshness_summary(
        identity: Identity = Depends(_require_read),
    ) -> JSONResponse:
        from security_lakehouse.evidence_freshness import build_freshness_summary
        from security_lakehouse.evidence_freshness_workflows import load_freshness_records

        records = load_freshness_records(str(lake_for(identity)))
        data = build_freshness_summary(records)
        return JSONResponse(api_v1.envelope("evidence.freshness.summary", data))

    @app.post("/api/v1/evidence/freshness/escalate", tags=["platform"])
    def evidence_freshness_escalate(
        body: EscalateFreshnessRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.evidence_freshness_workflows import escalate_stale_evidence

        data = escalate_stale_evidence(
            session,
            tenant_id=identity.tenant_id,
            lake_dir=str(lake_for(identity)),
            actor_email=identity.email,
            statuses=set(body.statuses),
            limit=body.limit,
        )
        session.commit()
        return JSONResponse(api_v1.envelope("evidence.freshness.escalate", data))

    @app.post("/api/v1/evidence/freshness/request", tags=["platform"])
    def evidence_freshness_request(
        body: EscalateFreshnessRequest,
        identity: Identity = Depends(_require_evidence_request),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.evidence_freshness_workflows import request_stale_evidence

        data = request_stale_evidence(
            session,
            tenant_id=identity.tenant_id,
            lake_dir=str(lake_for(identity)),
            actor_email=identity.email,
            statuses=set(body.statuses),
            limit=body.limit,
        )
        session.commit()
        return JSONResponse(api_v1.envelope("evidence.freshness.request", data))

    @app.get("/api/v1/platform/audit-readiness", tags=["platform"])
    def audit_readiness_route(
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.audit_readiness import build_audit_readiness

        data = build_audit_readiness(
            lake=lake_for(identity),
            session=session,
            tenant_id=identity.tenant_id,
        )
        return JSONResponse(api_v1.envelope("platform.audit-readiness", data))

    @app.get("/api/v1/platform/jobs", tags=["platform"])
    def platform_jobs_route(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.platform_jobs import build_platform_jobs

        params = _params(request)
        limit_raw = (params.get("limit") or ["50"])[0]
        kind = (params.get("kind") or [None])[0]
        status = (params.get("status") or [None])[0]
        try:
            limit = max(1, min(int(limit_raw or 50), 500))
        except ValueError:
            limit = 50
        agent_rows = agent_runs_db.list_agent_runs(session, tenant_id=identity.tenant_id, limit=limit)
        data = build_platform_jobs(
            str(lake_for(identity)),
            agent_runs=[agent_runs_db.agent_run_to_dict(row) for row in agent_rows],
            limit=limit,
            kind=kind,
            status=status,
        )
        return JSONResponse(api_v1.envelope("platform.jobs", data))

    @app.get("/api/v1/platform/ai-governance", tags=["platform"])
    def ai_governance_route(identity: Identity = Depends(_require_read)) -> JSONResponse:
        from security_lakehouse.ai_governance import build_ai_governance_status

        data = build_ai_governance_status(lake=lake_for(identity))
        return JSONResponse(api_v1.envelope("platform.ai-governance", data))

    @app.get("/api/v1/platform/ai-governance/inventory", tags=["platform"])
    def ai_governance_inventory_route(
        request: Request,
        identity: Identity = Depends(_require_read),
    ) -> JSONResponse:
        from security_lakehouse.ai_governance import list_ai_inventory

        params = _params(request)
        limit, offset = _pagination(params)
        rows = list_ai_inventory(lake=lake_for(identity), limit=limit, offset=offset)
        return JSONResponse(
            api_v1.envelope(
                "platform.ai-governance.inventory",
                rows,
                meta=_page_meta(limit, offset, len(rows)),
            )
        )

    @app.get("/api/v1/audit-log", tags=["platform"])
    def audit_log_v1(
        request: Request,
        identity: Identity = Depends(_require_read),
    ) -> JSONResponse:
        from security_lakehouse.audit_log import build_audit_log

        params = _params(request)
        limit_raw = (params.get("limit") or ["200"])[0]
        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 200
        include_requests = (params.get("include_requests") or ["false"])[0].lower() in {"1", "true", "yes"}
        category = (params.get("category") or [""])[0] or None
        actor = (params.get("actor") or [""])[0] or None
        entries = build_audit_log(
            lake_for(identity),
            category=category,
            actor=actor,
            limit=max(1, min(limit, 1000)),
            include_requests=include_requests,
        )
        return JSONResponse(
            api_v1.envelope(
                "audit-log",
                # The audit log replays other surfaces' payloads verbatim, so it
                # inherits their sensitivity without inheriting their redaction.
                # `credentials`, `actor`, `assignee`, and `note` are all in
                # AUDITOR_REDACTED_FIELDS; without this an auditor reads here what
                # every other route withholds.
                _redact_payload(entries, identity),
                meta={"count": len(entries), "limit": limit},
            )
        )

    @app.get("/api/v1/platform/poc-readiness")
    def poc_readiness(
        identity: Identity = Depends(_require_admin),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        data = _build_poc_readiness(app=app, lake=lake_for(identity), identity=identity, session=session)
        return JSONResponse(api_v1.envelope("platform.poc-readiness", data))

    # --- agent harness runs ---
    @app.get("/api/v1/agent-runs", tags=["agents"])
    def list_agent_runs(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit_raw = (params.get("limit") or ["100"])[0]
        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 100
        harness_filter = (params.get("harness") or [""])[0] or None
        status_filter = (params.get("status") or [""])[0] or None
        rows = agent_runs_db.list_agent_runs(
            session,
            tenant_id=identity.tenant_id,
            harness=harness_filter,
            status=status_filter,
            limit=limit,
        )
        data = [agent_runs_db.agent_run_to_dict(row) for row in rows]
        return JSONResponse(api_v1.envelope("agent-runs", _redact_payload(data, identity), meta={"count": len(data)}))

    @app.post("/api/v1/agent-runs", status_code=status.HTTP_201_CREATED, tags=["agents"])
    def create_agent_run(
        body: CreateAgentRunRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        from security_lakehouse.agents import AgentBudgetPolicy
        from security_lakehouse.agents.providers import ModelProviderConfig, provider_from_env

        role = body.role or identity.role
        if not _role_allowed_for_actor(role, identity):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="requested agent role exceeds caller")
        provider_base = provider_from_env()
        provider = ModelProviderConfig(
            provider=provider_base.provider,
            model=provider_base.model,
            base_url=provider_base.base_url,
            api_key_env=provider_base.api_key_env,
            use_model=bool(body.use_model and provider_base.enabled),
            timeout_seconds=provider_base.timeout_seconds,
        )
        budget_base = AgentBudgetPolicy.from_env()
        budget = AgentBudgetPolicy(
            max_context_chars=body.max_context_chars
            if body.max_context_chars is not None
            else budget_base.max_context_chars,
            max_fact_items=body.max_fact_items if body.max_fact_items is not None else budget_base.max_fact_items,
            max_output_tokens=body.max_output_tokens
            if body.max_output_tokens is not None
            else budget_base.max_output_tokens,
            max_string_chars=budget_base.max_string_chars,
        )
        try:
            row, created = agent_runs_db.run_and_persist_agent(
                session,
                tenant_id=identity.tenant_id,
                lake_dir=_safe_agent_lake_path(lake, lake_for(identity)),
                harness=body.harness,
                objective=body.objective or f"Run {body.harness} harness.",
                role=role,
                created_by=identity.email,
                idempotency_key=body.idempotency_key,
                provider=provider,
                budget=budget,
                orchestrator=body.orchestrator,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        response_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return JSONResponse(
            api_v1.envelope(
                "agent-runs",
                _redact_payload(agent_runs_db.agent_run_to_dict(row, include_state=True), identity),
                meta={"created": created},
            ),
            status_code=response_status,
        )

    @app.get("/api/v1/agent-runs/{run_id}", tags=["agents"])
    def get_agent_run(
        run_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        row = agent_runs_db.get_agent_run(session, tenant_id=identity.tenant_id, run_id=run_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent run not found")
        return JSONResponse(
            api_v1.envelope(
                "agent-runs", _redact_payload(agent_runs_db.agent_run_to_dict(row, include_state=True), identity)
            )
        )

    @app.post("/api/v1/agent-runs/{run_id}/decisions/{decision_index}/approve", tags=["agents"])
    def approve_agent_decision(
        run_id: str,
        decision_index: int,
        body: ApproveAgentDecisionRequest | None = None,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        row = agent_runs_db.get_agent_run(session, tenant_id=identity.tenant_id, run_id=run_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent run not found")
        if row.status != "completed":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent run is not executable")
        decisions = agent_runs_db.agent_run_decisions(row)
        if decision_index < 0 or decision_index >= len(decisions):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent decision not found")
        decision = decisions[decision_index]
        if decision.get("status") == "rejected":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="agent decision was rejected")
        existing_result = decision.get("execution_result")
        if decision.get("status") == "executed" and isinstance(existing_result, dict):
            return JSONResponse(
                api_v1.envelope(
                    "agent-runs.decisions",
                    _redact_payload(agent_runs_db.agent_run_to_dict(row, include_state=True), identity),
                    meta={"executed": False, "decision_index": decision_index, "execution_result": existing_result},
                )
            )

        result = _execute_agent_decision(
            session,
            lake=_safe_agent_lake_path(lake, lake_for(identity)),
            identity=identity,
            decision=decision,
            note=body.note if body is not None else "",
        )
        agent_runs_db.mark_decision_executed(
            row,
            decision_index=decision_index,
            approved_by=identity.email,
            execution_result=result,
        )
        session.commit()
        return JSONResponse(
            api_v1.envelope(
                "agent-runs.decisions",
                _redact_payload(agent_runs_db.agent_run_to_dict(row, include_state=True), identity),
                meta={"executed": True, "decision_index": decision_index, "execution_result": result},
            )
        )

    @app.post("/api/v1/agent-runs/{run_id}/decisions/{decision_index}/reject", tags=["agents"])
    def reject_agent_decision(
        run_id: str,
        decision_index: int,
        body: RejectAgentDecisionRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        reason = body.reason.strip()
        if not reason:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="a rejection reason is required")
        row = agent_runs_db.get_agent_run(session, tenant_id=identity.tenant_id, run_id=run_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent run not found")
        decisions = agent_runs_db.agent_run_decisions(row)
        if decision_index < 0 or decision_index >= len(decisions):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent decision not found")
        current = decisions[decision_index].get("status")
        if current == "executed":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="agent decision was already executed")
        if current != "rejected":
            agent_runs_db.mark_decision_rejected(
                row, decision_index=decision_index, rejected_by=identity.email, reason=reason
            )
            session.commit()
        return JSONResponse(
            api_v1.envelope(
                "agent-runs.decisions",
                _redact_payload(agent_runs_db.agent_run_to_dict(row, include_state=True), identity),
                meta={"rejected": current != "rejected", "decision_index": decision_index},
            )
        )

    # --- remediation workflow (tasks, evidence requests, exceptions) ---
    @app.get("/api/v1/remediation/tasks")
    def list_tasks(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        overdue_raw = (params.get("overdue") or [None])[0]
        overdue = None if overdue_raw is None else overdue_raw.lower() in {"1", "true", "yes"}
        rows = grc_services.list_tasks(
            session,
            identity.tenant_id,
            status=(params.get("status") or [None])[0],
            owner=(params.get("owner") or [None])[0],
            control_id=next(iter(params.get("control_id") or []), None),
            overdue=overdue,
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope(
                "remediation.tasks", _redact_payload(rows, identity), meta=_page_meta(limit, offset, len(rows))
            )
        )

    @app.post("/api/v1/remediation/tasks", status_code=status.HTTP_201_CREATED)
    def create_task(
        body: CreateTaskRequest, identity: Identity = Depends(_require_write), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            task = grc_services.create_task(
                session,
                identity.tenant_id,
                title=body.title,
                description=body.description,
                control_id=body.control_id,
                violation_id=body.violation_id,
                owner=body.owner,
                priority=body.priority,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("remediation.tasks", task), status_code=status.HTTP_201_CREATED)

    @app.get("/api/v1/remediation/tasks/{task_id}")
    def get_task(
        task_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        task = remediation.get_task(session, tenant_id=identity.tenant_id, task_id=task_id)
        if task is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
        return JSONResponse(
            api_v1.envelope("remediation.tasks", _redact_payload(remediation.task_to_dict(task), identity))
        )

    @app.patch("/api/v1/remediation/tasks/{task_id}")
    def update_task(
        task_id: str,
        body: UpdateTaskRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        if "due_at" in changes:
            changes["due_at"] = _parse_dt(changes["due_at"])
        try:
            task = grc_services.update_task(session, identity.tenant_id, task_id, changes=changes)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("remediation.tasks", task))

    @app.get("/api/v1/remediation/evidence-requests")
    def list_evidence_requests(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        rows = remediation.list_evidence_requests(
            session,
            tenant_id=identity.tenant_id,
            status=(params.get("status") or [None])[0],
            limit=limit,
            offset=offset,
        )
        data = [remediation.evidence_request_to_dict(row) for row in rows]
        return JSONResponse(
            api_v1.envelope(
                "remediation.evidence_requests",
                _redact_payload(data, identity),
                meta=_page_meta(limit, offset, len(data)),
            )
        )

    @app.post("/api/v1/remediation/evidence-requests", status_code=status.HTTP_201_CREATED)
    def create_evidence_request(
        body: CreateEvidenceRequestRequest,
        identity: Identity = Depends(_require_evidence_request),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            req = remediation.create_evidence_request(
                session,
                tenant_id=identity.tenant_id,
                control_id=body.control_id,
                requested_from=body.requested_from,
                note=body.note,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("remediation.evidence_requests", remediation.evidence_request_to_dict(req)),
            status_code=status.HTTP_201_CREATED,
        )

    @app.patch("/api/v1/remediation/evidence-requests/{request_id}")
    def update_evidence_request(
        request_id: str,
        body: EvidenceRequestStatusRequest,
        identity: Identity = Depends(_require_evidence_request),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            req = remediation.set_evidence_request_status(
                session, tenant_id=identity.tenant_id, request_id=request_id, status=body.status
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence request not found")
        session.commit()
        return JSONResponse(api_v1.envelope("remediation.evidence_requests", remediation.evidence_request_to_dict(req)))

    @app.get("/api/v1/remediation/exceptions")
    def list_exceptions(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        active_raw = (params.get("active") or [None])[0]
        rows = remediation.list_exceptions(
            session,
            tenant_id=identity.tenant_id,
            active_only=bool(active_raw and active_raw.lower() in {"1", "true", "yes"}),
            limit=limit,
            offset=offset,
        )
        data = [remediation.exception_to_dict(row) for row in rows]
        return JSONResponse(
            api_v1.envelope(
                "remediation.exceptions", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @app.post("/api/v1/remediation/exceptions", status_code=status.HTTP_201_CREATED)
    def create_exception(
        body: CreateExceptionRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            exc_row = remediation.create_exception(
                session,
                tenant_id=identity.tenant_id,
                control_id=body.control_id,
                reason=body.reason,
                approved_by=body.approved_by or identity.email,
                expires_at=_parse_dt(body.expires_at),
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("remediation.exceptions", remediation.exception_to_dict(exc_row)),
            status_code=status.HTTP_201_CREATED,
        )

    @app.delete("/api/v1/remediation/exceptions/{exception_id}")
    def revoke_exception(
        exception_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        revoked = remediation.revoke_exception(session, tenant_id=identity.tenant_id, exception_id=exception_id)
        if revoked is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="exception not found or not active")
        session.commit()
        return JSONResponse(api_v1.envelope("remediation.exceptions", remediation.exception_to_dict(revoked)))

    # --- risk register (GRC) ---
    @app.get("/api/v1/risks")
    def list_risks(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = grc_services.list_risks(
            session,
            identity.tenant_id,
            status=(params.get("status") or [None])[0],
            severity=(params.get("severity") or [None])[0],
            owner=(params.get("owner") or [None])[0],
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope("risks", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @app.post("/api/v1/risks", status_code=status.HTTP_201_CREATED)
    def create_risk(
        body: CreateRiskRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            risk = grc_services.create_risk(
                session,
                identity.tenant_id,
                title=body.title,
                description=body.description,
                category=body.category,
                severity=body.severity,
                likelihood=body.likelihood,
                impact=body.impact,
                status=body.status,
                treatment=body.treatment,
                owner=body.owner,
                control_id=body.control_id,
                asset_id=body.asset_id,
                due_at=_parse_dt(body.due_at),
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("risks", risk), status_code=status.HTTP_201_CREATED)

    @app.patch("/api/v1/risks/{risk_id}")
    def update_risk(
        risk_id: str,
        body: UpdateRiskRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        if "due_at" in changes:
            changes["due_at"] = _parse_dt(changes["due_at"])
        try:
            risk = grc_services.update_risk(session, identity.tenant_id, risk_id, changes=changes)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("risks", risk))

    @app.delete("/api/v1/risks/{risk_id}")
    def delete_risk(
        risk_id: str,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            result = grc_services.delete_risk(session, identity.tenant_id, risk_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("risks", result))

    # --- webhook subscriptions (outbound event push) ---
    @app.get("/api/v1/webhooks", tags=["webhooks"])
    def list_webhooks(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        enabled_raw = (params.get("enabled") or [None])[0]
        enabled = {"true": True, "false": False}.get((enabled_raw or "").lower())
        data = webhook_services.list_subscriptions(
            session,
            identity.tenant_id,
            enabled=enabled,
            event_type=(params.get("event_type") or [None])[0],
            limit=limit,
            offset=offset,
        )
        return JSONResponse(api_v1.envelope("webhooks", data, meta=_page_meta(limit, offset, len(data))))

    @app.post("/api/v1/webhooks", status_code=status.HTTP_201_CREATED, tags=["webhooks"])
    def create_webhook(
        body: CreateWebhookRequest,
        identity: Identity = Depends(_require_connector_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        secret = body.secret or secrets.token_urlsafe(32)
        try:
            subscription = webhook_services.create_subscription(
                session,
                identity.tenant_id,
                url=body.url,
                secret=secret,
                event_types=body.event_types,
                description=body.description,
                enabled=body.enabled,
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        # The secret is included here, in full, exactly once -- the caller must
        # store it now; every later read of this subscription omits it.
        return JSONResponse(api_v1.envelope("webhooks", subscription), status_code=status.HTTP_201_CREATED)

    @app.get("/api/v1/webhooks/{subscription_id}", tags=["webhooks"])
    def get_webhook(
        subscription_id: str,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            data = webhook_services.get_subscription(session, identity.tenant_id, subscription_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("webhooks", data))

    @app.patch("/api/v1/webhooks/{subscription_id}", tags=["webhooks"])
    def update_webhook(
        subscription_id: str,
        body: UpdateWebhookRequest,
        identity: Identity = Depends(_require_connector_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        try:
            data = webhook_services.update_subscription(session, identity.tenant_id, subscription_id, changes=changes)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("webhooks", data))

    @app.delete("/api/v1/webhooks/{subscription_id}", tags=["webhooks"])
    def delete_webhook(
        subscription_id: str,
        identity: Identity = Depends(_require_connector_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            result = webhook_services.delete_subscription(session, identity.tenant_id, subscription_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("webhooks", result))

    @app.get("/api/v1/webhooks/{subscription_id}/deliveries", tags=["webhooks"])
    def list_webhook_deliveries(
        subscription_id: str,
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            webhook_services.get_subscription(session, identity.tenant_id, subscription_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        limit, offset = _pagination(_params(request))
        data = webhook_services.list_deliveries(
            session, identity.tenant_id, subscription_id=subscription_id, limit=limit, offset=offset
        )
        return JSONResponse(api_v1.envelope("webhooks.deliveries", data, meta=_page_meta(limit, offset, len(data))))

    # --- policy templates + documents (GRC) ---
    @app.get("/api/v1/policy-templates")
    def list_policy_templates(identity: Identity = Depends(_require_read)) -> JSONResponse:
        data = policy_document_services.list_templates()
        return JSONResponse(
            api_v1.envelope("policy-templates", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @app.get("/api/v1/policy-templates/{template_id}")
    def get_policy_template(template_id: str, identity: Identity = Depends(_require_read)) -> JSONResponse:
        try:
            data = policy_document_services.get_template(template_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policy-templates", _redact_payload(data, identity)))

    @app.get("/api/v1/policies/coverage")
    def policy_coverage(
        identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        data = policy_document_services.control_coverage(session, identity.tenant_id)
        return JSONResponse(
            api_v1.envelope("policies.coverage", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @app.get("/api/v1/policies/attestation-summary")
    def policy_attestation_summary(
        identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        data = policy_document_services.attestation_summary(session, identity.tenant_id)
        return JSONResponse(api_v1.envelope("policies.attestation", _redact_payload(data, identity)))

    @app.get("/api/v1/policies")
    def list_policies(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = policy_document_services.list_documents(
            session,
            identity.tenant_id,
            status=params.get("status"),
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope("policies", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @app.post("/api/v1/policies", status_code=status.HTTP_201_CREATED)
    def adopt_policy(
        body: AdoptPolicyTemplateRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            document = policy_document_services.adopt_template(
                session,
                identity.tenant_id,
                template_id=body.template_id,
                variables=body.variables,
                owner=body.owner,
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", document), status_code=status.HTTP_201_CREATED)

    @app.get("/api/v1/policies/{document_id}")
    def get_policy(
        document_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = policy_document_services.get_document(session, identity.tenant_id, document_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", _redact_payload(data, identity)))

    @app.patch("/api/v1/policies/{document_id}")
    def update_policy(
        document_id: str,
        body: UpdatePolicyDocumentRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            document = policy_document_services.update_document(
                session,
                identity.tenant_id,
                document_id,
                changes=body.model_dump(exclude_unset=True),
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", document))

    @app.post("/api/v1/policies/{document_id}/publish")
    def publish_policy(
        document_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            document = policy_document_services.publish_document(session, identity.tenant_id, document_id)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", document))

    @app.get("/api/v1/policies/{document_id}/acknowledgments")
    def list_policy_acknowledgments(
        document_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = policy_document_services.list_acknowledgments(session, identity.tenant_id, document_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(
            api_v1.envelope("policies.acknowledgments", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @app.post("/api/v1/policies/{document_id}/acknowledgments", status_code=status.HTTP_201_CREATED)
    def record_policy_acknowledgment(
        document_id: str,
        body: RecordPolicyAcknowledgmentRequest,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        target_email = (body.user_email or identity.email or "").strip()
        if (
            body.user_email
            and identity.role not in {"admin", "security_admin"}
            and target_email.lower() != (identity.email or "").lower()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="only admins may record acknowledgments for other users",
            )
        try:
            row = policy_document_services.record_acknowledgment(
                session,
                identity.tenant_id,
                document_id,
                user_email=target_email,
                display_name=body.display_name,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies.acknowledgments", row), status_code=status.HTTP_201_CREATED)

    # --- access reviews (GRC) ---
    @app.get("/api/v1/access-reviews")
    def list_access_reviews(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = access_review_services.list_campaigns(
            session,
            identity.tenant_id,
            status=(params.get("status") or [None])[0],
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope(
                "access-reviews", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @app.post("/api/v1/access-reviews", status_code=status.HTTP_201_CREATED)
    def create_access_review(
        body: CreateCampaignRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            campaign = access_review_services.create_campaign(
                session,
                identity.tenant_id,
                name=body.name,
                description=body.description,
                scope=body.scope,
                control_id=body.control_id,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", campaign), status_code=status.HTTP_201_CREATED)

    # Registered before the ``/{campaign_id}`` route so the static segment wins.
    @app.get("/api/v1/access-reviews/coverage")
    def access_review_coverage(
        identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        data = access_review_services.control_coverage(session, identity.tenant_id)
        return JSONResponse(
            api_v1.envelope("access-reviews.coverage", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @app.get("/api/v1/access-reviews/{campaign_id}")
    def get_access_review(
        campaign_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = access_review_services.get_campaign(session, identity.tenant_id, campaign_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", _redact_payload(data, identity)))

    @app.patch("/api/v1/access-reviews/{campaign_id}")
    def update_access_review_status(
        campaign_id: str,
        body: CampaignStatusRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            campaign = access_review_services.set_campaign_status(
                session, identity.tenant_id, campaign_id, status=body.status
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", campaign))

    @app.get("/api/v1/access-reviews/{campaign_id}/items")
    def list_access_review_items(
        campaign_id: str,
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        try:
            data = access_review_services.list_items(
                session,
                identity.tenant_id,
                campaign_id,
                decision=(params.get("decision") or [None])[0],
                limit=limit,
                offset=offset,
            )
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(
            api_v1.envelope(
                "access-reviews.items", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @app.post("/api/v1/access-reviews/{campaign_id}/items", status_code=status.HTTP_201_CREATED)
    def add_access_review_item(
        campaign_id: str,
        body: AddReviewItemRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            item = access_review_services.add_item(
                session,
                identity.tenant_id,
                campaign_id,
                subject_id=body.subject_id,
                subject_name=body.subject_name,
                source=body.source,
                access_summary=body.access_summary,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews.items", item), status_code=status.HTTP_201_CREATED)

    @app.post("/api/v1/access-reviews/{campaign_id}/seed")
    def seed_access_review(
        campaign_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            result = access_review_services.seed_campaign_from_evidence(
                session, lake_for(identity), identity.tenant_id, campaign_id
            )
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", result))

    @app.post("/api/v1/access-reviews/items/{item_id}/decision")
    def decide_access_review_item(
        item_id: str,
        body: ReviewDecisionRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            item = access_review_services.record_decision(
                session,
                identity.tenant_id,
                item_id,
                decision=body.decision,
                reviewer=identity.email,
                note=body.note,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews.items", _redact_payload(item, identity)))

    # --- vendor risk questionnaires (GRC) ---
    @app.get("/api/v1/vendor-questionnaires")
    def list_vendor_questionnaires(identity: Identity = Depends(_require_read)) -> JSONResponse:
        data = vendor_risk_services.list_templates()
        return JSONResponse(
            api_v1.envelope("vendor-questionnaires", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @app.get("/api/v1/vendor-questionnaires/{template_id}")
    def get_vendor_questionnaire(template_id: str, identity: Identity = Depends(_require_read)) -> JSONResponse:
        try:
            data = vendor_risk_services.get_template(template_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-questionnaires", _redact_payload(data, identity)))

    @app.get("/api/v1/vendor-assessments")
    def list_vendor_assessments(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = vendor_risk_services.list_assessments(
            session,
            identity.tenant_id,
            status=params.get("status"),
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope(
                "vendor-assessments", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @app.post("/api/v1/vendor-assessments", status_code=status.HTTP_201_CREATED)
    def create_vendor_assessment(
        body: CreateVendorAssessmentRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            assessment = vendor_risk_services.create_assessment(
                session,
                identity.tenant_id,
                vendor_name=body.vendor_name,
                template_id=body.template_id,
                owner=body.owner,
                control_id=body.control_id,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", assessment), status_code=status.HTTP_201_CREATED)

    @app.get("/api/v1/vendor-assessments/{assessment_id}")
    def get_vendor_assessment(
        assessment_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = vendor_risk_services.get_assessment(session, identity.tenant_id, assessment_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", _redact_payload(data, identity)))

    @app.patch("/api/v1/vendor-assessments/{assessment_id}")
    def update_vendor_assessment(
        assessment_id: str,
        body: UpdateVendorAssessmentRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        if "due_at" in changes:
            changes["due_at"] = _parse_dt(changes["due_at"])
        try:
            assessment = vendor_risk_services.update_assessment(
                session, identity.tenant_id, assessment_id, changes=changes
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", assessment))

    @app.post("/api/v1/vendor-assessments/{assessment_id}/submit")
    def submit_vendor_assessment(
        assessment_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            assessment = vendor_risk_services.submit_assessment(session, identity.tenant_id, assessment_id)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", assessment))

    # --- remediation guidance ---
    @app.get("/api/v1/controls/{control_id}/remediation")
    def control_remediation(
        control_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        control = load_control_catalog().get(control_id)
        if control is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control not found")
        data = remediation_guidance.guidance_for_control(control)
        return JSONResponse(api_v1.envelope("controls.remediation", data))

    # --- tags ---
    @app.get("/api/v1/tags")
    def list_tags(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        limit, offset = _pagination(_params(request))
        rows = tags_db.list_tags(session, tenant_id=identity.tenant_id, limit=limit, offset=offset)
        data = [tags_db.tag_to_dict(t) for t in rows]
        return JSONResponse(
            api_v1.envelope("tags", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @app.post("/api/v1/tags", status_code=status.HTTP_201_CREATED)
    def create_tag(
        body: CreateTagRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            tag = tags_db.create_tag(session, tenant_id=identity.tenant_id, name=body.name, color=body.color)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("tags", tags_db.tag_to_dict(tag)), status_code=status.HTTP_201_CREATED)

    @app.delete("/api/v1/tags/{tag_id}")
    def delete_tag(
        tag_id: str,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        deleted = tags_db.delete_tag(session, tenant_id=identity.tenant_id, tag_id=tag_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tag not found")
        session.commit()
        return JSONResponse(api_v1.envelope("tags", {"id": tag_id, "deleted": True}))

    @app.post("/api/v1/tags/attach", status_code=status.HTTP_201_CREATED)
    def attach_tag(
        body: AttachTagRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            et = tags_db.attach_tag(
                session,
                tenant_id=identity.tenant_id,
                tag_id=body.tag_id,
                entity_type=body.entity_type,
                entity_id=body.entity_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("tags.attach", tags_db.entity_tag_to_dict(et)), status_code=status.HTTP_201_CREATED
        )

    @app.post("/api/v1/tags/detach")
    def detach_tag(
        body: AttachTagRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            removed = tags_db.detach_tag(
                session,
                tenant_id=identity.tenant_id,
                tag_id=body.tag_id,
                entity_type=body.entity_type,
                entity_id=body.entity_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        if not removed:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="association not found")
        session.commit()
        return JSONResponse(api_v1.envelope("tags.detach", {"detached": True}))

    @app.get("/api/v1/tags/for")
    def tags_for_entity(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        entity_type = (params.get("entity_type") or [None])[0]
        entity_id = (params.get("entity_id") or [None])[0]
        if not entity_type or not entity_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="entity_type and entity_id are required"
            )
        rows = tags_db.tags_for_entity(
            session, tenant_id=identity.tenant_id, entity_type=entity_type, entity_id=entity_id
        )
        data = [tags_db.tag_to_dict(t) for t in rows]
        return JSONResponse(api_v1.envelope("tags.for", data, meta={"count": len(data)}))

    @app.get("/api/v1/tags/entities")
    def tag_entities(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        tag_id = (params.get("tag_id") or [None])[0]
        entity_type = (params.get("entity_type") or [None])[0]
        if not tag_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tag_id is required")
        entity_ids = tags_db.entity_ids_for_tag(
            session,
            tenant_id=identity.tenant_id,
            tag_id=str(tag_id),
            entity_type=str(entity_type) if entity_type else None,
        )
        return JSONResponse(
            api_v1.envelope(
                "tags.entities",
                entity_ids,
                meta={"count": len(entity_ids), "tag_id": tag_id, "entity_type": entity_type or "all"},
            )
        )

    # --- saved views ---
    @app.get("/api/v1/saved-views")
    def list_saved_views(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        surface = (params.get("surface") or [None])[0]
        rows = tags_db.list_saved_views(
            session, tenant_id=identity.tenant_id, surface=surface, limit=limit, offset=offset
        )
        data = [tags_db.saved_view_to_dict(v) for v in rows]
        return JSONResponse(
            api_v1.envelope("saved_views", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @app.post("/api/v1/saved-views", status_code=status.HTTP_201_CREATED)
    def create_saved_view(
        body: CreateSavedViewRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            view = tags_db.create_saved_view(
                session,
                tenant_id=identity.tenant_id,
                surface=body.surface,
                name=body.name,
                filters=body.filters,
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("saved_views", tags_db.saved_view_to_dict(view)), status_code=status.HTTP_201_CREATED
        )

    @app.delete("/api/v1/saved-views/{view_id}")
    def delete_saved_view(
        view_id: str,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        deleted = tags_db.delete_saved_view(session, tenant_id=identity.tenant_id, view_id=view_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="saved view not found")
        session.commit()
        return JSONResponse(api_v1.envelope("saved_views", {"id": view_id, "deleted": True}))

    # --- metrics & insights ---
    @app.get("/api/v1/insights/timeseries")
    def insights_timeseries(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        raw_limit = (_params(request).get("limit") or [None])[0]
        limit = int(raw_limit) if raw_limit and raw_limit.isdigit() else 90
        limit = min(max(limit, 1), 1000)
        points = metrics_db.list_metric_points(session, tenant_id=identity.tenant_id, limit=limit)
        rows = [metrics_db.metric_point_to_dict(p) for p in points]
        return JSONResponse(
            api_v1.envelope("insights.timeseries", _redact_payload(rows, identity), meta={"count": len(rows)})
        )

    @app.get("/api/v1/insights/remediation")
    def insights_remediation(
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        data = metrics_db.remediation_insights(session, tenant_id=identity.tenant_id)
        return JSONResponse(api_v1.envelope("insights.remediation", _redact_payload(data, identity)))

    @app.get("/api/v1/insights/framework-trends")
    def insights_framework_trends(
        request: Request,
        identity: Identity = Depends(_require_read),
    ) -> JSONResponse:
        raw_limit = (_params(request).get("limit") or [None])[0]
        limit = int(raw_limit) if raw_limit and raw_limit.isdigit() else 90
        limit = min(max(limit, 1), 1000)
        data = metrics_db.framework_readiness_trends(lake_for(identity), limit=limit)
        return JSONResponse(
            api_v1.envelope(
                "insights.framework_trends",
                _redact_payload(data, identity),
                meta={
                    "framework_count": len(data.get("frameworks") or []),
                    "point_count": len(data.get("points") or []),
                },
            )
        )

    @app.get("/api/v1/insights/sla-heatmap")
    def insights_sla_heatmap(
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        data = metrics_db.sla_heatmap(session, tenant_id=identity.tenant_id)
        return JSONResponse(api_v1.envelope("insights.sla_heatmap", _redact_payload(data, identity)))

    @app.post("/api/v1/insights/capture", status_code=status.HTTP_201_CREATED)
    def insights_capture(
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        point = metrics_db.capture_metric_point(session, tenant_id=identity.tenant_id, lake_dir=lake_for(identity))
        session.commit()
        return JSONResponse(
            api_v1.envelope("insights.timeseries", metrics_db.metric_point_to_dict(point)),
            status_code=status.HTTP_201_CREATED,
        )

    @app.get("/api/v1/frameworks/{framework_id}/detail", tags=["data"])
    def v1_framework_detail(framework_id: str, identity: Identity = Depends(_require_read)) -> JSONResponse:
        _status, body = api_v1.handle_get(f"/api/v1/frameworks/{framework_id}/detail", {}, lake_for(identity))
        return JSONResponse(_redact_payload(body, identity), status_code=int(_status))

    @app.get("/api/v1/frameworks/coverage", tags=["data"])
    def v1_framework_coverage(identity: Identity = Depends(_require_read)) -> JSONResponse:
        from security_lakehouse.framework_coverage import (
            build_framework_coverage,
            framework_coverage_summary,
        )

        rows = build_framework_coverage()
        data = {
            "summary": framework_coverage_summary(rows),
            "frameworks": rows,
        }
        return JSONResponse(
            api_v1.envelope(
                "frameworks.coverage",
                _redact_payload(data, identity),
                meta={"count": len(rows)},
            )
        )

    @app.get("/api/v1/snapshots/{snapshot_id}", tags=["assessment"])
    def snapshot_detail(snapshot_id: str, identity: Identity = Depends(_require_read)) -> JSONResponse:
        from security_lakehouse.assessment import load_snapshot, snapshot_detail_summary

        lake = lake_for(identity)
        try:
            payload = load_snapshot(lake, snapshot_id)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="snapshot not found") from None
        data = snapshot_detail_summary(snapshot_id, payload)
        return JSONResponse(api_v1.envelope("snapshots.detail", _redact_payload(data, identity)))

    @app.get("/api/v1/snapshots/{snapshot_id}/export.pdf", tags=["assessment"])
    def snapshot_export_pdf(snapshot_id: str, identity: Identity = Depends(_require_read)) -> Response:
        from security_lakehouse.assessment import load_snapshot, safe_snapshot_export_filename
        from security_lakehouse.reporting.executive_pdf import render_executive_pdf

        lake = lake_for(identity)
        try:
            assessment = load_snapshot(lake, snapshot_id)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="snapshot not found") from None
        try:
            pdf_bytes = render_executive_pdf(assessment)
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
        filename = safe_snapshot_export_filename(snapshot_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    # --- versioned data surface (authenticated) ---
    @app.get("/api/v1/{rest:path}")
    def v1_get(rest: str, request: Request, identity: Identity = Depends(_require_read)) -> JSONResponse:
        _status, body = api_v1.handle_get(f"/api/v1/{rest}", _params(request), lake_for(identity))
        return JSONResponse(_redact_payload(body, identity), status_code=int(_status))

    @app.post("/api/v1/{rest:path}")
    async def v1_post(
        rest: str,
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        body = await _json_object_body(request)
        v1_path = f"/api/v1/{rest}"
        if request.headers.get("Idempotency-Key") and "idempotency_key" not in body:
            body = {**body, "idempotency_key": request.headers["Idempotency-Key"]}
        required_scope = api_v1.required_post_scope(v1_path)
        if not identity.has_scope(required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires scope: {required_scope}",
            )
        # handle_post rebuilds posture and writes a snapshot; offload so it does
        # not block the event loop. on_snapshot_written is a no-op for every
        # v1_path except /api/v1/snapshots -- it dispatches webhook events
        # after write_assessment_snapshot's chain lock is released. The hook
        # only stages delivery-log rows in savepoints on `session` (it never
        # commits); this route has no other pending DB work, so committing
        # once here persists them.
        _status, payload = await run_in_threadpool(
            api_v1.handle_post,
            v1_path,
            body,
            lake_for(identity),
            on_snapshot_written=_snapshot_written_hook(session, identity.tenant_id),
        )
        session.commit()
        return JSONResponse(payload, status_code=int(_status))

    # --- legacy console surface (authenticated; same handlers as local mode) ---
    # Registered after the v1 routes so /api/v1/* and /api/healthz keep priority.
    @app.get("/api/{rest:path}")
    def legacy_get(rest: str, request: Request, identity: Identity = Depends(_require_read)) -> JSONResponse:
        _status, body = api_legacy.handle_get(f"/api/{rest}", _params(request), lake_for(identity))
        return JSONResponse(_redact_payload(body, identity), status_code=int(_status))

    @app.post("/api/{rest:path}")
    async def legacy_post(
        rest: str,
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        body = await _json_object_body(request)
        legacy_path = f"/api/{rest}"
        required_scope = api_legacy.required_post_scope(legacy_path)
        if not identity.has_scope(required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires scope: {required_scope}",
            )
        if request.headers.get("Idempotency-Key") and "idempotency_key" not in body:
            body = {**body, "idempotency_key": request.headers["Idempotency-Key"]}
        # Legacy POSTs run workflows, connector syncs (full pipeline + network),
        # and scheduler ticks; offload so they do not block the event loop.
        # on_snapshot_written mirrors v1_post: a no-op except for
        # /api/snapshots, which also deserves webhook dispatch -- it has the
        # same auth/tenant machinery as the versioned route.
        response = await run_in_threadpool(
            _legacy_post_response,
            legacy_path,
            body,
            lake_for(identity),
            identity,
            _snapshot_written_hook(session, identity.tenant_id),
        )
        session.commit()
        return response

    @app.get("/", response_class=HTMLResponse)
    @app.get("/console", response_class=HTMLResponse)
    def console() -> HTMLResponse:
        return HTMLResponse(dashboard.read_text(encoding="utf-8"))

    brand_mark = Path(__file__).resolve().parent / "static" / "trustops-mark.svg"

    @app.get("/brand/trustops-mark.svg", include_in_schema=False)
    def trustops_brand_mark() -> Response:
        """Public TrustOps monogram for MCP clients and link previews."""
        if not brand_mark.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return Response(
            brand_mark.read_bytes(),
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> RedirectResponse:
        return RedirectResponse(url="/brand/trustops-mark.svg", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    # The public trust page is a static export under a dynamic segment, so
    # only one placeholder is prebuilt. Keep the route in the OpenAPI contract
    # whether or not a bundle is installed; otherwise generated contracts
    # drift between source checkouts and CI jobs that download web-dist.
    # Serve that prebuilt HTML for any token path (the client reads the real
    # token from the URL). No auth — this is the unauthenticated reviewer
    # surface. The handler remains an explicit 404 when the optional bundle is
    # absent, matching the existing legacy-console fallback boundary.
    trust_page = web_dist / "trust" / "share" / "index.html" if web_dist is not None else None

    @app.get("/console/trust/{token}", response_class=HTMLResponse)
    @app.get("/console/trust/{token}/", response_class=HTMLResponse, include_in_schema=False)
    def public_trust_page(token: str) -> HTMLResponse:  # noqa: ARG001 - token read client-side
        if trust_page is None or not trust_page.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return HTMLResponse(trust_page.read_text(encoding="utf-8"))

    if web_dist is not None:
        # Next.js static export; html=True resolves /console/<route>/ to index.html.
        app.mount("/console", StaticFiles(directory=str(web_dist), html=True), name="console")

    return app


def serve(lake_dir: str | Path, *, host: str = "127.0.0.1", port: int = 8787, require_auth: bool = True) -> None:
    """Run the server-mode app under uvicorn."""
    import uvicorn

    uvicorn.run(create_app(lake_dir, require_auth=require_auth), host=host, port=port)
