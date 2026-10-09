"""Workflow (story) DAG + action library + persistence.

A workflow is a directed acyclic graph of typed actions that runs against
the lake. The library aims for best-in-class UX: every node has a published
input/output schema, can be tested live with sample data, and the whole
DAG is versioned + persisted append-only.

Persistence
-----------
* ``gold/workflows.jsonl``     — append-only workflow versions; each line
  is a full snapshot (``workflow_id``, ``version``, ``nodes``, ``edges``,
  ``actor``, ``occurred_at``). The latest version per id is materialized
  on read.
* ``gold/workflow_runs.jsonl`` — append-only execution log; each line is
  one whole-DAG run with per-node results.

Action library (the registry is the extension point):

  trigger.evidence_changed     fires when new silver events land
  trigger.cron                 fires on a cron schedule via scheduler tick
  check.evidence_exists        passes when N silver events match a filter
  check.control_pass           passes when a control_id's latest test is "pass"
  action.snapshot              freezes a point-in-time assessment snapshot
  action.assign_owner          appends a triage event with assignee + state
  action.connector_sync        runs a configured connector sync into the raw lake
  action.webhook               POSTs to an allowlisted, SSRF-guarded URL
  action.slack                 posts a Slack incoming-webhook message
  action.jira                  creates a Jira issue (POST /rest/api/3/issue)

Egress safety
-------------
``action.webhook`` was the engine's first OUTBOUND action; ``action.slack`` and
``action.jira`` build on the same machinery. Every outbound action routes through
the shared ``_http_post`` helper, so the egress guarantees are identical and not
duplicated. Egress is deny-by-default: a target host must match
``GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST``
(comma-separated ``host`` or ``host:port`` patterns) or the action refuses to
run. Every target is additionally SSRF-guarded — only ``http``/``https`` is
allowed and the *resolved* IP(s) must be public (private, loopback, link-local,
reserved and multicast ranges are rejected, as is ``localhost``). Secrets are
referenced as ``{{secret.NAME}}`` and resolved at run time; the resolved value is
never written to the run log — the persisted params keep the ``{{secret.NAME}}``
token. Locally a token resolves from ``GRC_LAKE_SECRET_<NAME>``. In hosted server
mode it resolves from the calling tenant's ``GRC_LAKE_TENANT_<ID>__SECRET_<NAME>``
(see :func:`security_lakehouse.secret_refs.tenant_secret_prefix`); the shared
``GRC_LAKE_SECRET_<NAME>`` is used there only for names the operator lists in
``GRC_LAKE_WORKFLOW_SHARED_SECRETS``.

Every action declares its input schema (the params the user fills in) and
its output schema (the keys downstream nodes can read), so the canvas can
validate edge wiring and the "Test action" button can render a form +
display the live result.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from security_lakehouse import netguard
from security_lakehouse.assessment import SnapshotWrittenHook, write_assessment_snapshot
from security_lakehouse.execution_mode import in_server_mode, server_tenant_id
from security_lakehouse.io import append_jsonl, canonical_sha256, read_jsonl
from security_lakehouse.ledger import chain_lock
from security_lakehouse.models import instant_sort_key
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.secret_refs import tenant_secret_prefix
from security_lakehouse.tracking import append_event as append_triage_event

WORKFLOWS_FILE = "workflows.jsonl"
RUNS_FILE = "workflow_runs.jsonl"

_RUN_ACTORS = {"console", "scheduler", "api"}

# --- webhook egress safety -------------------------------------------------
EGRESS_ALLOWLIST_ENV = "GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST"
SECRET_ENV_PREFIX = "GRC_LAKE_SECRET_"
WORKFLOW_SHARED_SECRETS_ENV = "GRC_LAKE_WORKFLOW_SHARED_SECRETS"
_WEBHOOK_TIMEOUT_SECONDS = 15
_WEBHOOK_BACKOFF_CAP_SECONDS = 2.0
_SECRET_RE = re.compile(r"\{\{\s*secret\.([A-Za-z0-9_]+)\s*\}\}")


# ---------------------------------------------------------------------------
# Action library
# ---------------------------------------------------------------------------


def _evidence_changed(_lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    return {
        "trigger_kind": "evidence_changed",
        "since": params.get("since"),
        "matched": True,
    }


def _cron(_lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    return {"trigger_kind": "cron", "schedule": params.get("schedule") or "@hourly"}


def _gate_approval(_lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    title = str(params.get("title") or "Approval required")
    assignee = str(params.get("assignee") or "")
    if dry_run:
        return {
            "dry_run": True,
            "would": "pause workflow for human approval before downstream actions",
            "title": title,
            "assignee": assignee,
        }
    return {
        "awaiting_approval": True,
        "title": title,
        "assignee": assignee,
        "passed": True,
    }


def _check_evidence_exists(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    control_id = str(params.get("control_id") or "")
    minimum = int(params.get("minimum") or 1)
    silver = lake / "silver" / "normalized_events.jsonl"
    matched = 0
    if silver.is_file():
        for row in read_jsonl(silver):
            if control_id and control_id not in (row.get("control_ids") or []):
                continue
            matched += 1
    return {"matched_count": matched, "passed": matched >= minimum, "minimum": minimum}


def _check_control_pass(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    control_id = str(params.get("control_id") or "")
    tests = lake / "gold" / "control_tests.jsonl"
    if not tests.is_file():
        return {"control_id": control_id, "passed": False, "reason": "no control_tests.jsonl"}
    rows = [r for r in read_jsonl(tests) if r.get("control_id") == control_id]
    if not rows:
        return {"control_id": control_id, "passed": False, "reason": "control not found"}
    rows.sort(key=lambda r: instant_sort_key(r.get("evaluated_at")), reverse=True)
    latest = rows[0]
    return {
        "control_id": control_id,
        "passed": latest.get("result") == "pass",
        "result": latest.get("result"),
        "confidence_score": latest.get("confidence_score"),
    }


def _action_snapshot(
    lake: Path,
    params: dict[str, Any],
    *,
    dry_run: bool = False,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> dict[str, Any]:
    reason = str(params.get("reason") or "workflow_run")
    if dry_run:
        return {
            "dry_run": True,
            "would": f"write an assessment snapshot to gold/snapshots/ (reason={reason!r})",
            "snapshot_path": None,
            "reason": reason,
        }
    path = write_assessment_snapshot(lake, reason=reason, on_snapshot_written=on_snapshot_written)
    return {"snapshot_path": str(path), "reason": reason}


def _action_connector_sync(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    connector_id = str(params.get("connector_id") or "").strip()
    if not connector_id:
        raise ValueError("connector_id is required")
    actor = str(params.get("actor") or "workflow")
    if dry_run:
        return {
            "dry_run": True,
            "would": f"sync connector {connector_id!r} (actor={actor!r})",
            "connector_id": connector_id,
            "result": None,
            "evidence_count": None,
            "error": None,
        }
    from security_lakehouse.connector_runner import run_connector_sync

    sync = run_connector_sync(lake, connector_id=connector_id, actor=actor)
    return {
        "connector_id": connector_id,
        "result": sync.result,
        "evidence_count": sync.evidence_count,
        # A failed sync raises ConnectorSyncError; a returned result succeeded.
        "error": None,
        "watermark_cursor": sync.watermark_cursor,
    }


def _action_assign_owner(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    violation_id = str(params.get("violation_id") or "")
    assignee = str(params.get("assignee") or "")
    if not violation_id:
        raise ValueError("violation_id is required")
    if dry_run:
        state = str(params.get("state") or "triaged")
        return {
            "dry_run": True,
            "would": (f"append a triage event for violation {violation_id!r} (assignee={assignee!r}, state={state!r})"),
            "violation_id": violation_id,
            "assignee": assignee,
            "tracking_id": None,
        }
    record = append_triage_event(
        lake,
        violation_id=violation_id,
        actor=str(params.get("actor") or "workflow"),
        state=str(params.get("state") or "triaged"),
        assignee=assignee or None,
        due_at=params.get("due_at"),
        note=params.get("note") or "auto-assigned by workflow",
    )
    return {"violation_id": violation_id, "assignee": assignee, "tracking_id": record["tracking_id"]}


# ---------------------------------------------------------------------------
# action.webhook — first OUTBOUND/egress action (deny-by-default + SSRF guard)
# ---------------------------------------------------------------------------


def _webhook_backoff_sleep(seconds: float) -> None:
    """Indirection point so tests can monkeypatch the retry sleep to a no-op."""
    time.sleep(seconds)


def _load_egress_allowlist() -> set[str]:
    """Parse ``GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST`` into normalized host[:port] entries.

    An empty/unset env means egress is disabled (deny-by-default); the caller
    treats an empty set as "deny all".
    """
    raw = runtime_env().get(EGRESS_ALLOWLIST_ENV, "")
    entries: set[str] = set()
    for chunk in raw.split(","):
        entry = chunk.strip().lower()
        if entry:
            entries.add(entry)
    return entries


def _host_is_allowlisted(host: str, port: int, allowlist: set[str]) -> bool:
    """A target matches if its bare host or its explicit ``host:port`` is listed."""
    host = host.lower()
    if host in allowlist:
        return True
    return f"{host}:{port}" in allowlist


def _assert_resolved_ip_is_public(host: str) -> list[str]:
    """SSRF guard for webhook egress; delegates to the shared :mod:`netguard`."""
    return netguard.assert_resolved_ip_is_public(host, label="webhook target")


def _shared_secret_allowlist() -> frozenset[str]:
    raw = runtime_env().get(WORKFLOW_SHARED_SECRETS_ENV, "")
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


def _resolve_secret(name: str, lake_dir: str | Path | None) -> str:
    """One ``{{secret.NAME}}`` value for the current mode (see the module docstring)."""
    shared_key = f"{SECRET_ENV_PREFIX}{name}"
    if not in_server_mode():
        secret = runtime_env().get(shared_key)
        if secret is None:
            raise ValueError(f"secret {name!r} is not set (expected env {shared_key})")
        return secret
    tenant_id = server_tenant_id(lake_dir)
    prefix = tenant_secret_prefix(tenant_id) if tenant_id else None
    if prefix:
        # The key is built from the validated tenant prefix and a [A-Za-z0-9_]
        # name, so a token can never step outside the tenant's namespace.
        tenant_value = runtime_env().get(f"{prefix}SECRET_{name}")
        if tenant_value is not None:
            return tenant_value
    if name in _shared_secret_allowlist():
        shared = runtime_env().get(shared_key)
        if shared is not None:
            return shared
    expected = f"{prefix}SECRET_{name}" if prefix else "a tenant-scoped secret"
    raise ValueError(f"secret {name!r} is not set for this tenant (expected env {expected})")


def _resolve_secrets(value: Any, lake_dir: str | Path | None = None) -> Any:
    """Replace ``{{secret.NAME}}`` tokens with their values for the current tenant.

    Applied to the request actually sent on the wire. The caller must NOT feed
    the resolved result back into anything that is persisted — the run log keeps
    the pre-resolution token form so the secret value never lands on disk.
    """
    if isinstance(value, str):
        return _SECRET_RE.sub(lambda match: _resolve_secret(match.group(1), lake_dir), value)
    if isinstance(value, list):
        return [_resolve_secrets(item, lake_dir) for item in value]
    if isinstance(value, dict):
        return {k: _resolve_secrets(v, lake_dir) for k, v in value.items()}
    return value


def _redact_secret_tokens(value: Any) -> Any:
    """Best-effort: rewrite any ``{{secret.NAME}}`` token to ``[secret]``.

    Defense in depth for output echoing — even though secrets are only resolved
    on the outbound copy, this guards against a token (and never the value) ever
    being surfaced verbatim in a snippet that mirrors request content.
    """
    if isinstance(value, str):
        return _SECRET_RE.sub("[secret]", value)
    if isinstance(value, list):
        return [_redact_secret_tokens(item) for item in value]
    if isinstance(value, dict):
        return {k: _redact_secret_tokens(v) for k, v in value.items()}
    return value


def _webhook_idempotency_key(params: dict[str, Any]) -> str:
    """Stable per-node-run key so retries/replays of identical params don't double-fire.

    Derived from the *templated* (pre-secret-resolution) params, so the key
    never depends on — or leaks — a secret value, yet stays constant across the
    retry loop of a single run.
    """
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _assert_egress_allowed(url: str, *, what: str = "webhook") -> None:
    """Run the deny-by-default allowlist + SSRF guard against the connect url.

    The guard runs on the *exact* url the request connects to (after any
    ``{{secret.NAME}}`` in the url itself has been resolved — e.g. a Slack
    incoming-webhook URL passed as a secret). A secret therefore cannot smuggle
    the request past the gate: whatever host it resolves to must still match the
    allowlist AND its resolved IP(s) must still be public. Raises ``ValueError``
    on any violation; returns ``None`` when the target is permitted.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{what} url scheme {parsed.scheme!r} is not allowed (http/https only)")
    host = parsed.hostname
    if not host:
        raise ValueError(f"{what} url has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    allowlist = _load_egress_allowlist()
    if not allowlist:
        raise ValueError("workflow egress is disabled; set GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST")
    if not _host_is_allowlisted(host, port, allowlist):
        raise ValueError(f"{what} target host {host!r} is not in the egress allowlist")
    _assert_resolved_ip_is_public(host)


def _http_post(
    url_template: str,
    *,
    body: Any = None,
    headers: dict[str, Any] | None = None,
    max_retries: int = 2,
    idempotency_key: str | None = None,
    what: str = "webhook",
    lake_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Shared outbound POST: allowlist + SSRF guard + secret resolver + retry.

    This is the single egress path for every OUTBOUND action (``action.webhook``,
    ``action.slack``, ``action.jira``). ``url_template``/``body``/``headers`` arrive
    carrying ``{{secret.NAME}}`` tokens; secrets are resolved here on the outbound
    copy only, so nothing the caller persists (its params, this return value) ever
    holds a resolved secret value. The allowlist + SSRF guard run on the resolved
    connect url, so a url supplied as a secret is still gated.

    Returns ``status_code``, ``ok``, ``response_snippet`` (secret-token redacted),
    ``attempts``, ``idempotency_key``, ``error``.
    """
    if not url_template or not isinstance(url_template, str):
        raise ValueError(f"{what} 'url' is required")

    max_retries = max(0, max_retries)
    if idempotency_key is None:
        idempotency_key = _webhook_idempotency_key({"url": url_template, "body": body, "headers": headers})

    # Resolve the url's secrets ONCE, then run the allowlist + SSRF guard on the
    # exact host we will connect to (so a url passed as {{secret.NAME}} — e.g. a
    # Slack incoming-webhook URL — is still gated, and guard-vs-connect can't
    # disagree). The caller's params stay token-form; nothing resolved is persisted.
    url = str(_resolve_secrets(url_template, lake_dir))
    _assert_egress_allowed(url, what=what)
    body_value = _resolve_secrets(body, lake_dir) if body is not None else None
    if body_value is None:
        data = None
    elif isinstance(body_value, str):
        data = body_value.encode("utf-8")
    else:
        data = json.dumps(body_value, separators=(",", ":")).encode("utf-8")

    header_template = headers or {}
    if not isinstance(header_template, dict):
        raise ValueError(f"{what} 'headers' must be an object")
    out_headers: dict[str, str] = {str(k): str(_resolve_secrets(v, lake_dir)) for k, v in header_template.items()}
    out_headers.setdefault("Idempotency-Key", idempotency_key)
    if data is not None and not any(k.lower() == "content-type" for k in out_headers):
        out_headers["Content-Type"] = "application/json"

    last_error: str | None = None
    status_code = 0
    response_snippet = ""
    ok = False
    attempts = 0
    for attempt in range(max_retries + 1):
        attempts = attempt + 1
        request = urllib.request.Request(url, data=data, headers=out_headers, method="POST")  # noqa: S310 (scheme + allowlist + SSRF guarded above)
        try:
            # open_guarded re-runs the allowlist + SSRF guard on every redirect
            # hop and strips Authorization/Cookie across origins, so a 302 from
            # an allowlisted host cannot pivot this request (or its secret
            # headers, or the response body) at an internal address.
            with netguard.open_guarded(
                request,
                timeout=_WEBHOOK_TIMEOUT_SECONDS,
                validate=lambda target: _assert_egress_allowed(target, what=what),
            ) as resp:
                status_code = int(getattr(resp, "status", 0) or 0)
                payload = resp.read(2048)
                response_snippet = payload.decode("utf-8", errors="replace")[:500]
                ok = 200 <= status_code < 300
                last_error = None
                break
        except urllib.error.HTTPError as exc:
            status_code = int(exc.code)
            try:
                response_snippet = exc.read(2048).decode("utf-8", errors="replace")[:500]
            except Exception:  # noqa: BLE001 — snippet is best-effort
                response_snippet = ""
            ok = False
            if 400 <= status_code < 500:
                # 4xx is a client error — not retryable.
                last_error = None
                break
            last_error = f"HTTP {status_code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            status_code = 0
            ok = False
        if attempt < max_retries:
            sleep_for = min(_WEBHOOK_BACKOFF_CAP_SECONDS, 0.1 * (2**attempt))
            _webhook_backoff_sleep(sleep_for)

    return {
        "status_code": status_code,
        "ok": ok,
        "response_snippet": _redact_secret_tokens(response_snippet),
        "attempts": attempts,
        "idempotency_key": idempotency_key,
        "error": last_error,
    }


def _coerce_max_retries(params: dict[str, Any], default: int = 2) -> int:
    try:
        return max(0, int(params.get("max_retries", default)))
    except (TypeError, ValueError):
        return default


def _action_webhook(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    """POST to an allowlisted, SSRF-guarded URL with retry + idempotency.

    ``params`` arrives already templated for ``{{node.output.*}}`` (resolved by
    ``run_workflow``) but still carrying ``{{secret.NAME}}`` tokens — the shared
    ``_http_post`` resolves secrets on the outbound request only, so the persisted
    node params and this output keep the token form.
    """
    url_template = params.get("url")
    if not url_template or not isinstance(url_template, str):
        raise ValueError("webhook 'url' is required")
    if dry_run:
        return {
            "dry_run": True,
            "would": f"POST a webhook to {_redact_secret_tokens(url_template)}",
            "status_code": None,
            "ok": None,
        }
    return _http_post(
        url_template,
        body=params.get("body"),
        headers=params.get("headers") or {},
        max_retries=_coerce_max_retries(params),
        # Preserve the historical idempotency key derived from the full params.
        idempotency_key=_webhook_idempotency_key(params),
        what="webhook",
        lake_dir=lake,
    )


def _action_slack(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    """POST a Slack incoming-webhook message via the shared egress path.

    ``webhook_url`` is typically ``{{secret.SLACK_WEBHOOK}}`` — it still flows
    through the allowlist + SSRF guard (on the pre-secret token) and is never
    persisted in resolved form.
    """
    webhook_url = params.get("webhook_url")
    if not webhook_url or not isinstance(webhook_url, str):
        raise ValueError("slack 'webhook_url' is required")
    text = params.get("text")
    if not text or not isinstance(text, str):
        raise ValueError("slack 'text' is required")

    if dry_run:
        return {
            "dry_run": True,
            "would": f"post a Slack message to {_redact_secret_tokens(webhook_url)}",
            "status_code": None,
            "ok": None,
        }

    payload: dict[str, Any] = {"text": text}
    for key in ("username", "icon_emoji", "channel"):
        value = params.get(key)
        if value:
            payload[key] = value

    result = _http_post(
        webhook_url,
        body=payload,
        max_retries=_coerce_max_retries(params),
        what="slack",
        lake_dir=lake,
    )
    return {
        "status_code": result["status_code"],
        "ok": result["ok"],
        "response_snippet": result["response_snippet"],
        "attempts": result["attempts"],
        "idempotency_key": result["idempotency_key"],
        "error": result["error"],
    }


def _action_jira(lake: Path, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    """Create a Jira issue via the shared egress path.

    Auth is built from a resolved ``{{secret.JIRA_TOKEN}}`` token: with an
    ``email`` it forms HTTP Basic (``email:token`` → base64), otherwise it is
    sent as a Bearer token. The Authorization header value keeps its token form
    in the caller's persisted params; ``_http_post`` resolves it only on the wire.
    """
    base_url = params.get("base_url")
    if not base_url or not isinstance(base_url, str):
        raise ValueError("jira 'base_url' is required")
    project_key = params.get("project_key")
    if not project_key or not isinstance(project_key, str):
        raise ValueError("jira 'project_key' is required")
    summary = params.get("summary")
    if not summary or not isinstance(summary, str):
        raise ValueError("jira 'summary' is required")
    token = params.get("token")
    if not token or not isinstance(token, str):
        raise ValueError("jira 'token' is required (typically {{secret.JIRA_TOKEN}})")

    if dry_run:
        return {
            "dry_run": True,
            "would": (
                f"create a Jira {str(params.get('issue_type') or 'Task')!r} issue in "
                f"project {project_key!r} at {_redact_secret_tokens(base_url)} "
                f"(summary={summary!r})"
            ),
            "status_code": None,
            "ok": None,
            "issue_key": None,
        }

    issue_type = str(params.get("issue_type") or "Task")
    fields: dict[str, Any] = {
        "project": {"key": project_key},
        "summary": summary,
        "issuetype": {"name": issue_type},
    }
    description = params.get("description")
    if description:
        fields["description"] = description

    # With an email -> HTTP Basic over email:token. Without -> Bearer, which keeps
    # the {{secret.NAME}} token form so _http_post resolves it on the wire only and
    # the caller's persisted params never hold the secret value.
    email = params.get("email")
    auth_header = _jira_basic_auth(str(email), token, lake) if email else f"Bearer {token}"

    url = base_url.rstrip("/") + "/rest/api/3/issue"
    result = _http_post(
        url,
        body={"fields": fields},
        headers={"Authorization": auth_header, "Accept": "application/json"},
        max_retries=_coerce_max_retries(params),
        what="jira",
        lake_dir=lake,
    )

    issue_key: str | None = None
    snippet = result.get("response_snippet") or ""
    if snippet:
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict) and isinstance(parsed.get("key"), str):
                issue_key = parsed["key"]
        except (ValueError, TypeError):
            issue_key = None

    return {
        "status_code": result["status_code"],
        "ok": result["ok"],
        "issue_key": issue_key,
        "response_snippet": result["response_snippet"],
        "attempts": result["attempts"],
        "idempotency_key": result["idempotency_key"],
        "error": result["error"],
    }


def _jira_basic_auth(email: str, token: str, lake_dir: str | Path | None = None) -> str:
    """Build a Basic-auth header value, deferring secret resolution to the wire.

    When ``token`` is a ``{{secret.NAME}}`` token we cannot base64 it here without
    materializing the secret into the (persisted) params. Instead we resolve the
    secret *temporarily*, base64-encode ``email:secret``, and hand the encoded
    value to ``_http_post`` already wrapped so it is treated as opaque. Because
    the encoded value still never appears in the caller's stored params (only the
    header object passed to ``_http_post`` does), and that header object is local
    to this call, the persisted node params are untouched. The encoded credential
    is built fresh each run and never written to the run log.
    """
    resolved_token = str(_resolve_secrets(token, lake_dir))
    raw = f"{email}:{resolved_token}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


ACTION_LIBRARY: dict[str, dict[str, Any]] = {
    "trigger.evidence_changed": {
        "kind": "trigger",
        "label": "Evidence changed",
        "description": "Fires when new evidence is collected.",
        "input_schema": {"since": {"type": "string", "label": "Since (ISO 8601)", "optional": True}},
        "output_schema": {"trigger_kind": "string", "since": "string", "matched": "boolean"},
        "handler": _evidence_changed,
    },
    "trigger.cron": {
        "kind": "trigger",
        "label": "Cron schedule",
        "description": "Fires when the scheduler tick finds this workflow due.",
        "input_schema": {"schedule": {"type": "string", "label": "Cron expression", "default": "@hourly"}},
        "output_schema": {"trigger_kind": "string", "schedule": "string"},
        "handler": _cron,
    },
    "check.evidence_exists": {
        "kind": "check",
        "label": "Evidence exists",
        "description": "Passes when at least N evidence records map to the given control.",
        "input_schema": {
            "control_id": {"type": "string", "label": "Control id", "required": True},
            "minimum": {"type": "number", "label": "Minimum count", "default": 1},
        },
        "output_schema": {"matched_count": "number", "passed": "boolean", "minimum": "number"},
        "handler": _check_evidence_exists,
    },
    "check.control_pass": {
        "kind": "check",
        "label": "Control passes",
        "description": "Passes when the latest control test for this control_id is 'pass'.",
        "input_schema": {"control_id": {"type": "string", "label": "Control id", "required": True}},
        "output_schema": {
            "control_id": "string",
            "passed": "boolean",
            "result": "string",
            "confidence_score": "number",
        },
        "handler": _check_control_pass,
    },
    "gate.approval": {
        "kind": "gate",
        "label": "Approval gate",
        "description": "Pauses the workflow until an operator approves or rejects downstream actions.",
        "input_schema": {
            "title": {"type": "string", "label": "Approval title", "default": "Approval required"},
            "assignee": {"type": "string", "label": "Assignee (optional)", "optional": True},
        },
        "output_schema": {
            "awaiting_approval": "boolean",
            "title": "string",
            "assignee": "string",
            "passed": "boolean",
        },
        "handler": _gate_approval,
    },
    "action.snapshot": {
        "kind": "action",
        "label": "Freeze snapshot",
        "description": "Freezes a point-in-time assessment snapshot for the audit trail.",
        "input_schema": {"reason": {"type": "string", "label": "Reason", "default": "workflow_run"}},
        "output_schema": {"snapshot_path": "string", "reason": "string"},
        "handler": _action_snapshot,
    },
    "action.assign_owner": {
        "kind": "action",
        "label": "Assign owner",
        "description": "Appends a triage event with an assignee for a violation_id.",
        "input_schema": {
            "violation_id": {"type": "string", "label": "Violation id", "required": True},
            "assignee": {"type": "string", "label": "Assignee", "required": True},
            "state": {"type": "string", "label": "State", "default": "triaged"},
            "note": {"type": "string", "label": "Note", "optional": True},
            "due_at": {"type": "string", "label": "Due (ISO 8601)", "optional": True},
        },
        "output_schema": {"violation_id": "string", "assignee": "string", "tracking_id": "string"},
        "handler": _action_assign_owner,
    },
    "action.webhook": {
        "kind": "action",
        "label": "Send webhook",
        "description": (
            "Sends a request to an approved URL. Outbound hosts must be on the "
            "server's allowlist (deny by default); {{secret.NAME}} tokens resolve "
            "from server-side secrets at run time and are never saved."
        ),
        "input_schema": {
            "url": {"type": "string", "label": "URL", "required": True},
            "body": {"type": "string", "label": "Body (JSON or text)", "optional": True},
            "headers": {"type": "object", "label": "Headers", "optional": True},
            "max_retries": {"type": "number", "label": "Max retries", "default": 2},
        },
        "output_schema": {
            "status_code": "number",
            "ok": "boolean",
            "response_snippet": "string",
        },
        "handler": _action_webhook,
    },
    "action.slack": {
        "kind": "action",
        "label": "Send Slack message",
        "description": (
            "POSTs a message to a Slack incoming-webhook URL over the shared egress "
            "path (deny-by-default allowlist + SSRF guard). The webhook_url is "
            "typically {{secret.SLACK_WEBHOOK}}; resolved secrets are never persisted."
        ),
        "input_schema": {
            "webhook_url": {"type": "string", "label": "Slack webhook URL", "required": True},
            "text": {"type": "string", "label": "Message text", "required": True},
            "username": {"type": "string", "label": "Username", "optional": True},
            "icon_emoji": {"type": "string", "label": "Icon emoji", "optional": True},
            "channel": {"type": "string", "label": "Channel", "optional": True},
            "max_retries": {"type": "number", "label": "Max retries", "default": 2},
        },
        "output_schema": {
            "status_code": "number",
            "ok": "boolean",
        },
        "handler": _action_slack,
    },
    "action.jira": {
        "kind": "action",
        "label": "Create Jira issue",
        "description": (
            "Creates a Jira issue over the shared outbound path (deny-by-default "
            "allowlist and SSRF guard). Auth derives from "
            "{{secret.JIRA_TOKEN}} (Bearer, or Basic with an email); resolved "
            "secrets are never persisted."
        ),
        "input_schema": {
            "base_url": {"type": "string", "label": "Base URL", "required": True},
            "project_key": {"type": "string", "label": "Project key", "required": True},
            "summary": {"type": "string", "label": "Summary", "required": True},
            "token": {"type": "string", "label": "API token", "required": True},
            "email": {"type": "string", "label": "Email (for Basic auth)", "optional": True},
            "description": {"type": "string", "label": "Description", "optional": True},
            "issue_type": {"type": "string", "label": "Issue type", "default": "Task"},
            "max_retries": {"type": "number", "label": "Max retries", "default": 2},
        },
        "output_schema": {
            "status_code": "number",
            "ok": "boolean",
            "issue_key": "string",
        },
        "handler": _action_jira,
    },
    "action.connector_sync": {
        "kind": "action",
        "label": "Sync connector",
        "description": (
            "Runs a configured connector sync into the managed raw lake using the "
            "in-repo adapter registry (read-only collection adapters only)."
        ),
        "input_schema": {
            "connector_id": {"type": "string", "label": "Connector id", "required": True},
            "actor": {"type": "string", "label": "Actor", "default": "workflow"},
        },
        "output_schema": {
            "connector_id": "string",
            "result": "string",
            "evidence_count": "number",
            "error": "string",
            "watermark_cursor": "string",
        },
        "handler": _action_connector_sync,
    },
}


def action_catalog() -> list[dict[str, Any]]:
    """Return the action library minus handler refs (the React canvas reads this)."""
    return [
        {
            "node_type": node_type,
            "kind": spec["kind"],
            "label": spec["label"],
            "description": spec["description"],
            "input_schema": spec["input_schema"],
            "output_schema": spec["output_schema"],
        }
        for node_type, spec in ACTION_LIBRARY.items()
    ]


def run_action(
    lake_dir: str | Path,
    *,
    node_type: str,
    params: dict[str, Any] | None = None,
    dry_run: bool = False,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> dict[str, Any]:
    """Execute a single action node against the lake and return its output.

    When ``dry_run=True``, side-effecting actions (``action.snapshot``,
    ``action.assign_owner``, ``action.connector_sync``, ``action.webhook``, ``action.slack``,
    ``action.jira``) skip their side effect and return a ``{"dry_run": True,
    "would": ...}`` preview instead. Read-only checks and triggers run normally
    so downstream branching stays realistic.

    ``on_snapshot_written`` is forwarded only to ``action.snapshot`` (every
    other handler has a uniform, fixed signature and does not accept it) so a
    workflow-triggered snapshot dispatches webhook events the same way an
    API-triggered one does.
    """
    spec = ACTION_LIBRARY.get(node_type)
    if spec is None:
        raise ValueError(f"unknown node_type {node_type!r}")
    handler = spec["handler"]
    if node_type == "action.snapshot":
        return handler(Path(lake_dir), params or {}, dry_run=dry_run, on_snapshot_written=on_snapshot_written)
    return handler(Path(lake_dir), params or {}, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Workflow persistence
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _gold(lake_dir: str | Path) -> Path:
    return Path(lake_dir) / "gold"


def _read_log(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _slugify(text: str) -> str:
    clean = "".join(c if c.isalnum() or c in "-_" else "-" for c in text.lower())
    while "--" in clean:
        clean = clean.replace("--", "-")
    return clean.strip("-") or "workflow"


def _validate_workflow_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    """Reject structurally invalid workflows before they are persisted.

    Guards against unknown node types, missing/duplicate node ids, edges that
    reference non-existent nodes, and cycles. A saved workflow is therefore
    always a runnable DAG over known actions, rather than failing opaquely (or
    running in a nondeterministic order) at execution time.
    """
    if not isinstance(edges, list):
        raise ValueError("workflow edges must be a list")
    ids: list[str] = []
    for node in nodes:
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            raise ValueError("every workflow node requires a non-empty 'id'")
        node_type = str(node.get("node_type") or "")
        if node_type not in ACTION_LIBRARY:
            raise ValueError(f"unknown node_type {node_type!r} for node {node_id!r}")
        ids.append(node_id)
    id_set = set(ids)
    if len(id_set) != len(ids):
        duplicates = sorted({nid for nid in ids if ids.count(nid) > 1})
        raise ValueError(f"duplicate node ids: {duplicates}")

    incoming: dict[str, list[str]] = {nid: [] for nid in id_set}
    outgoing: dict[str, list[str]] = {nid: [] for nid in id_set}
    for edge in edges:
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if source not in id_set:
            raise ValueError(f"edge source {source!r} is not a node id")
        if target not in id_set:
            raise ValueError(f"edge target {target!r} is not a node id")
        incoming[target].append(source)
        outgoing[source].append(target)

    # Kahn's algorithm: if any node never reaches in-degree 0, a cycle exists.
    indegree = {nid: len(parents) for nid, parents in incoming.items()}
    ready = [nid for nid, degree in indegree.items() if degree == 0]
    visited = 0
    while ready:
        nid = ready.pop()
        visited += 1
        for child in outgoing[nid]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(id_set):
        raise ValueError("workflow graph must be acyclic (a cycle was detected)")


def save_workflow(
    lake_dir: str | Path,
    *,
    workflow_id: str | None,
    name: str,
    description: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    actor: str = "console",
) -> dict[str, Any]:
    """Append a new version of a workflow (auto-generates workflow_id if absent)."""
    if not name:
        raise ValueError("workflow name is required")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("workflow must declare at least one node")
    _validate_workflow_graph(nodes, edges)
    workflow_id = workflow_id or _slugify(name)
    existing = list_workflows(lake_dir)
    versions = [w for w in existing if w["workflow_id"] == workflow_id]
    version = (max(int(v.get("version") or 0) for v in versions) + 1) if versions else 1
    record = {
        "workflow_id": workflow_id,
        "version": version,
        "name": name,
        "description": description,
        "nodes": nodes,
        "edges": edges,
        "actor": actor,
        "occurred_at": _utc_now_iso(),
        "hash": hashlib.sha256(
            json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16],
    }
    gold = _gold(lake_dir)
    gold.mkdir(parents=True, exist_ok=True)
    with (gold / WORKFLOWS_FILE).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    return record


def list_workflows(lake_dir: str | Path) -> list[dict[str, Any]]:
    """Return the latest version per workflow_id, newest-saved first."""
    rows = _read_log(_gold(lake_dir) / WORKFLOWS_FILE)
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        wid = str(row.get("workflow_id") or "")
        if not wid:
            continue
        prev = latest.get(wid)
        if prev is None or int(row.get("version") or 0) > int(prev.get("version") or 0):
            latest[wid] = row
    return sorted(latest.values(), key=lambda r: instant_sort_key(r.get("occurred_at")), reverse=True)


def _evidence_changed_trigger(workflow: dict[str, Any]) -> dict[str, Any] | None:
    for node in workflow.get("nodes", []) or []:
        if str(node.get("node_type") or "") == "trigger.evidence_changed":
            return node
    return None


def run_evidence_changed_workflows(
    lake_dir: str | Path,
    *,
    actor: str = "evidence_changed",
    connector_id: str | None = None,
) -> list[dict[str, Any]]:
    """Run every workflow whose entry trigger is ``trigger.evidence_changed``.

    This is the push side of continuous evaluation: instead of waiting for the
    next cron tick, a sync that lands fresh evidence fires the dependent
    automations immediately. A trigger may scope itself to one source via a
    ``connector_id`` param; an unscoped trigger fires on any evidence change.
    """
    runs: list[dict[str, Any]] = []
    for workflow in list_workflows(lake_dir):
        trigger = _evidence_changed_trigger(workflow)
        if trigger is None:
            continue
        wanted = str((trigger.get("params") or {}).get("connector_id") or "").strip()
        if wanted and connector_id and wanted != connector_id:
            continue
        workflow_id = str(workflow.get("workflow_id") or "")
        if workflow_id:
            runs.append(run_workflow(lake_dir, workflow_id=workflow_id, actor=actor))
    return runs


def get_workflow(lake_dir: str | Path, workflow_id: str) -> dict[str, Any] | None:
    for w in list_workflows(lake_dir):
        if w["workflow_id"] == workflow_id:
            return w
    return None


_VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\.output\.([A-Za-z0-9_]+)\s*\}\}")


def _substitute_variables(
    params: dict[str, Any],
    outputs_by_node: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Replace ``{{nodeId.output.field}}`` references in string params."""

    def resolve(value: Any) -> Any:
        if isinstance(value, str):

            def repl(match: re.Match[str]) -> str:
                node_id = match.group(1)
                field = match.group(2)
                source = outputs_by_node.get(node_id)
                if not source:
                    return match.group(0)
                replacement = source.get(field)
                if replacement is None:
                    return ""
                return str(replacement)

            return _VAR_RE.sub(repl, value)
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if isinstance(value, dict):
            return {k: resolve(v) for k, v in value.items()}
        return value

    return {k: resolve(v) for k, v in params.items()}


# ``output.<field> <op> <literal>``; the membership form ``output.<field> in <list>``
# is matched separately because its operator is a word, not a symbol.
_EXPR_RE = re.compile(r"^\s*output\.([A-Za-z0-9_]+)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s*$")
_EXPR_IN_RE = re.compile(r"^\s*output\.([A-Za-z0-9_]+)\s+in\s+(.+?)\s*$")


def _coerce_literal(token: str) -> Any:
    """Parse an edge-expression right-hand literal into a Python value.

    ``true``/``false``/``null`` map to ``True``/``False``/``None`` (case
    insensitive); quoted strings drop their quotes; bare numbers become
    ``int``/``float``; everything else stays a string. This is a tiny, total
    parser — there is no ``eval``/``exec`` anywhere on this path.
    """
    raw = token.strip()
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none"):
        return None
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _coerce_pair(left: Any, right: Any) -> tuple[Any, Any]:
    """Coerce ``left`` (parent output value) toward ``right``'s type for comparison.

    If the literal is numeric, try to read the output value as a number too so
    ``output.status == 403`` matches whether the producer emitted ``403`` or
    ``"403"``. If the literal is a bool, coerce the output value with ``bool``.
    Otherwise both sides are compared as strings.
    """
    if isinstance(right, bool):
        return bool(left), right
    if isinstance(right, (int, float)) and not isinstance(left, bool):
        try:
            return type(right)(left), right
        except (TypeError, ValueError):
            return left, right
    return left, right


def _apply_operator(op: str, left: Any, right: Any) -> bool:
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    # Ordering comparisons need mutually-orderable operands.
    try:
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
    except TypeError:
        return False
    return False


def _evaluate_expression(expr: str, output: dict[str, Any]) -> bool:
    """Safely evaluate an edge-condition expression over the parent output.

    Grammar (all over the parent node's ``output`` dict; no ``eval``/``exec``):

      output.<field> == <literal>
      output.<field> != <literal>
      output.<field> >  <number>
      output.<field> >= <number>
      output.<field> <  <number>
      output.<field> <= <number>
      output.<field> in <json-list-or-comma-list>

    ``<literal>`` is ``true``/``false``/``null``, a quoted string, a number, or a
    bare string. A reference to a field the parent never emitted (or a malformed
    expression) declines the edge rather than raising, so a typo can't crash a
    run. Returns ``True`` when the edge should fire.
    """
    in_match = _EXPR_IN_RE.match(expr)
    if in_match:
        field, rhs = in_match.group(1), in_match.group(2).strip()
        if field not in output:
            return False
        members: list[Any]
        try:
            parsed = json.loads(rhs)
            members = parsed if isinstance(parsed, list) else [parsed]
        except (ValueError, TypeError):
            members = [_coerce_literal(part) for part in rhs.split(",") if part.strip()]
        left = output.get(field)
        for member in members:
            coerced_left, coerced_right = _coerce_pair(left, member)
            if coerced_left == coerced_right:
                return True
        return False

    match = _EXPR_RE.match(expr)
    if not match:
        return False
    field, op, rhs = match.group(1), match.group(2), match.group(3)
    if field not in output:
        return False
    left = output.get(field)
    right = _coerce_literal(rhs)
    left, right = _coerce_pair(left, right)
    return _apply_operator(op, left, right)


def _is_expression_condition(condition: str) -> bool:
    """An edge condition is an expression when it references ``output.<field>``."""
    return condition.strip().startswith("output.")


def _edge_allows(edge: dict[str, Any], parent_result: dict[str, Any] | None) -> bool:
    """Return True if `edge` should fire given the parent node's run result.

    The ``condition`` is either a legacy literal — ``"always"`` (default),
    ``"passed"``, ``"failed"`` — or a safe expression over the parent node's
    output (see :func:`_evaluate_expression` for the grammar), e.g.
    ``"output.status == 403"`` or ``"output.matched_count > 0"``. A condition may
    also be supplied as an object ``{"expression": "output.ok != true"}``.

    Expression and ``passed``/``failed`` conditions require the parent to have
    completed (``result == "ok"``); ``always`` fires regardless.
    """
    raw_condition = edge.get("condition")
    if isinstance(raw_condition, dict):
        condition = str(raw_condition.get("expression") or raw_condition.get("condition") or "always")
    else:
        condition = str(raw_condition or "always")

    if condition.strip().lower() == "always":
        return True
    if parent_result is None or parent_result.get("result") != "ok":
        return False
    output = parent_result.get("output") or {}

    if _is_expression_condition(condition):
        return _evaluate_expression(condition, output)

    passed = bool(output.get("passed"))
    legacy = condition.lower()
    if legacy == "passed":
        return passed
    if legacy == "failed":
        return not passed
    return True


def _node_failure_reason(exc: Exception) -> str:
    """A safe, bounded failure category for a workflow node.

    The run log is returned to the caller at the HTTP boundary, and a raw
    exception string can carry internal filesystem paths, lake contents, or
    secret material. Only the exception class name — a code identifier, not
    runtime data — is surfaced, so an operator still sees the failure category
    without the engine leaking internals.
    """
    return f"node execution failed ({type(exc).__name__})"


def _append_run_record(lake_dir: str | Path, run: dict[str, Any]) -> None:
    path = _gold(lake_dir) / RUNS_FILE
    with chain_lock(path):
        append_jsonl(path, run)


def _workflow_execution_state(
    workflow: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, list[str]], list[str]]:
    nodes_by_id = {str(n.get("id")): n for n in workflow["nodes"]}
    edges: list[dict[str, Any]] = list(workflow.get("edges") or [])
    parents: dict[str, list[dict[str, Any]]] = {nid: [] for nid in nodes_by_id}
    incoming: dict[str, list[str]] = {nid: [] for nid in nodes_by_id}
    for edge in edges:
        src = str(edge.get("source"))
        dst = str(edge.get("target"))
        if dst in incoming:
            incoming[dst].append(src)
            parents[dst].append(edge)
    order = _topo_sort(nodes_by_id, incoming)
    return nodes_by_id, parents, incoming, order


def _execute_workflow_nodes(
    lake_dir: str | Path,
    workflow: dict[str, Any],
    *,
    dry_run: bool,
    start_after_node_id: str | None = None,
    initial_outputs: dict[str, dict[str, Any]] | None = None,
    initial_results: dict[str, dict[str, Any]] | None = None,
    initial_node_results: list[dict[str, Any]] | None = None,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> dict[str, Any]:
    nodes_by_id, parents, _incoming, order = _workflow_execution_state(workflow)
    node_results: list[dict[str, Any]] = list(initial_node_results or [])
    outputs_by_node = dict(initial_outputs or {})
    results_by_node = dict(initial_results or {})
    any_failed = any(entry.get("result") == "error" for entry in node_results)
    failed_nodes = {entry["node_id"] for entry in node_results if entry.get("result") == "error"}
    blocked = {entry["node_id"] for entry in node_results if entry.get("result") == "skipped"}
    started = start_after_node_id is None
    awaiting_approval = False
    pending_node_id: str | None = None

    for node_id in order:
        if not started:
            if node_id == start_after_node_id:
                started = True
            continue
        node = nodes_by_id[node_id]
        node_type = str(node.get("node_type") or "")
        raw_params = node.get("params") or {}
        skip_reason: str | None = None
        for edge in parents.get(node_id, []):
            parent_id = str(edge.get("source"))
            if parent_id in failed_nodes or parent_id in blocked:
                skip_reason = f"upstream node {parent_id} did not complete"
                blocked.add(node_id)
                break
        if skip_reason is None:
            for edge in parents.get(node_id, []):
                parent_id = str(edge.get("source"))
                parent_result = results_by_node.get(parent_id)
                if not _edge_allows(edge, parent_result):
                    condition = str(edge.get("condition") or "always")
                    skip_reason = f"edge from {parent_id} declined (condition={condition})"
                    break
        if skip_reason:
            entry = {
                "node_id": node_id,
                "node_type": node_type,
                "params": raw_params,
                "result": "skipped",
                "reason": skip_reason,
            }
            node_results.append(entry)
            results_by_node[node_id] = entry
            continue
        params = _substitute_variables(raw_params, outputs_by_node)
        result_entry: dict[str, Any] = {
            "node_id": node_id,
            "node_type": node_type,
            "params": params,
        }
        try:
            output = run_action(
                lake_dir, node_type=node_type, params=params, dry_run=dry_run, on_snapshot_written=on_snapshot_written
            )
            result_entry["result"] = "ok"
            result_entry["output"] = output
            outputs_by_node[node_id] = output
            if node_type == "gate.approval" and not dry_run and bool(output.get("awaiting_approval")):
                awaiting_approval = True
                pending_node_id = node_id
                node_results.append(result_entry)
                results_by_node[node_id] = result_entry
                for remaining_id in order[order.index(node_id) + 1 :]:
                    remaining = nodes_by_id[remaining_id]
                    skipped = {
                        "node_id": remaining_id,
                        "node_type": str(remaining.get("node_type") or ""),
                        "params": remaining.get("params") or {},
                        "result": "skipped",
                        "reason": f"awaiting approval at {node_id}",
                    }
                    node_results.append(skipped)
                    results_by_node[remaining_id] = skipped
                    blocked.add(remaining_id)
                break
        except Exception as exc:  # noqa: BLE001
            any_failed = True
            failed_nodes.add(node_id)
            result_entry["result"] = "error"
            result_entry["error"] = _node_failure_reason(exc)
        node_results.append(result_entry)
        results_by_node[node_id] = result_entry

    return {
        "node_results": node_results,
        "any_failed": any_failed,
        "awaiting_approval": awaiting_approval,
        "pending_node_id": pending_node_id,
    }


def run_workflow(
    lake_dir: str | Path,
    *,
    workflow_id: str,
    actor: str = "console",
    dry_run: bool = False,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> dict[str, Any]:
    """Execute every node in a workflow (topological order) and persist the run.

    Variable references ``{{nodeId.output.field}}`` in params are substituted
    from upstream node outputs before each action runs. Edges with
    ``condition: "passed"|"failed"`` — or an expression such as
    ``"output.matched_count > 0"`` (see :func:`_evaluate_expression`) — gate the
    target node based on the parent node's output.

    When ``dry_run=True`` the whole DAG is previewed safely: read-only checks and
    triggers run for real (so branching is realistic), but side-effecting actions
    (snapshot, assign_owner, webhook, slack, jira) skip their side effect and
    return a ``{"dry_run": True, "would": ...}`` preview instead. The persisted
    run record is marked ``dry_run: true``.

    ``on_snapshot_written``, when given, reaches any ``action.snapshot`` node in
    this run (see :func:`run_action`) — this is how a scheduler-fired workflow
    (:func:`security_lakehouse.scheduler.tick`) dispatches webhook events for a
    snapshot the same way an API-triggered one does. Resuming a paused run
    (``retry_workflow_run``/``approve_workflow_run``) does not thread this
    through yet -- a snapshot node reached only via resume does not dispatch
    webhooks in this slice.
    """
    if not in_server_mode() and actor not in _RUN_ACTORS:
        actor = "console"
    workflow = get_workflow(lake_dir, workflow_id)
    if workflow is None:
        raise ValueError(f"unknown workflow_id {workflow_id!r}")
    started_at = _utc_now_iso()
    execution = _execute_workflow_nodes(lake_dir, workflow, dry_run=dry_run, on_snapshot_written=on_snapshot_written)
    node_results = execution["node_results"]
    if execution["awaiting_approval"]:
        result = "awaiting_approval"
    elif execution["any_failed"]:
        result = "error"
    else:
        result = "ok"
    run = {
        "run_id": str(uuid.uuid4()),
        "workflow_id": workflow_id,
        "workflow_version": workflow["version"],
        "workflow_hash": canonical_sha256({"nodes": workflow["nodes"], "edges": workflow["edges"]}),
        "actor": actor,
        "dry_run": dry_run,
        "status": result,
        "result": result,
        "started_at": started_at,
        "finished_at": _utc_now_iso(),
        "node_results": node_results,
    }
    if execution["pending_node_id"]:
        run["pending_node_id"] = execution["pending_node_id"]
    _append_run_record(lake_dir, run)
    return run


def list_runs(lake_dir: str | Path, workflow_id: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
    history = _read_log(_gold(lake_dir) / RUNS_FILE)
    rows = list({str(row["run_id"]): row for row in history}.values())
    if workflow_id:
        rows = [r for r in rows if r.get("workflow_id") == workflow_id]
    rows.sort(key=lambda r: instant_sort_key(r.get("started_at")), reverse=True)
    return rows[:limit]


def get_workflow_run(lake_dir: str | Path, run_id: str) -> dict[str, Any] | None:
    for row in reversed(_read_log(_gold(lake_dir) / RUNS_FILE)):
        if str(row.get("run_id") or "") == run_id:
            return row
    return None


def retry_workflow_run(
    lake_dir: str | Path,
    *,
    run_id: str,
    actor: str = "console",
) -> dict[str, Any]:
    prior = get_workflow_run(lake_dir, run_id)
    if prior is None:
        raise ValueError(f"unknown run_id {run_id!r}")
    if str(prior.get("status") or "").endswith("_claimed") or prior.get("failure_code") == "outcome_unknown":
        raise ApprovalConflict("reconcile the interrupted decision before retrying")
    return run_workflow(
        lake_dir, workflow_id=str(prior["workflow_id"]), actor=actor, dry_run=bool(prior.get("dry_run"))
    )


class ApprovalConflict(ValueError):
    """An approval is stale, already consumed, or requires reconciliation."""


@contextmanager
def _decision_execution_lock(lake_dir: str | Path, run_id: str) -> Iterator[None]:
    # A process-owned lock disappears on exit; reconciliation cannot race a live
    # execution, even when another server process handles the request.
    lock_path = _gold(lake_dir) / "workflow_execution" / canonical_sha256(run_id)
    try:
        with chain_lock(lock_path, blocking=False):
            yield
    except BlockingIOError as exc:
        raise ApprovalConflict("workflow decision is still executing") from exc


def approve_workflow_run(
    lake_dir: str | Path, *, run_id: str, actor: str = "console", note: str = ""
) -> dict[str, Any]:
    with _decision_execution_lock(lake_dir, run_id):
        return _approve_workflow_run(lake_dir, run_id=run_id, actor=actor, note=note)


def reject_workflow_run(lake_dir: str | Path, *, run_id: str, actor: str = "console", note: str = "") -> dict[str, Any]:
    with _decision_execution_lock(lake_dir, run_id):
        return _reject_workflow_run(lake_dir, run_id=run_id, actor=actor, note=note)


def reconcile_workflow_run(lake_dir: str | Path, *, run_id: str, actor: str, note: str = "") -> dict[str, Any]:
    """Close an abandoned claim with an unknown outcome, never replay actions."""
    with _decision_execution_lock(lake_dir, run_id), chain_lock(_gold(lake_dir) / "workflow_approvals"):
        prior = get_workflow_run(lake_dir, run_id)
        if prior is None or not str(prior.get("status") or "").endswith("_claimed"):
            raise ApprovalConflict("only interrupted decision claims can be reconciled")
        if (
            not note.strip()
            or not actor.strip()
            or actor.casefold()
            in {
                "console",
                "api",
                "scheduler",
                str(prior.get("actor") or "").casefold(),
                str(prior.get("decision_actor") or "").casefold(),
            }
        ):
            raise ValueError("reconciliation requires an independent named reviewer and reason")
        result = {
            **prior,
            "status": "interrupted",
            "result": "interrupted",
            "failure_code": "outcome_unknown",
            "reconciled_by": actor,
            "reconciliation_note": note,
            "finished_at": _utc_now_iso(),
        }
        _append_run_record(lake_dir, result)
        return result


def _claim_workflow_decision(lake_dir: str | Path, run_id: str, actor: str, decision: str):
    # A separate lock spans lookup and durable claim; the run-log writer takes
    # its own lock. No external action runs until this claim has been fsynced.
    with chain_lock(_gold(lake_dir) / "workflow_approvals"):
        prior = get_workflow_run(lake_dir, run_id)
        if prior is None:
            raise ValueError(f"unknown run_id {run_id!r}")
        if in_server_mode() and decision == "approval":
            initiator = str(prior.get("actor") or "").casefold()
            if initiator in {"", "console", "api"}:
                raise ApprovalConflict("workflow initiator is unknown; start a new run for independent review")
            if initiator == actor.casefold():
                raise ApprovalConflict("workflow approval requires an independent reviewer")
        if (prior.get("status") or prior.get("result")) != "awaiting_approval":
            raise ApprovalConflict("run is not awaiting approval; reconcile an interrupted claim before retrying")
        workflow = get_workflow(lake_dir, str(prior["workflow_id"]))
        if (
            workflow is None
            or workflow["version"] != prior.get("workflow_version")
            or canonical_sha256({"nodes": workflow["nodes"], "edges": workflow["edges"]}) != prior.get("workflow_hash")
        ):
            raise ApprovalConflict("workflow version or content changed; start a new run for review")
        if not prior.get("pending_node_id"):
            raise ApprovalConflict("run is missing pending_node_id")
        _append_run_record(
            lake_dir,
            {
                **prior,
                "status": decision + "_claimed",
                "result": decision + "_claimed",
                "decision_actor": actor,
                "decision_at": _utc_now_iso(),
            },
        )
        return prior, workflow


def _approve_workflow_run(
    lake_dir: str | Path,
    *,
    run_id: str,
    actor: str = "console",
    note: str = "",
) -> dict[str, Any]:
    prior, workflow = _claim_workflow_decision(lake_dir, run_id, actor, "approval")
    pending_node_id = str(prior["pending_node_id"])
    outputs_by_node: dict[str, dict[str, Any]] = {}
    results_by_node: dict[str, dict[str, Any]] = {}
    for entry in prior.get("node_results") or []:
        node_id = str(entry.get("node_id") or "")
        results_by_node[node_id] = entry
        if entry.get("result") == "ok" and isinstance(entry.get("output"), dict):
            outputs_by_node[node_id] = entry["output"]
    if pending_node_id in results_by_node:
        gate_output = dict(results_by_node[pending_node_id].get("output") or {})
        gate_output["approved"] = True
        gate_output["approved_by"] = actor
        gate_output["approval_note"] = note
        gate_output["awaiting_approval"] = False
        results_by_node[pending_node_id]["output"] = gate_output
        outputs_by_node[pending_node_id] = gate_output
    prior_results = []
    for entry in prior.get("node_results") or []:
        node_id = str(entry.get("node_id") or "")
        if node_id == pending_node_id:
            prior_results.append(results_by_node[pending_node_id])
        elif str(entry.get("reason") or "").startswith("awaiting approval"):
            continue
        else:
            prior_results.append(entry)
    started_at = _utc_now_iso()
    execution = _execute_workflow_nodes(
        lake_dir,
        workflow,
        dry_run=False,
        start_after_node_id=pending_node_id,
        initial_outputs=outputs_by_node,
        initial_results=results_by_node,
        initial_node_results=prior_results,
    )
    node_results = execution["node_results"]
    if execution["awaiting_approval"]:
        result = "awaiting_approval"
    elif execution["any_failed"]:
        result = "error"
    else:
        result = "ok"
    run = {
        "run_id": str(uuid.uuid4()),
        "workflow_id": prior["workflow_id"],
        "workflow_version": workflow["version"],
        "workflow_hash": canonical_sha256({"nodes": workflow["nodes"], "edges": workflow["edges"]}),
        "actor": actor,
        "dry_run": False,
        "status": result,
        "result": result,
        "started_at": started_at,
        "finished_at": _utc_now_iso(),
        "node_results": node_results,
        "resumed_from_run_id": run_id,
        "approval_note": note,
    }
    if execution["pending_node_id"]:
        run["pending_node_id"] = execution["pending_node_id"]
    _append_run_record(lake_dir, run)
    _append_run_record(
        lake_dir,
        {
            **prior,
            "status": "approved",
            "result": "approved",
            "decision_actor": actor,
            "decision_at": _utc_now_iso(),
            "decision_run_id": run["run_id"],
        },
    )
    return run


def _reject_workflow_run(
    lake_dir: str | Path,
    *,
    run_id: str,
    actor: str = "console",
    note: str = "",
) -> dict[str, Any]:
    prior, _workflow = _claim_workflow_decision(lake_dir, run_id, actor, "rejection")
    run = {
        "run_id": str(uuid.uuid4()),
        "workflow_id": prior["workflow_id"],
        "workflow_version": prior.get("workflow_version"),
        "actor": actor,
        "dry_run": False,
        "status": "rejected",
        "result": "rejected",
        "started_at": _utc_now_iso(),
        "finished_at": _utc_now_iso(),
        "node_results": list(prior.get("node_results") or []),
        "rejected_from_run_id": run_id,
        "rejection_note": note,
    }
    _append_run_record(lake_dir, run)
    _append_run_record(
        lake_dir,
        {
            **prior,
            "status": "rejected",
            "result": "rejected",
            "decision_actor": actor,
            "decision_at": _utc_now_iso(),
            "decision_run_id": run["run_id"],
        },
    )
    return run


def _topo_sort(nodes_by_id: dict[str, dict], incoming: dict[str, list[str]]) -> list[str]:
    """Kahn's algorithm. Cycles fall back to insertion order so the run still attempts."""
    indeg = {nid: len(parents) for nid, parents in incoming.items()}
    ready = [nid for nid, n in indeg.items() if n == 0]
    order: list[str] = []
    seen: set[str] = set()
    # Outgoing index
    outgoing: dict[str, list[str]] = {nid: [] for nid in nodes_by_id}
    for child, parents in incoming.items():
        for parent in parents:
            if parent in outgoing:
                outgoing[parent].append(child)
    while ready:
        nid = ready.pop(0)
        if nid in seen:
            continue
        seen.add(nid)
        order.append(nid)
        for child in outgoing.get(nid, []):
            indeg[child] = max(0, indeg[child] - 1)
            if indeg[child] == 0:
                ready.append(child)
    # Append any cycle survivors so the workflow still runs partially.
    for nid in nodes_by_id:
        if nid not in seen:
            order.append(nid)
    return order
