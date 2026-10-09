"""Outbound event webhook signing + delivery (transport-agnostic, no DB).

GRC Lake's API is otherwise pull-only. A registered subscription (see
``db.webhooks``) lets a tenant receive a push the moment something happens —
a new finding, a completed assessment, a control transitioning to failing —
instead of polling. This module is the sending half: build the signed
envelope and POST it, with the same SSRF guard every other outbound egress
path in this codebase uses (:mod:`security_lakehouse.netguard`).

Signing follows the GitHub/Stripe convention: the raw JSON body is HMAC-SHA256
signed with the subscriber's registered secret, and the hex digest travels in
an ``X-GRC-Lake-Signature: sha256=<hex>`` header so a receiver can verify the
delivery actually came from this GRC Lake instance and was not tampered with
in transit. See ``docs/WEBHOOKS.md`` for the receiver-side verification code.

Delivery never raises: every failure (non-2xx, timeout, DNS, SSRF-blocked
target) is caught and returned as ``{"ok": False, ...}`` so a slow or dead
receiver can never fail the caller's write path. Retries once by default with
a short backoff, matching "at least one retry" — this is intentionally a
synchronous call, not a queue: the codebase has no background job worker
today, and adding one is out of scope for this slice (see docs/WEBHOOKS.md).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from typing import Any
from urllib.parse import urlsplit

from security_lakehouse import netguard
from security_lakehouse.runtime_environment import runtime_env

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_RETRIES = 1
DEFAULT_BACKOFF_SECONDS = 0.5

SIGNATURE_HEADER = "X-GRC-Lake-Signature"
EVENT_HEADER = "X-GRC-Lake-Event"
DELIVERY_HEADER = "X-GRC-Lake-Delivery"

# Optional, opt-in destination allowlist for webhook subscription deliveries.
#
# This is deliberately a *separate* control from the workflow engine's
# GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST (see workflows.py's action.webhook), and
# deliberately NOT deny-by-default the way that one is. That allowlist gates
# an admin-authored automation step POSTing to an admin-chosen target; this
# gates a *tenant's own* subscription registered to receive that tenant's own
# compliance events -- the GitHub/Stripe self-service webhook model, where a
# customer registers any endpoint they control without needing a platform
# operator to allowlist it first. Coupling the two (or defaulting this one to
# deny-all) would make every webhook subscription undeliverable out of the box
# for any operator who has not also configured workflow egress, for an
# unrelated feature. The SSRF guard (assert_url_is_public, below) already
# blocks the classic internal-metadata-service target regardless of this
# allowlist's state; this allowlist is an *additional*, opt-in restriction for
# operators who want to cap egress to specific approved destinations (e.g. an
# approved SIEM vendor's IP range) even among public addresses.
EGRESS_ALLOWLIST_ENV = "GRC_LAKE_WEBHOOK_EGRESS_ALLOWLIST"


def _backoff_sleep(seconds: float) -> None:
    """Indirection point so tests can monkeypatch the retry sleep to a no-op."""
    if seconds > 0:
        time.sleep(seconds)


def _load_egress_allowlist() -> set[str]:
    """Parse ``GRC_LAKE_WEBHOOK_EGRESS_ALLOWLIST`` into normalized host[:port] entries."""
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
    return host in allowlist or f"{host}:{port}" in allowlist


def _assert_egress_allowed(url: str) -> None:
    """SSRF guard, plus ``GRC_LAKE_WEBHOOK_EGRESS_ALLOWLIST`` when an operator has set one.

    Always enforces the public-IP SSRF guard. The allowlist is opt-in: an
    unset/empty value applies no further restriction (see the module docstring
    for why this differs from the workflow engine's deny-by-default egress
    control). Raises ``ValueError`` on any violation.
    """
    netguard.assert_url_is_public(url, label="webhook")
    allowlist = _load_egress_allowlist()
    if not allowlist:
        return
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not _host_is_allowlisted(host, port, allowlist):
        raise ValueError(f"webhook target host {host!r} is not in {EGRESS_ALLOWLIST_ENV}")


def _delivery_error(exc: BaseException) -> str:
    """Error text safe to store on a delivery record.

    Delivery records are readable by the tenant, and resolver and socket
    errors can carry the private address an internal hostname resolved to,
    so only a fixed reason reaches the record; the detail goes to the log.
    """
    logger.info("webhook delivery failed: %s: %s", type(exc).__name__, exc)
    if isinstance(exc, ValueError):
        message = str(exc)
        if "SSRF" in message:
            return "webhook target resolves to a non-public address (SSRF blocked)"
        if "did not resolve" in message:
            return "webhook target host did not resolve"
        if EGRESS_ALLOWLIST_ENV in message:
            return f"webhook target host is not in {EGRESS_ALLOWLIST_ENV}"
        return "webhook target URL was refused"
    return type(exc).__name__


def sign_payload(secret: str, body: bytes) -> str:
    """Return the ``sha256=<hex>`` signature a receiver can independently recompute."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    """Constant-time check that ``signature`` matches ``body`` signed with ``secret``."""
    expected = sign_payload(secret, body)
    return hmac.compare_digest(expected, signature)


def build_envelope(*, event_type: str, tenant_id: str, occurred_at: str, data: dict[str, Any]) -> dict[str, Any]:
    """The event envelope every delivery carries; ``event_id`` is the delivery's idempotency key."""
    return {
        "event": event_type,
        "event_id": str(uuid.uuid4()),
        "occurred_at": occurred_at,
        "tenant_id": tenant_id,
        "data": data,
    }


def deliver_webhook(
    url: str,
    *,
    secret: str,
    event_type: str,
    envelope: dict[str, Any],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
) -> dict[str, Any]:
    """POST ``envelope`` to ``url``, HMAC-signed with ``secret``. Never raises.

    Returns ``{"ok", "status_code", "attempts", "error"}``. A non-2xx response
    or a network/timeout error is retried up to ``max_retries`` additional
    times with a short backoff; a target that fails the SSRF guard or the
    optional ``GRC_LAKE_WEBHOOK_EGRESS_ALLOWLIST`` (see :func:`_assert_egress_allowed`)
    fails immediately without an attempt (there is nothing safe to retry).
    """
    body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: sign_payload(secret, body),
        EVENT_HEADER: event_type,
        DELIVERY_HEADER: envelope.get("event_id", ""),
        # Existing receivers keep their wire contract across the product rename.
        "X-TrustOps-Signature": sign_payload(secret, body),
        "X-TrustOps-Event": event_type,
        "X-TrustOps-Delivery": envelope.get("event_id", ""),
    }

    try:
        _assert_egress_allowed(url)
    except ValueError as exc:
        return {"ok": False, "status_code": None, "attempts": 0, "error": _delivery_error(exc)}

    attempts = 0
    last_error: str | None = None
    status_code: int | None = None
    max_retries = max(0, int(max_retries))
    for attempt in range(max_retries + 1):
        attempts = attempt + 1
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 (scheme + egress guarded above)
        try:
            # Re-validated on every redirect hop too, so an allowlisted target
            # cannot 302 a delivery to a non-allowlisted or non-public one.
            with netguard.open_guarded(
                request,
                timeout=timeout,
                validate=_assert_egress_allowed,
            ) as response:
                status_code = int(getattr(response, "status", 0) or 0)
                if 200 <= status_code < 300:
                    return {"ok": True, "status_code": status_code, "attempts": attempts, "error": None}
                last_error = f"HTTP {status_code}"
        except urllib.error.HTTPError as exc:
            status_code = int(exc.code)
            last_error = f"HTTP {status_code}"
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
            status_code = None
            last_error = _delivery_error(exc)
        if attempt < max_retries:
            _backoff_sleep(backoff_seconds * (2**attempt))

    return {"ok": False, "status_code": status_code, "attempts": attempts, "error": last_error}


__all__ = [
    "DELIVERY_HEADER",
    "EGRESS_ALLOWLIST_ENV",
    "EVENT_HEADER",
    "SIGNATURE_HEADER",
    "build_envelope",
    "deliver_webhook",
    "sign_payload",
    "verify_signature",
]
