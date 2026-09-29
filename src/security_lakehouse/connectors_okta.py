"""Okta identity-evidence collector.

The second connector with a real runner. It collects read-only identity
governance signals — user lifecycle state, MFA-factor enrollment, and the
org's authentication/MFA policies — and emits them in the lake's raw evidence
shape so they flow through the same validate -> write -> pipeline path the
``github-security`` runner uses.

Two clients sit behind one interface, mirroring ``repo_audit``:

* :class:`OktaClient` — authenticated ``urllib`` reads against the Okta
  management API with the API token in an ``Authorization: SSWS`` header.
* :class:`OktaFixtureClient` — reads ``users.json`` / ``factors.json`` /
  ``policies.json`` from a fixture directory so collection is fully testable
  in CI without a live Okta org.

The collector is strictly read-only and least-privilege: it only ever issues
GET requests against ``users``, ``users/{id}/factors``, and ``policies`` and
never mutates Okta state.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.ingestion import backoff
from security_lakehouse.io import read_json
from security_lakehouse.models import utc_iso

# Identity controls that exist in controls/catalog.json. Verified before wiring.
IDENTITY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15", "HIPAA-164.308(a)(4)"]
MFA_CONTROLS = ["SOC2-CC6.1", "HIPAA-164.308(a)(4)"]
POLICY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15"]

# Okta user lifecycle states that mean the account can authenticate. Anything
# else (STAGED, DEPROVISIONED, SUSPENDED, LOCKED_OUT, ...) is an access signal
# that an auditor should look at, so we surface it as ``open``.
ACTIVE_USER_STATUSES = {"ACTIVE", "PROVISIONED", "RECOVERY", "PASSWORD_EXPIRED"}

# Okta factor statuses that count as a real, usable MFA enrollment.
ENROLLED_FACTOR_STATUSES = {"ACTIVE"}

DEFAULT_TIMEOUT = 20
USER_PAGE_LIMIT = 200
# Safety cap so a misbehaving Link chain can't loop forever (200 rows/page).
MAX_PAGES = 1000


def _next_link(link_header: str) -> str | None:
    """Extract the ``rel="next"`` URL from an Okta ``Link`` response header."""
    for part in link_header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip().lstrip("<").rstrip(">").strip()
        rels = "".join(segments[1:]).replace(" ", "").replace('"', "")
        if "rel=next" in rels and url:
            return url
    return None


class OktaClient:
    """Authenticated, read-only Okta management API client."""

    def __init__(self, org_url: str, *, token: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.org_url = org_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def users(self) -> list[dict[str, Any]]:
        return self._json_list(f"{self.org_url}/api/v1/users?limit={USER_PAGE_LIMIT}")

    def factors(self, user_id: str) -> list[dict[str, Any]]:
        safe_id = urllib.parse.quote(str(user_id), safe="")
        return self._json_list(f"{self.org_url}/api/v1/users/{safe_id}/factors")

    def policies(self) -> list[dict[str, Any]]:
        return self._json_list(f"{self.org_url}/api/v1/policies?type=MFA_ENROLL")

    def logs(self, *, since: str | None = None) -> list[dict[str, Any]]:
        query = f"{self.org_url}/api/v1/logs?limit=100"
        if since:
            query = f"{query}&since={urllib.parse.quote(since)}"
        return self._json_list(query)

    def _json_list(self, url: str) -> list[dict[str, Any]]:
        # Okta cursor-paginates list endpoints via the Link header; follow
        # rel="next" to the end so large orgs collect complete evidence rather
        # than a silently-truncated first page.
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        for _ in range(MAX_PAGES):
            if not next_url:
                break
            request = urllib.request.Request(
                next_url,
                headers={
                    "accept": "application/json",
                    "authorization": f"SSWS {self.token}",
                    "user-agent": "trustops-security-data-lake",
                },
            )

            def _fetch_page(req: urllib.request.Request = request) -> tuple[Any, str]:
                # open_public re-validates every page URL — including the
                # server-supplied Link: rel="next" target and any 3xx redirect —
                # so a malicious org cannot pivot this SSWS-authenticated request
                # at an internal host after the boundary check passed.
                with netguard.open_public(req, timeout=self.timeout, label="okta org url") as resp:
                    return json.loads(resp.read().decode("utf-8")), resp.headers.get("Link", "")

            # Okta rate-limits with HTTP 429 + a Retry-After header; back off and
            # retry transient 429/5xx rather than failing the whole collection.
            payload, link_header = backoff.http_retry(_fetch_page)
            if not isinstance(payload, list):
                raise ValueError(f"Okta returned non-list JSON for {next_url}")
            items.extend(item for item in payload if isinstance(item, dict))
            next_url = _next_link(link_header)
        return items


class OktaFixtureClient:
    """Offline Okta client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, org_url: str = "https://fixture.okta.com") -> None:
        self.fixture = Path(fixture_dir)
        self.org_url = org_url.rstrip("/")

    def users(self) -> list[dict[str, Any]]:
        return self._read_list("users.json")

    def factors(self, user_id: str) -> list[dict[str, Any]]:
        payload = self._read("factors.json")
        if isinstance(payload, dict):
            items = payload.get(str(user_id), [])
            return [item for item in items if isinstance(item, dict)]
        # A flat list fixture: keep only factors that name this user.
        return [item for item in payload if isinstance(item, dict) and str(item.get("userId")) == str(user_id)]

    def policies(self) -> list[dict[str, Any]]:
        return self._read_list("policies.json")

    def logs(self, *, since: str | None = None) -> list[dict[str, Any]]:
        rows = self._read_list("logs.json")
        if not since:
            return rows
        return [row for row in rows if str(row.get("published") or "") > since]

    def _read(self, name: str) -> Any:
        path = self.fixture / name
        return read_json(path) if path.exists() else []

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        payload = self._read(name)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []


def collect_okta_evidence(
    client: OktaClient | OktaFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect normalized raw identity evidence from an Okta org.

    Emits, per collection:

    * one identity-access event per user (lifecycle state -> identity controls),
    * one MFA-enrollment event per user (factor status -> MFA controls),
    * one policy event per MFA-enrollment policy (-> policy controls).

    Every event passes :func:`security_lakehouse.validation.validate_raw_events`.
    """
    now = collected_at or datetime.now(UTC)
    org = _org_slug(client.org_url)
    rows: list[dict[str, Any]] = []

    users = client.users()
    for user in users:
        user_id = str(user.get("id") or "").strip()
        if not user_id:
            continue
        rows.append(_user_event(client.org_url, org, user, now, tenant_id))
        factors = _safe_factors(client, user_id)
        rows.append(_mfa_event(client.org_url, org, user_id, user, factors, now, tenant_id))

    for policy in client.policies():
        policy_id = str(policy.get("id") or "").strip()
        if not policy_id:
            continue
        rows.append(_policy_event(client.org_url, org, policy, now, tenant_id))

    return rows


def _user_event(
    org_url: str,
    org: str,
    user: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    user_id = str(user["id"])
    status = str(user.get("status") or "UNKNOWN").upper()
    profile = user.get("profile")
    if not isinstance(profile, dict):
        profile = {}
    login = profile.get("login") or profile.get("email")
    is_active = status in ACTIVE_USER_STATUSES
    evidence_ref = f"{org_url}/api/v1/users/{user_id}"
    return _event(
        org=org,
        org_url=org_url,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="identity_access",
        event_type="okta.identity.user_access",
        asset_id=f"okta:user:{user_id}",
        asset_type="identity_account",
        controls=IDENTITY_CONTROLS,
        # Lifecycle states that cannot authenticate are the noteworthy ones.
        status="observed" if is_active else "open",
        severity="info" if is_active else "low",
        evidence_ref=evidence_ref,
        attributes={
            "user_id": user_id,
            "login": login,
            "lifecycle_status": status,
            "can_authenticate": is_active,
            "created": user.get("created"),
            "last_login": user.get("lastLogin"),
            "status_changed": user.get("statusChanged"),
        },
    )


def _mfa_event(
    org_url: str,
    org: str,
    user_id: str,
    user: dict[str, Any],
    factors: list[dict[str, Any]],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    active_factors = [f for f in factors if str(f.get("status") or "").upper() in ENROLLED_FACTOR_STATUSES]
    enrolled = bool(active_factors)
    factor_types = sorted({str(f.get("factorType")) for f in active_factors if f.get("factorType")})
    lifecycle = str(user.get("status") or "UNKNOWN").upper()
    can_authenticate = lifecycle in ACTIVE_USER_STATUSES
    # An active account with no usable MFA factor is the finding worth raising.
    needs_mfa = can_authenticate and not enrolled
    evidence_ref = f"{org_url}/api/v1/users/{user_id}/factors"
    return _event(
        org=org,
        org_url=org_url,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="mfa_enrollment",
        event_type="okta.identity.mfa_enrollment",
        asset_id=f"okta:user:{user_id}",
        asset_type="identity_account",
        controls=MFA_CONTROLS,
        status="open" if needs_mfa else "pass",
        severity="high" if needs_mfa else "info",
        evidence_ref=evidence_ref,
        attributes={
            "user_id": user_id,
            "mfa_enrolled": enrolled,
            "active_factor_count": len(active_factors),
            "factor_types": factor_types,
            "lifecycle_status": lifecycle,
            "needs_mfa": needs_mfa,
        },
    )


def _policy_event(
    org_url: str,
    org: str,
    policy: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    policy_id = str(policy["id"])
    policy_status = str(policy.get("status") or "UNKNOWN").upper()
    active = policy_status == "ACTIVE"
    evidence_ref = f"{org_url}/api/v1/policies/{policy_id}"
    return _event(
        org=org,
        org_url=org_url,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="mfa_policy",
        dedupe_key=policy_id,
        event_type="okta.identity.mfa_policy",
        asset_id=f"okta:org:{org}",
        asset_type="identity_policy",
        controls=POLICY_CONTROLS,
        status="observed" if active else "open",
        severity="info" if active else "low",
        evidence_ref=evidence_ref,
        attributes={
            "policy_id": policy_id,
            "policy_name": policy.get("name"),
            "policy_type": policy.get("type"),
            "policy_status": policy_status,
            "is_active": active,
            "system": bool(policy.get("system")),
        },
    )


def _event(
    *,
    org: str,
    org_url: str,
    collected_at: datetime,
    tenant_id: str,
    signal: str,
    event_type: str,
    asset_id: str,
    asset_type: str,
    controls: list[str],
    status: str,
    severity: str,
    evidence_ref: str,
    attributes: dict[str, Any],
    dedupe_key: str | None = None,
) -> dict[str, Any]:
    stable = _stable_suffix(org=org, signal=signal, asset_id=asset_id, dedupe_key=dedupe_key)
    return {
        "event_id": f"okta-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "okta",
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": org,
            "environment": "prod",
            "org": org,
        },
        "severity": severity,
        "status": status,
        "controls": controls,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": evidence_ref,
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": attributes,
    }


def _safe_factors(client: OktaClient | OktaFixtureClient, user_id: str) -> list[dict[str, Any]]:
    try:
        return client.factors(user_id)
    except urllib.error.HTTPError:
        # A factor read that the token cannot authorize must not abort the run;
        # the MFA event records an unknown-enrollment signal instead.
        return []


def _org_slug(org_url: str) -> str:
    netloc = urllib.parse.urlparse(org_url).netloc or org_url
    return netloc.strip("/") or "okta"


def _stable_suffix(*, org: str, signal: str, asset_id: str, dedupe_key: str | None) -> str:
    """Build a deterministic connector-local id without hashing identity data.

    The pipeline computes the canonical raw evidence hash after collection. These
    IDs only need to be stable for connector upserts and evidence-room links.
    """
    seed = f"{org}:{signal}:{dedupe_key or asset_id}".lower()
    return stable_id_slug(seed, fallback="okta")


SYSTEM_LOG_CONTROLS = ["SOC2-CC6.1", "FEDRAMP-AC-7"]
FAILED_OUTCOMES = frozenset({"FAILURE", "FAIL"})


def collect_okta_system_log_evidence(
    client: OktaClient | OktaFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
    since: str | None = None,
) -> list[dict[str, Any]]:
    """Collect authentication events from the Okta System Log API."""
    moment = collected_at or datetime.now(UTC)
    org_url = client.org_url
    org = _org_slug(org_url)
    rows: list[dict[str, Any]] = []
    for entry in client.logs(since=since):
        event = _system_log_event(org=org, org_url=org_url, entry=entry, collected_at=moment, tenant_id=tenant_id)
        if event is not None:
            rows.append(event)
    return rows


def _system_log_event(
    *,
    org: str,
    org_url: str,
    entry: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any] | None:
    published = str(entry.get("published") or "").strip()
    if not published:
        return None
    event_type = str(entry.get("eventType") or "okta.system.log")
    outcome = entry.get("outcome")
    if not isinstance(outcome, dict):
        outcome = {}
    outcome_result = str(outcome.get("result") or "").upper()
    actor = entry.get("actor")
    if not isinstance(actor, dict):
        actor = {}
    actor_id = str(actor.get("id") or actor.get("alternateId") or "unknown")
    failed = outcome_result in FAILED_OUTCOMES
    status = "open" if failed else "observed"
    severity = "high" if failed else "info"
    uuid = str(entry.get("uuid") or published)
    return {
        "event_id": f"okta-log-{uuid}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": published,
        "source": "okta-system-log",
        "event_type": "okta.auth.event",
        "entity": {
            "asset_id": f"okta:actor:{actor_id}",
            "asset_type": "identity_session",
            "asset_owner": org,
            "environment": "prod",
            "org": org,
        },
        "severity": severity,
        "status": status,
        "controls": SYSTEM_LOG_CONTROLS,
        "evidence": {
            "evidence_id": f"ev-log-{uuid}",
            "evidence_ref": f"{org_url}/api/v1/logs/{uuid}",
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": {
            "okta_event_type": event_type,
            "display_message": entry.get("displayMessage"),
            "outcome_result": outcome_result or None,
            "actor_id": actor_id,
            "client_ip": (entry.get("client") or {}).get("ipAddress")
            if isinstance(entry.get("client"), dict)
            else None,
        },
    }
