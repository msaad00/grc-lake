"""KnowBe4 security-awareness training evidence collector.

Reads the KnowBe4 **Reporting API** (read-only; OpenAPI 3.0.1 spec served at
https://developer.knowbe4.com/elvis-swagger.yml, rendered at
https://developer.knowbe4.com/rest/reporting, retrieved 2026-09-27):

* ``GET /v1/users?status=active`` — active users (``id``, ``email``,
  ``employee_number``, ``phish_prone_percentage`` as a percentage, e.g. 14.235).
* ``GET /v1/training/enrollments?exclude_archived_users=true`` — enrollments with
  ``status`` one of ``Not Started``, ``In Progress``, ``Completed``, ``Passed``,
  ``Past Due``. The schema has no due-date field, so ``Past Due`` is the only
  overdue signal the API offers.
* ``GET /v1/phishing/security_tests`` — phishing security tests (PSTs) with
  ``phish_prone_percentage`` in decimal form (0.2 == 20%), ``started_at``,
  ``status`` and delivery/click counts.

Per the spec: base URL is regional (``https://{us,eu,ca,uk,de}.api.knowbe4.com``),
auth is ``Authorization: Bearer <Reporting API key>``, and usage is limited to
4 requests/second, a burst of 50 requests/minute, and 2,000 requests per day
plus the licensed-user count. The client paces requests to stay under the burst
limit and retries 429/5xx through ``backoff.http_retry``; a 429 that outlasts
that budget raises :class:`KnowBe4RateLimitedError` ("retry later").

Paging (spec re-checked 2026-10-07): ``page`` is deprecated from November 2026
in favour of ``per_page`` (max 500) and ``cursor``; "set cursor=0 or
cursor=true in your first request to begin pagination". The spec does not say
where the next cursor comes back, so the client:

1. starts with ``cursor=0&per_page=500`` and, while a ``Link: rel="next"``
   header carries a ``cursor``, follows it (cursor value only, host pinned);
2. treats a short or empty page without a next cursor as the last page;
3. on a full page without a next cursor, restarts with legacy ``page`` paging,
   which works until the deprecation; once the server ignores ``page`` and
   repeats rows, raises :class:`KnowBe4PaginationError` instead of storing
   duplicates. A repeated cursor raises the same error.

Every request goes through ``netguard.open_public`` to the configured regional
host only; the key is never sent anywhere else.

Data minimization: only the user id, primary email (the join key to
identity-provider and HRIS records, like Intune's UPN), and employee number are
kept. Names, job titles, phone numbers, locations, divisions, manager details,
aliases, and custom fields are dropped before anything is stored.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connector_errors import ConnectorAccessError
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.oauth import CredentialRejectedError
from security_lakehouse.ingestion.paginate import next_link_url, paginate
from security_lakehouse.io import read_json
from security_lakehouse.models import instant_sort_key, utc_iso

KNOWBE4_REGIONS: dict[str, str] = {
    "us": "us.api.knowbe4.com",
    "eu": "eu.api.knowbe4.com",
    "ca": "ca.api.knowbe4.com",
    "uk": "uk.api.knowbe4.com",
    "de": "de.api.knowbe4.com",
}
DEFAULT_TIMEOUT = 30
PER_PAGE = 500
# The spec: "Set cursor=0 or cursor=true in your first request to begin pagination."
START_CURSOR = "0"
# 50 requests/minute burst limit -> at most one request every 1.2 seconds.
MIN_REQUEST_INTERVAL_SECONDS = 1.25

# Phishing tests that started within this window feed the account summary.
PHISHING_LOOKBACK_DAYS = 90
# GRC Lake default, not a KnowBe4 benchmark: an aggregate phish-prone
# percentage at or above this is an open (low) finding.
PHISH_PRONE_THRESHOLD = 20.0

COMPLETED_STATUSES = {"completed", "passed"}
PAST_DUE_STATUS = "past due"
CANCELLED_TEST_STATUSES = {"canceled", "cancelled"}

# Controls verified to exist in controls/catalog.json.
TRAINING_CONTROLS = [
    "FEDRAMP-AT-2",
    "FEDRAMP-AT-4",
    "CMMC-3.2.1",
    "CMMC-3.2.2",
    "ISO27001-A.6.3",
    "NIST-CSF-PR.AT-01",
    "CIS-CONTROLS-14",
    "SOC2-CC1.4",
    "HIPAA-164.308(a)(5)",
]
PHISHING_CONTROLS = ["FEDRAMP-AT-2", "CMMC-3.2.1", "ISO27001-A.6.3", "NIST-CSF-PR.AT-01", "CIS-CONTROLS-14"]


class KnowBe4RateLimitedError(ConnectorAccessError):
    """KnowBe4 kept answering 429 past the shared backoff budget; retry the sync later."""


class KnowBe4PaginationError(ConnectorAccessError):
    """The Reporting API's paging cannot be completed safely; nothing partial is returned."""


class _NoNextCursorError(Exception):
    """A full cursor-mode page carried no next cursor."""


def _link_cursor(headers: Any) -> str | None:
    """The ``cursor`` query value of a ``Link: rel="next"`` target, if the response sends one.

    Only the cursor value is taken; the next request is rebuilt against the
    configured regional host and path, so a ``Link`` target cannot redirect the key.
    """
    link = str(headers.get("Link") or "") if headers is not None else ""
    url = next_link_url(link)
    if not url:
        return None
    values = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("cursor") or []
    cursor = values[0].strip() if values else ""
    return cursor or None


def region_host(region: str) -> str:
    key = str(region or "").strip().lower()
    if key not in KNOWBE4_REGIONS:
        raise ValueError(f"unknown KnowBe4 region {region!r}; expected one of {', '.join(sorted(KNOWBE4_REGIONS))}")
    return KNOWBE4_REGIONS[key]


class KnowBe4Client:
    """Read-only KnowBe4 Reporting API client for one regional host."""

    def __init__(
        self,
        region: str,
        *,
        token: str,
        timeout: int = DEFAULT_TIMEOUT,
        min_interval: float = MIN_REQUEST_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        self.region = str(region).strip().lower()
        self.host = region_host(self.region)
        if not token:
            raise ValueError("KnowBe4 Reporting API key is required")
        self._token = token
        self.timeout = timeout
        self._min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._last_request: float | None = None

    def users(self) -> list[dict[str, Any]]:
        return self._list("/v1/users", {"status": "active"})

    def training_enrollments(self) -> list[dict[str, Any]]:
        return self._list("/v1/training/enrollments", {"exclude_archived_users": "true"})

    def phishing_tests(self) -> list[dict[str, Any]]:
        # The endpoint has no date filter; collect_knowbe4_evidence keeps only
        # tests started inside PHISHING_LOOKBACK_DAYS.
        return self._list("/v1/phishing/security_tests", {})

    def _list(self, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
        try:
            return self._list_by_cursor(path, params)
        except _NoNextCursorError:
            # A full page came back without a next cursor, so cursor mode cannot
            # continue. Restart from page 1 rather than splice two orderings.
            return self._list_by_page(path, params)

    def _list_by_cursor(self, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
        seen: set[str] = set()

        def fetch_page(cursor: str | None) -> tuple[list[Any], str | None]:
            current = cursor or START_CURSOR
            seen.add(current)
            payload, headers = self._fetch(path, {**params, "per_page": PER_PAGE, "cursor": current})
            return payload, _link_cursor(headers)

        def extract_items(page: tuple[list[Any], str | None]) -> list[dict[str, Any]]:
            return [item for item in page[0] if isinstance(item, dict)]

        def next_cursor(page: tuple[list[Any], str | None]) -> str | None:
            rows, cursor = page
            if cursor is None:
                if len(rows) >= PER_PAGE:
                    raise _NoNextCursorError
                return None
            if cursor in seen:
                raise KnowBe4PaginationError(
                    "KnowBe4 Reporting API repeated a pagination cursor; stopped to avoid a loop. "
                    "Retry the sync, and report it to KnowBe4 support if it persists."
                )
            return cursor

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _list_by_page(self, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
        def fetch_page(page: int | None) -> tuple[int, list[Any]]:
            number = page or 1
            payload, _headers = self._fetch(path, {**params, "page": number, "per_page": PER_PAGE})
            return number, payload

        def extract_items(page: tuple[int, list[Any]]) -> list[dict[str, Any]]:
            return [item for item in page[1] if isinstance(item, dict)]

        previous: list[list[Any]] = []

        def next_cursor(page: tuple[int, list[Any]]) -> int | None:
            number, rows = page
            if previous and rows and rows == previous[0]:
                # Once ``page`` is retired the server can ignore it and repeat the
                # first rows; collecting them again would duplicate evidence.
                raise KnowBe4PaginationError(
                    "KnowBe4 Reporting API ignored page-based paging and returned no next cursor, "
                    "so the collection cannot be completed. The connector needs an update for "
                    "KnowBe4's cursor pagination response."
                )
            previous[:] = [rows]
            return number + 1 if len(rows) >= PER_PAGE else None

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _fetch(self, path: str, query: dict[str, Any]) -> tuple[list[Any], Any]:
        url = f"https://{self.host}{path}?{urllib.parse.urlencode(query)}"
        try:
            payload, headers = backoff.http_retry(lambda: self._get_json(url))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise KnowBe4RateLimitedError(
                    "KnowBe4 Reporting API rate limit reached (HTTP 429) and retries were exhausted. "
                    "KnowBe4 burst lockouts last about five minutes and the daily quota resets about "
                    "24 hours after the first request; retry the sync later."
                ) from None
            raise
        if not isinstance(payload, list):
            raise ValueError(f"KnowBe4 returned non-list JSON for {path}")
        return payload, headers

    def _pace(self) -> None:
        now = self._clock()
        if self._last_request is not None:
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                (self._sleep or time.sleep)(wait)
                now = self._clock()
        self._last_request = now

    def _get_json(self, url: str) -> tuple[Any, Any]:
        self._pace()
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self._token}",
                "user-agent": "grc-lake",
            },
        )
        try:
            with netguard.open_public(request, timeout=self.timeout, label="knowbe4 reporting api") as resp:
                return json.loads(resp.read().decode("utf-8")), getattr(resp, "headers", None)
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise CredentialRejectedError(
                    f"KnowBe4 Reporting API rejected the API key (HTTP {exc.code}); check credential_ref, "
                    "the account region, and that the key was generated in the Reporting API console"
                ) from None
            raise


class KnowBe4FixtureClient:
    """Offline KnowBe4 client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, region: str) -> None:
        self.fixture = Path(fixture_dir)
        self.region = str(region).strip().lower()
        self.host = region_host(self.region)

    def users(self) -> list[dict[str, Any]]:
        return [u for u in self._read("users.json") if str(u.get("status") or "active").lower() == "active"]

    def training_enrollments(self) -> list[dict[str, Any]]:
        return self._read("training_enrollments.json")

    def phishing_tests(self) -> list[dict[str, Any]]:
        return self._read("phishing_security_tests.json")

    def _read(self, name: str) -> list[dict[str, Any]]:
        path = self.fixture / name
        payload = read_json(path) if path.exists() else []
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []


def collect_knowbe4_evidence(
    client: KnowBe4Client | KnowBe4FixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Emit one training event per active user and one phishing summary event."""
    now = collected_at or datetime.now(UTC)
    users = {
        str(u.get("id")): u
        for u in client.users()
        if str(u.get("id") or "").strip() and str(u.get("status") or "active").lower() == "active"
    }
    enrollments: dict[str, list[dict[str, Any]]] = {user_id: [] for user_id in users}
    for enrollment in client.training_enrollments():
        user_id = str((enrollment.get("user") or {}).get("id") or "")
        if user_id in enrollments:
            enrollments[user_id].append(enrollment)

    rows = [
        _training_event(client, user_id, users[user_id], enrollments[user_id], now, tenant_id)
        for user_id in sorted(users)
    ]
    rows.append(_phishing_event(client, client.phishing_tests(), now, tenant_id))
    return rows


def _training_event(
    client: KnowBe4Client | KnowBe4FixtureClient,
    user_id: str,
    user: dict[str, Any],
    user_enrollments: list[dict[str, Any]],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    statuses = [str(e.get("status") or "").strip().lower() for e in user_enrollments]
    completed = sum(1 for s in statuses if s in COMPLETED_STATUSES)
    past_due = sum(1 for s in statuses if s == PAST_DUE_STATUS)
    if not statuses:
        status, severity, reason = "open", "medium", "not_enrolled"
    elif past_due:
        status, severity, reason = "open", "medium", "training_overdue"
    elif completed == len(statuses):
        status, severity, reason = "pass", "info", None
    else:
        status, severity, reason = "open", "low", "training_incomplete"
    completion_dates = [str(e["completion_date"]) for e in user_enrollments if e.get("completion_date")]
    attributes = {
        "user_id": user_id,
        "email": user.get("email"),
        "employee_number": user.get("employee_number"),
        "enrollment_count": len(statuses),
        "completed_count": completed,
        "past_due_count": past_due,
        "in_progress_count": sum(1 for s in statuses if s == "in progress"),
        "not_started_count": sum(1 for s in statuses if s == "not started"),
        "last_completion_date": max(completion_dates) if completion_dates else None,
        "phish_prone_percentage": user.get("phish_prone_percentage"),
        "finding_reason": reason,
    }
    return _event(
        region=client.region,
        stable_key=f"user:{user_id}",
        event_type="knowbe4.user.training",
        asset_id=f"knowbe4:user:{user_id}",
        asset_type="workforce_user",
        controls=TRAINING_CONTROLS,
        status=status,
        severity=severity,
        evidence_ref=f"https://{client.host}/v1/training/enrollments?user_id={urllib.parse.quote(user_id)}",
        attributes=attributes,
        collected_at=collected_at,
        tenant_id=tenant_id,
    )


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _phishing_event(
    client: KnowBe4Client | KnowBe4FixtureClient,
    tests: list[dict[str, Any]],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    window_start = collected_at - timedelta(days=PHISHING_LOOKBACK_DAYS)
    recent = []
    for test in tests:
        started = _parse_time(test.get("started_at"))
        if started is None or not window_start <= started <= collected_at:
            continue
        if str(test.get("status") or "").strip().lower() in CANCELLED_TEST_STATUSES:
            continue
        recent.append(test)

    delivered = sum(_count(t.get("delivered_count")) for t in recent)
    clicked = sum(_count(t.get("clicked_count")) for t in recent)
    percentage = _aggregate_phish_prone(recent)
    if not recent or percentage is None:
        status, severity, reason = "observed", "info", "no_recent_phishing_test"
    elif percentage >= PHISH_PRONE_THRESHOLD:
        status, severity, reason = "open", "low", "phish_prone_above_threshold"
    else:
        status, severity, reason = "pass", "info", None
    attributes = {
        "region": client.region,
        "lookback_days": PHISHING_LOOKBACK_DAYS,
        "test_count": len(recent),
        "delivered_count": delivered,
        "clicked_count": clicked,
        "phish_prone_percentage": percentage,
        "phish_prone_threshold": PHISH_PRONE_THRESHOLD,
        "latest_test_started_at": max((str(t.get("started_at")) for t in recent), key=instant_sort_key, default=None),
        "finding_reason": reason,
    }
    return _event(
        region=client.region,
        stable_key="phishing-summary",
        event_type="knowbe4.phishing.summary",
        asset_id=f"knowbe4:account:{client.region}",
        asset_type="security_awareness_program",
        controls=PHISHING_CONTROLS,
        status=status,
        severity=severity,
        evidence_ref=f"https://{client.host}/v1/phishing/security_tests",
        attributes=attributes,
        collected_at=collected_at,
        tenant_id=tenant_id,
    )


def _count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _aggregate_phish_prone(tests: list[dict[str, Any]]) -> float | None:
    """Delivery-weighted phish-prone percentage (0-100) across tests.

    PST ``phish_prone_percentage`` is a decimal (0.2 == 20%). Tests with no
    deliveries are averaged unweighted only if no test has deliveries.
    """
    rated = [t for t in tests if isinstance(t.get("phish_prone_percentage"), (int, float))]
    if not rated:
        return None
    weighted = [(float(t["phish_prone_percentage"]), _count(t.get("delivered_count"))) for t in rated]
    total = sum(weight for _, weight in weighted)
    if total:
        value = sum(ppp * weight for ppp, weight in weighted) / total
    else:
        value = sum(ppp for ppp, _ in weighted) / len(weighted)
    return round(value * 100, 2)


def _event(
    *,
    region: str,
    stable_key: str,
    event_type: str,
    asset_id: str,
    asset_type: str,
    controls: list[str],
    status: str,
    severity: str,
    evidence_ref: str,
    attributes: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    stable = stable_id_slug(f"{region}:{stable_key}", fallback="knowbe4")
    return {
        "event_id": f"knowbe4-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "knowbe4",
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": f"knowbe4-{region}",
            "environment": "prod",
            "org": f"knowbe4-{region}",
        },
        "severity": severity,
        "status": status,
        "controls": list(controls),
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": evidence_ref,
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": attributes,
    }
