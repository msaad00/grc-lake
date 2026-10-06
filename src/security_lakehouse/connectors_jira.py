"""Jira ticketing/workflow-evidence collector.

A workflow connector with a real runner. It collects read-only remediation and
governance workflow signals — security/governance tickets, their lifecycle
status, assignee/owner, and SLA/due-date fields, plus the projects that hold
them — and emits them in the lake's raw evidence shape so they flow through the
same validate -> write -> pipeline path the ``github-security``, ``okta-identity``
and ``aws-posture`` runners use.

Two clients sit behind one interface, mirroring ``connectors_okta``:

* :class:`JiraClient` — authenticated ``urllib`` reads against the Jira Cloud
  REST API. Authentication is HTTP Basic with an account email plus an API
  token (the standard Jira Cloud read auth), and the collector only ever issues
  GET reads against ``search`` and ``project``.
* :class:`JiraFixtureClient` — reads ``issues.json`` / ``projects.json`` from a
  fixture directory so collection is fully testable in CI without a live Jira
  site.

The collector is strictly read-only and least-privilege: it only ever issues
GET requests against the issue search and project endpoints and never mutates
Jira state (no transitions, comments, or writes).
"""

from __future__ import annotations

import base64
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

# Workflow controls that exist in controls/catalog.json. Verified before wiring
# (SOC2-CC7.2 incident response/operations, ISO27001-A.8.16 monitoring
# activities, HIPAA-164.308(a)(1)(ii)(B) risk management/remediation).
TICKET_CONTROLS = ["SOC2-CC7.2", "ISO27001-A.8.16", "HIPAA-164.308(a)(1)(ii)(B)"]
PROJECT_CONTROLS = ["SOC2-CC7.2", "ISO27001-A.8.16"]
TRANSITION_CONTROLS = ["SOC2-CC7.2", "HIPAA-164.308(a)(1)(ii)(B)"]

# Jira status categories that mean a remediation ticket is finished. Anything
# else is still-open work an auditor should be able to see and age against SLA.
DONE_STATUS_CATEGORIES = {"done", "complete", "completed", "resolved", "closed"}

# Default JQL that scopes collection to governance/security remediation work
# rather than the whole backlog. The live client passes this to the read-only
# search endpoint; callers can override it.
DEFAULT_JQL = 'labels in ("security", "governance", "remediation") ORDER BY updated DESC'

DEFAULT_TIMEOUT = 20
SEARCH_PAGE_LIMIT = 100
# Safety cap on pages so a bad total/isLast response can't loop forever.
MAX_PAGES = 1000


class JiraClient:
    """Authenticated, read-only Jira Cloud REST client.

    Authentication is HTTP Basic with ``email:api_token`` base64-encoded, the
    standard Jira Cloud read scheme. The client only issues GET requests against
    the issue search and project list endpoints and never mutates Jira state.
    """

    def __init__(
        self,
        base_url: str,
        *,
        email: str,
        token: str,
        jql: str = DEFAULT_JQL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.token = token
        self.jql = jql
        self.timeout = timeout

    def issues(self) -> list[dict[str, Any]]:
        # Jira search is startAt/total paginated; loop to the end so large
        # backlogs collect complete evidence instead of a truncated first page.
        out: list[dict[str, Any]] = []
        start = 0
        for _ in range(MAX_PAGES):
            query = urllib.parse.urlencode(
                {
                    "jql": self.jql,
                    "startAt": start,
                    "maxResults": SEARCH_PAGE_LIMIT,
                    "fields": "summary,status,assignee,duedate,labels,priority,project,updated,created",
                }
            )
            payload = self._json(f"{self.base_url}/rest/api/3/search?{query}")
            issues = payload.get("issues")
            if not isinstance(issues, list):
                raise ValueError("Jira returned no issues array for the search query")
            out.extend(item for item in issues if isinstance(item, dict))
            total = payload.get("total")
            start += len(issues)
            if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                raise ValueError("Jira collection incomplete: missing pagination total")
            if start >= total:
                break
            if not issues:
                raise ValueError("Jira collection incomplete: premature empty page")
        else:
            raise ValueError("Jira collection incomplete: pagination limit reached")
        return out

    def projects(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        start = 0
        for _ in range(MAX_PAGES):
            payload = self._json(
                f"{self.base_url}/rest/api/3/project/search?startAt={start}&maxResults={SEARCH_PAGE_LIMIT}"
            )
            values = payload.get("values")
            if not isinstance(values, list):
                raise ValueError("Jira returned no project values for the project search")
            out.extend(item for item in values if isinstance(item, dict))
            start += len(values)
            total = payload.get("total")
            if payload.get("isLast") is True or (isinstance(total, int) and start >= total):
                break
            if not values:
                raise ValueError("Jira collection incomplete: premature empty page")
        else:
            raise ValueError("Jira collection incomplete: pagination limit reached")
        return out

    def _json(self, url: str) -> dict[str, Any]:
        basic = base64.b64encode(f"{self.email}:{self.token}".encode()).decode("ascii")
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Basic {basic}",
                "user-agent": "trustops-security-data-lake",
            },
        )

        # Jira rate-limits with HTTP 429 + a Retry-After header; back off and
        # retry transient 429/5xx rather than failing the whole collection.
        def _fetch() -> Any:
            with netguard.open_public(request, timeout=self.timeout, label="jira base url") as resp:
                return json.loads(resp.read().decode("utf-8"))

        payload = backoff.http_retry(_fetch)
        if isinstance(payload, dict):
            return payload
        raise ValueError(f"Jira returned non-object JSON for {url}")


class JiraFixtureClient:
    """Offline Jira client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, base_url: str = "https://fixture.atlassian.net") -> None:
        self.fixture = Path(fixture_dir)
        self.base_url = base_url.rstrip("/")

    def issues(self) -> list[dict[str, Any]]:
        return self._read_list("issues.json")

    def projects(self) -> list[dict[str, Any]]:
        return self._read_list("projects.json")

    def _read(self, name: str) -> Any:
        path = self.fixture / name
        return read_json(path) if path.exists() else []

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        payload = self._read(name)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []


def collect_jira_evidence(
    client: JiraClient | JiraFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect normalized raw workflow evidence from a Jira site.

    Emits, per collection:

    * one ticket event per governance/security issue (lifecycle status +
      SLA/due-date -> ticket controls),
    * one transition event per issue (current status-category transition state
      -> transition controls),
    * one project event per workflow project (-> project controls).

    Every event passes :func:`security_lakehouse.validation.validate_raw_events`.
    """
    now = collected_at or datetime.now(UTC)
    site = _site_slug(client.base_url)
    rows: list[dict[str, Any]] = []

    for issue in client.issues():
        key = str(issue.get("key") or "").strip()
        if not key:
            continue
        fields = issue.get("fields")
        if not isinstance(fields, dict):
            fields = {}
        rows.append(_ticket_event(client.base_url, site, key, fields, now, tenant_id))
        rows.append(_transition_event(client.base_url, site, key, fields, now, tenant_id))

    for project in client.projects():
        project_key = str(project.get("key") or "").strip()
        if not project_key:
            continue
        rows.append(_project_event(client.base_url, site, project, now, tenant_id))

    return rows


def _ticket_event(
    base_url: str,
    site: str,
    key: str,
    fields: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    status_name, category = _status(fields)
    is_done = category in DONE_STATUS_CATEGORIES
    assignee = _assignee(fields)
    due_date = fields.get("duedate")
    # An open remediation ticket that is unassigned or past its SLA due date is
    # the finding worth raising; a resolved ticket is observed evidence.
    overdue = (not is_done) and _is_overdue(due_date, collected_at)
    unassigned = (not is_done) and not assignee
    needs_attention = overdue or unassigned
    evidence_ref = f"{base_url}/rest/api/3/issue/{key}"
    return _event(
        site=site,
        base_url=base_url,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="workflow_ticket",
        dedupe_key=key,
        event_type="jira.workflow.ticket",
        asset_id=f"jira:issue:{key}",
        asset_type="workflow_ticket",
        controls=TICKET_CONTROLS,
        status="pass" if is_done else ("open" if needs_attention else "observed"),
        severity=_ticket_severity(is_done, needs_attention),
        evidence_ref=evidence_ref,
        attributes={
            "issue_key": key,
            "summary": fields.get("summary"),
            "status": status_name,
            "status_category": category,
            "is_done": is_done,
            "assignee": assignee,
            "is_assigned": bool(assignee),
            "due_date": due_date,
            "is_overdue": overdue,
            "priority": _priority(fields),
            "labels": _labels(fields),
            "project_key": _project_key(fields),
            "updated": fields.get("updated"),
            "created": fields.get("created"),
        },
    )


def _transition_event(
    base_url: str,
    site: str,
    key: str,
    fields: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    status_name, category = _status(fields)
    is_done = category in DONE_STATUS_CATEGORIES
    # The transition signal records where the ticket currently sits in its
    # lifecycle so the lake can age in-progress remediation work over time.
    in_progress = (not is_done) and category in {"indeterminate", "in progress", "in-progress"}
    evidence_ref = f"{base_url}/rest/api/3/issue/{key}/transitions"
    return _event(
        site=site,
        base_url=base_url,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="workflow_transition",
        dedupe_key=key,
        event_type="jira.workflow.transition",
        asset_id=f"jira:issue:{key}",
        asset_type="workflow_transition",
        controls=TRANSITION_CONTROLS,
        status="observed" if is_done else "open",
        severity="info" if is_done else "low",
        evidence_ref=evidence_ref,
        attributes={
            "issue_key": key,
            "status": status_name,
            "status_category": category,
            "is_done": is_done,
            "in_progress": in_progress,
            "project_key": _project_key(fields),
        },
    )


def _project_event(
    base_url: str,
    site: str,
    project: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    project_key = str(project["key"])
    archived = bool(project.get("archived"))
    lead = project.get("lead")
    lead_name = lead.get("displayName") if isinstance(lead, dict) else lead
    evidence_ref = f"{base_url}/rest/api/3/project/{project_key}"
    return _event(
        site=site,
        base_url=base_url,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="workflow_project",
        dedupe_key=project_key,
        event_type="jira.workflow.project",
        asset_id=f"jira:project:{project_key}",
        asset_type="workflow_project",
        controls=PROJECT_CONTROLS,
        status="open" if archived else "observed",
        severity="low" if archived else "info",
        evidence_ref=evidence_ref,
        attributes={
            "project_key": project_key,
            "project_name": project.get("name"),
            "project_type": project.get("projectTypeKey"),
            "lead": lead_name,
            "is_archived": archived,
        },
    )


def _event(
    *,
    site: str,
    base_url: str,
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
    stable = _stable_suffix(site=site, signal=signal, asset_id=asset_id, dedupe_key=dedupe_key)
    return {
        "event_id": f"jira-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "jira",
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": site,
            "environment": "prod",
            "org": site,
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


def _status(fields: dict[str, Any]) -> tuple[str, str]:
    status = fields.get("status")
    if not isinstance(status, dict):
        status = {}
    name = str(status.get("name") or "UNKNOWN")
    category_obj = status.get("statusCategory")
    if not isinstance(category_obj, dict):
        category_obj = {}
    category = str(category_obj.get("key") or category_obj.get("name") or "unknown").strip().lower()
    return name, category


def _assignee(fields: dict[str, Any]) -> str | None:
    assignee = fields.get("assignee")
    if isinstance(assignee, dict):
        return assignee.get("displayName") or assignee.get("emailAddress") or assignee.get("accountId")
    return assignee if isinstance(assignee, str) else None


def _priority(fields: dict[str, Any]) -> str | None:
    priority = fields.get("priority")
    if isinstance(priority, dict):
        return priority.get("name")
    return priority if isinstance(priority, str) else None


def _labels(fields: dict[str, Any]) -> list[str]:
    labels = fields.get("labels")
    if isinstance(labels, list):
        return [str(label) for label in labels]
    return []


def _project_key(fields: dict[str, Any]) -> str | None:
    project = fields.get("project")
    if isinstance(project, dict):
        return project.get("key")
    return project if isinstance(project, str) else None


def _ticket_severity(is_done: bool, needs_attention: bool) -> str:
    if is_done:
        return "info"
    return "medium" if needs_attention else "low"


def _is_overdue(due_date: Any, collected_at: datetime) -> bool:
    if not isinstance(due_date, str) or not due_date.strip():
        return False
    try:
        due = datetime.fromisoformat(due_date.strip())
    except ValueError:
        return False
    if due.tzinfo is None:
        due = due.replace(tzinfo=UTC)
    return due.date() < collected_at.astimezone(UTC).date()


def _site_slug(base_url: str) -> str:
    netloc = urllib.parse.urlparse(base_url).netloc or base_url
    return netloc.strip("/") or "jira"


def _stable_suffix(*, site: str, signal: str, asset_id: str, dedupe_key: str | None) -> str:
    """Build a deterministic connector-local id without hashing workflow data.

    The pipeline computes the canonical raw evidence hash after collection. These
    IDs only need to be stable for connector upserts and evidence-room links.
    """
    seed = f"{site}:{signal}:{dedupe_key or asset_id}".lower()
    return stable_id_slug(seed, fallback="jira")
