"""Authenticated repository governance evidence collector.

The public repo audit records what can be seen without credentials. This module
collects private/org-only governance signals when a GitHub App installation
token, GitLab access token, or fixture is available and emits the same raw
evidence shape.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from security_lakehouse import netguard
from security_lakehouse.ingestion import backoff
from security_lakehouse.io import read_json, write_jsonl
from security_lakehouse.models import utc_iso
from security_lakehouse.secret_refs import resolve_ref_or_default

# Runaway guard for page-number pagination, matched to the shared paginator so a
# repo with thousands of alerts is not silently truncated.
_MAX_PAGES = 1000


def _guarded_request(request: urllib.request.Request, *, timeout: int, label: str) -> object:
    """Perform a read-only GET through the SSRF guard, with transient-error retry.

    Routes through ``netguard.open_public`` — same as every other HTTP connector —
    so a redirect from the configured host cannot pivot the request (or its bearer
    token) at an internal address, and a base URL supplied via env/spec is still
    boundary-checked on every hop. Retries 429/5xx (honoring ``Retry-After``); a
    ``204`` keeps its ``{"enabled": True}`` contract.
    """

    def _fetch() -> object:
        with netguard.open_public(request, timeout=timeout, label=label) as resp:
            if getattr(resp, "status", None) == 204:
                return {"enabled": True}
            return json.loads(resp.read().decode("utf-8"))

    return backoff.http_retry(_fetch)


GITHUB_RE = re.compile(r"^(?:https://github\.com/)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")
GITLAB_RE = re.compile(
    r"^(?:https?://(?:[\w.-]+\.)?gitlab\.com/)?(?P<path>[\w./-]+?)(?:\.git)?/?$",
)

CONTROL_MAP = {
    "branch_protection": ["SOC2-CC6.1", "ISO27001-A.5.15", "PCI-DSS-7"],
    "collaborators": ["SOC2-CC6.1", "ISO27001-A.5.15"],
    "teams": ["SOC2-CC6.1", "ISO27001-A.5.15"],
    "workflow_permissions": ["SOC2-CC7.2", "ISO27001-A.8.16"],
    "security_settings": ["SOC2-CC7.2", "PCI-DSS-11", "GDPR-Art.32"],
    "security_findings": ["SOC2-CC7.2", "PCI-DSS-11", "ISO27001-A.8.16"],
}

GITHUB_READ_ONLY_SCOPES = [
    "metadata:read",
    "administration:read",
    "code_scanning_alerts:read",
    "secret_scanning_alerts:read",
    "dependabot_alerts:read",
]
GITLAB_READ_ONLY_SCOPES = ["read_api", "read_repository", "read_user", "read_registry"]


@dataclass(frozen=True)
class GovernanceRepoSpec:
    provider: str
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        if self.provider == "gitlab" and "/" in self.owner:
            return f"{self.owner}/{self.repo}"
        if self.provider == "gitlab":
            return f"{self.owner}/{self.repo}"
        return f"{self.owner}/{self.repo}"

    @property
    def asset_id(self) -> str:
        return f"{self.provider}:repo:{self.slug}"


class GovernanceClient(Protocol):
    def repo(self) -> dict[str, Any]:
        pass

    def branch_protection(self, branch: str) -> dict[str, Any] | list[dict[str, Any]]:
        pass

    def collaborators(self) -> list[dict[str, Any]]:
        pass

    def teams(self) -> list[dict[str, Any]]:
        pass

    def workflow_permissions(self) -> dict[str, Any]:
        pass

    def vulnerability_alerts(self) -> dict[str, Any]:
        pass

    def security_findings(self) -> dict[str, Any]:
        pass


def parse_governance_repo_spec(value: str, *, provider: str | None = None) -> GovernanceRepoSpec:
    raw = value.strip()
    detected = provider
    if detected is None:
        lowered = raw.lower()
        if "gitlab" in lowered:
            detected = "gitlab"
        elif "github" in lowered:
            detected = "github"
        else:
            detected = "github"
    if detected == "gitlab":
        match = GITLAB_RE.match(raw)
        if not match:
            raise ValueError("repo must be a GitLab URL or NAMESPACE/PROJECT")
        parts = [part for part in match.group("path").split("/") if part]
        if len(parts) < 2:
            raise ValueError("GitLab repo must include namespace and project")
        return GovernanceRepoSpec(provider="gitlab", owner="/".join(parts[:-1]), repo=parts[-1])
    match = GITHUB_RE.match(raw)
    if not match:
        raise ValueError("repo must be a GitHub URL or OWNER/REPO")
    return GovernanceRepoSpec(provider="github", owner=match.group("owner"), repo=match.group("repo"))


class GitHubGovernanceClient:
    def __init__(self, spec: GovernanceRepoSpec, *, token: str) -> None:
        self.spec = spec
        self.token = token

    def repo(self) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}")

    def branch_protection(self, branch: str) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}/branches/{branch}/protection")

    def collaborators(self) -> list[dict[str, Any]]:
        return self._json_list(f"https://api.github.com/repos/{self.spec.slug}/collaborators?per_page=100")

    def teams(self) -> list[dict[str, Any]]:
        return self._json_list(f"https://api.github.com/repos/{self.spec.slug}/teams?per_page=100")

    def workflow_permissions(self) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}/actions/permissions/workflow")

    def vulnerability_alerts(self) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}/vulnerability-alerts")

    def security_findings(self) -> dict[str, Any]:
        base = f"https://api.github.com/repos/{self.spec.slug}"
        return {
            "code_scanning": _safe_call(lambda: self._json_list_paginated(f"{base}/code-scanning/alerts")),
            "secret_scanning": _safe_call(lambda: self._json_list_paginated(f"{base}/secret-scanning/alerts")),
            "dependabot": _safe_call(lambda: self._json_list_paginated(f"{base}/dependabot/alerts")),
        }

    def _json(self, url: str) -> dict[str, Any]:
        payload = self._request(url)
        if isinstance(payload, dict):
            return payload
        raise ValueError(f"GitHub returned non-object JSON for {url}")

    def _json_list(self, url: str) -> list[dict[str, Any]]:
        payload = self._request(url)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        raise ValueError(f"GitHub returned non-list JSON for {url}")

    def _json_list_paginated(self, url: str, *, max_pages: int = _MAX_PAGES) -> list[dict[str, Any]]:
        """Read a paginated GitHub list endpoint without silently truncating.

        ``max_pages`` is a runaway guard, not an expected ceiling — matched to the
        shared paginator so a repo with thousands of alerts is not dropped at 1000.
        """
        rows: list[dict[str, Any]] = []
        separator = "&" if "?" in url else "?"
        for page in range(1, max_pages + 1):
            payload = self._request(f"{url}{separator}per_page=100&page={page}")
            if not isinstance(payload, list):
                raise ValueError(f"GitHub returned non-list JSON for {url}")
            page_rows = [item for item in payload if isinstance(item, dict)]
            rows.extend(page_rows)
            if len(payload) < 100:
                break
        return rows

    def _request(self, url: str) -> object:
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/vnd.github+json",
                "authorization": f"Bearer {self.token}",
                "user-agent": "trustops-security-data-lake",
            },
        )
        return _guarded_request(request, timeout=20, label="github api")


class GitLabGovernanceClient:
    def __init__(self, spec: GovernanceRepoSpec, *, token: str, base_url: str | None = None) -> None:
        self.spec = spec
        self.token = token
        self.api_base = (base_url or os.environ.get("TRUSTOPS_GITLAB_API_URL", "https://gitlab.com/api/v4")).rstrip("/")
        self.project_id = urllib.parse.quote(self.spec.slug, safe="")

    def repo(self) -> dict[str, Any]:
        project = self._json(f"{self.api_base}/projects/{self.project_id}")
        return {
            "default_branch": project.get("default_branch") or "main",
            "full_name": project.get("path_with_namespace") or self.spec.slug,
            "name": project.get("name") or self.spec.repo,
            "private": project.get("visibility") != "public",
            "visibility": project.get("visibility") or "private",
            "project_id": project.get("id"),
        }

    def branch_protection(self, branch: str) -> dict[str, Any]:
        branches = self._json_list(f"{self.api_base}/projects/{self.project_id}/protected_branches")
        match = next((item for item in branches if str(item.get("name")) == branch), None)
        if match is None:
            return {
                "available": False,
                "requires_scope_or_permission": True,
                "reason": f"no protected branch rule for {branch}",
            }
        return _normalize_gitlab_branch_protection(match)

    def collaborators(self) -> list[dict[str, Any]]:
        members = self._json_list(f"{self.api_base}/projects/{self.project_id}/members/all")
        return [
            {
                "login": item.get("username") or item.get("name") or "unknown",
                "role_name": _gitlab_access_label(int(item.get("access_level") or 0)),
                "permissions": {"access_level": item.get("access_level")},
            }
            for item in members
        ]

    def teams(self) -> list[dict[str, Any]]:
        groups = self._json_list(f"{self.api_base}/projects/{self.project_id}/groups")
        return [
            {
                "name": item.get("full_name") or item.get("name") or "unknown",
                "permission": _gitlab_access_label(int(item.get("group_access_level") or 0)),
                "privacy": item.get("visibility") or "private",
            }
            for item in groups
        ]

    def workflow_permissions(self) -> dict[str, Any]:
        project = self._json(f"{self.api_base}/projects/{self.project_id}")
        restricted = bool(project.get("restrict_user_defined_variables"))
        return {
            "default_workflow_permissions": "read" if restricted else "write",
            "can_approve_pull_request_reviews": bool(project.get("only_allow_merge_if_all_discussions_are_resolved")),
            "only_allow_merge_if_pipeline_succeeds": bool(project.get("only_allow_merge_if_pipeline_succeeds")),
        }

    def vulnerability_alerts(self) -> dict[str, Any]:
        project = self._json(f"{self.api_base}/projects/{self.project_id}")
        enabled = bool(project.get("security_and_compliance_enabled"))
        return {"enabled": enabled, "security_and_compliance_enabled": enabled}

    def security_findings(self) -> dict[str, Any]:
        # GitLab exposes vulnerability detail through tier- and permission-dependent
        # APIs. Keep this signal honest until a stable read contract is configured.
        return {
            "available": False,
            "requires_scope_or_permission": True,
            "reason": "GitLab vulnerability findings require a supported security tier and API scope",
        }

    def _json(self, url: str) -> dict[str, Any]:
        payload = self._request(url)
        if isinstance(payload, dict):
            return payload
        raise ValueError(f"GitLab returned non-object JSON for {url}")

    def _json_list(self, url: str) -> list[dict[str, Any]]:
        payload = self._request(url)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        raise ValueError(f"GitLab returned non-list JSON for {url}")

    def _request(self, url: str) -> object:
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "private-token": self.token,
                "user-agent": "trustops-security-data-lake",
            },
        )
        return _guarded_request(request, timeout=20, label="gitlab api")


def _gitlab_access_label(level: int) -> str:
    if level >= 50:
        return "owner"
    if level >= 40:
        return "maintainer"
    if level >= 30:
        return "developer"
    if level >= 20:
        return "reporter"
    return "guest"


def _normalize_gitlab_branch_protection(payload: dict[str, Any]) -> dict[str, Any]:
    approvals = int(payload.get("approvals_before_merge") or payload.get("required_approving_review_count") or 0)
    contexts = [str(item.get("name")) for item in payload.get("status_checks") or [] if isinstance(item, dict)]
    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": approvals,
            "require_code_owner_reviews": bool(payload.get("code_owner_approval_required")),
        },
        "required_status_checks": {"strict": True, "contexts": contexts},
        "enforce_admins": {"enabled": bool(payload.get("allow_force_push") is False)},
    }


class FixtureGovernanceClient:
    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture = Path(fixture_dir)

    def repo(self) -> dict[str, Any]:
        return read_json(self.fixture / "repo.json")

    def branch_protection(self, _branch: str) -> dict[str, Any]:
        return self._read("branch_protection.json")

    def collaborators(self) -> list[dict[str, Any]]:
        payload = self._read("collaborators.json")
        return payload if isinstance(payload, list) else payload.get("collaborators", [])

    def teams(self) -> list[dict[str, Any]]:
        payload = self._read("teams.json")
        return payload if isinstance(payload, list) else payload.get("teams", [])

    def workflow_permissions(self) -> dict[str, Any]:
        return self._read("workflow_permissions.json")

    def vulnerability_alerts(self) -> dict[str, Any]:
        return self._read("vulnerability_alerts.json")

    def security_findings(self) -> dict[str, Any]:
        return self._read("security_findings.json")

    def _read(self, name: str) -> Any:
        path = self.fixture / name
        return read_json(path) if path.exists() else {"available": False}


def sync_repo_governance(
    repo: str,
    *,
    out: str | Path | None = None,
    fixture_dir: str | Path | None = None,
    token: str | None = None,
    token_env: str | None = None,
    provider: str | None = None,
    collected_at: datetime | None = None,
) -> list[dict[str, Any]]:
    spec = parse_governance_repo_spec(repo, provider=provider)
    default_env = (
        "TRUSTOPS_GITLAB_ACCESS_TOKEN" if spec.provider == "gitlab" else "TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"
    )
    secret = token
    if not secret:
        secret = resolve_ref_or_default(
            token_env, default_env, dict(os.environ), field="credential_ref", file_first=False
        )
    client: GovernanceClient
    if fixture_dir:
        client = FixtureGovernanceClient(fixture_dir)
    elif secret:
        if spec.provider == "gitlab":
            client = GitLabGovernanceClient(spec, token=secret)
        else:
            client = GitHubGovernanceClient(spec, token=secret)
    else:
        raise ValueError("repo governance sync requires --fixture-dir or an authenticated access token")

    repo_data = client.repo()
    now = collected_at or datetime.now(UTC)
    rows = _build_events(
        spec,
        repo_data,
        client,
        now,
        credential_fingerprint=_fingerprint(secret) if secret else "fixture",
    )
    if out:
        write_jsonl(out, rows)
    return rows


def _build_events(
    spec: GovernanceRepoSpec,
    repo: dict[str, Any],
    client: GovernanceClient,
    collected_at: datetime,
    *,
    credential_fingerprint: str,
) -> list[dict[str, Any]]:
    branch = str(repo.get("default_branch") or "main")
    scopes = GITLAB_READ_ONLY_SCOPES if spec.provider == "gitlab" else GITHUB_READ_ONLY_SCOPES
    source_health = {
        "credential_fingerprint": credential_fingerprint,
        "credential_boundary": (
            "gitlab_access_token_or_fixture"
            if spec.provider == "gitlab"
            else "github_app_installation_token_or_fixture"
        ),
        "minimum_scopes": scopes,
        "collected_at": utc_iso(collected_at),
        "provider": spec.provider,
    }
    evidence_ref = (
        f"https://gitlab.com/api/v4/projects/{urllib.parse.quote(spec.slug, safe='')}"
        if spec.provider == "gitlab"
        else f"https://api.github.com/repos/{spec.slug}"
    )
    signal_payloads = {
        "branch_protection": _safe_call(lambda: client.branch_protection(branch)),
        "collaborators": _safe_call(client.collaborators),
        "teams": _safe_call(client.teams),
        "workflow_permissions": _safe_call(client.workflow_permissions),
        "security_settings": _safe_call(client.vulnerability_alerts),
        "security_findings": _safe_call(client.security_findings),
    }
    return [
        _event(
            spec,
            collected_at,
            signal=signal,
            event_type=f"repository.governance.{signal}",
            controls=CONTROL_MAP[signal],
            evidence_ref=evidence_ref,
            attributes={
                "default_branch": branch,
                "source_health": source_health,
                "governance": (
                    _normalize_security_findings(payload)
                    if signal == "security_findings"
                    else _normalize_signal(signal, payload)
                ),
            },
            status=_status_for(payload, signal=signal),
            severity=_findings_severity(payload) if signal == "security_findings" else "info",
        )
        for signal, payload in signal_payloads.items()
    ]


def _safe_call(func: Any) -> dict[str, Any] | list[dict[str, Any]]:
    try:
        return func()
    except urllib.error.HTTPError as exc:
        return {
            "available": False,
            "requires_scope_or_permission": True,
            "http_status": exc.code,
            "reason": "authenticated API did not authorize this signal",
        }


def _normalize_signal(signal: str, payload: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(payload, list):
        return {
            "signal": signal,
            "available": True,
            "count": len(payload),
            "items": [_redact_item(item) for item in payload],
        }
    if payload.get("available") is False:
        return {"signal": signal, **payload}
    return {"signal": signal, "available": True, **_redact_item(payload)}


def _normalize_security_findings(payload: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    """Emit aggregate alert posture without copying secret- or code-bearing details."""

    if not isinstance(payload, dict) or payload.get("available") is False:
        return _normalize_signal("security_findings", payload)

    categories: dict[str, Any] = {}
    for category in ("code_scanning", "secret_scanning", "dependabot"):
        alerts = payload.get(category)
        if isinstance(alerts, dict) and alerts.get("available") is False:
            categories[category] = _redact_item(alerts)
            continue
        if not isinstance(alerts, list):
            alerts = []
        states = Counter(str(item.get("state") or "unknown") for item in alerts if isinstance(item, dict))
        severities = Counter(
            severity
            for item in alerts
            if isinstance(item, dict)
            for severity in [_alert_severity(category, item)]
            if severity
        )
        categories[category] = {
            "count": len(alerts),
            "by_state": dict(sorted(states.items())),
            "by_severity": dict(sorted(severities.items())),
        }
    return {"signal": "security_findings", "available": True, "categories": categories}


def _alert_severity(category: str, alert: dict[str, Any]) -> str | None:
    if category == "code_scanning":
        rule = alert.get("rule")
        value = rule.get("security_severity_level") if isinstance(rule, dict) else None
    elif category == "dependabot":
        advisory = alert.get("security_advisory")
        value = advisory.get("severity") if isinstance(advisory, dict) else None
    else:
        value = None
    return str(value).lower() if value else None


def _redact_item(item: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in item.items():
        lowered = key.lower()
        if any(secret in lowered for secret in ("token", "secret", "password", "private_key")):
            redacted[key] = "[redacted]"
        elif isinstance(value, dict):
            redacted[key] = _redact_item(value)
        elif isinstance(value, list):
            redacted[key] = [_redact_item(v) if isinstance(v, dict) else v for v in value]
        else:
            redacted[key] = value
    return redacted


def _open_alerts(payload: dict[str, Any] | list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(payload, dict) or payload.get("available") is False:
        return []
    return [
        (category, alert)
        for category in ("code_scanning", "secret_scanning", "dependabot")
        if isinstance(payload.get(category), list)
        for alert in payload[category]
        if isinstance(alert, dict) and alert.get("state") == "open"
    ]


def _findings_severity(payload: dict[str, Any] | list[dict[str, Any]]) -> str:
    ranks = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    levels = [_alert_severity(category, alert) or "info" for category, alert in _open_alerts(payload)]
    return max((level for level in levels if level in ranks), key=ranks.__getitem__, default="info")


def _status_for(payload: dict[str, Any] | list[dict[str, Any]], *, signal: str = "") -> str:
    if isinstance(payload, dict) and payload.get("available") is False:
        return "requires_authenticated_connector"
    if signal == "security_findings" and _open_alerts(payload):
        return "open"
    return "observed"


def _event(
    spec: GovernanceRepoSpec,
    collected_at: datetime,
    *,
    signal: str,
    event_type: str,
    controls: list[str],
    evidence_ref: str,
    attributes: dict[str, Any],
    status: str,
    severity: str = "info",
) -> dict[str, Any]:
    stable = _sha({"repo": spec.slug, "signal": signal, "provider": spec.provider})[:16]
    evidence_body = {"event_type": event_type, "evidence_ref": evidence_ref, "attributes": attributes}
    source = "gitlab-repo-governance" if spec.provider == "gitlab" else "github-repo-governance"
    return {
        "event_id": f"repo-governance-{stable}",
        "tenant_id": "customer-managed",
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": source,
        "event_type": event_type,
        "entity": {
            "asset_id": spec.asset_id,
            "asset_type": "repository",
            "asset_owner": spec.owner,
            "environment": "prod",
            "repo": spec.slug,
            "provider": spec.provider,
        },
        "severity": severity,
        "status": status,
        "controls": controls,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": evidence_ref,
            "evidence_collected_at": utc_iso(collected_at),
            "raw_sha256": _sha(evidence_body),
        },
        "attributes": attributes,
    }


def _fingerprint(secret: str | None) -> str:
    if not secret:
        return "none"
    return f"sha256:{hashlib.sha256(secret.encode('utf-8')).hexdigest()[:12]}"


def _sha(value: object) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
