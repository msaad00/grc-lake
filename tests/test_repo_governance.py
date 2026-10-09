"""Authenticated repository governance connector tests."""

from __future__ import annotations

import json
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security_lakehouse.cli import main
from security_lakehouse.io import read_jsonl
from security_lakehouse.repo_governance import (
    GitHubGovernanceClient,
    GitLabGovernanceClient,
    GovernanceRepoSpec,
    sync_repo_governance,
)
from security_lakehouse.validation import validate_raw_events


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "governance-fixture"
    _write_json(
        fixture / "repo.json",
        {
            "default_branch": "main",
            "full_name": "acme/private-agent-api",
            "name": "private-agent-api",
            "private": True,
            "visibility": "private",
        },
    )
    _write_json(
        fixture / "branch_protection.json",
        {
            "required_pull_request_reviews": {
                "dismiss_stale_reviews": True,
                "required_approving_review_count": 2,
                "require_code_owner_reviews": True,
            },
            "required_status_checks": {"strict": True, "contexts": ["quality", "web", "smoke"]},
            "enforce_admins": {"enabled": True},
        },
    )
    _write_json(
        fixture / "collaborators.json",
        [
            {"login": "alice", "role_name": "admin", "permissions": {"admin": True}, "token": "do-not-emit"},
            {"login": "bob", "role_name": "maintain", "permissions": {"maintain": True}},
        ],
    )
    _write_json(fixture / "teams.json", [{"name": "security", "permission": "admin", "privacy": "closed"}])
    _write_json(
        fixture / "workflow_permissions.json",
        {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
    )
    _write_json(fixture / "vulnerability_alerts.json", {"enabled": True})
    _write_json(
        fixture / "security_findings.json",
        {
            "code_scanning": [
                {"state": "open", "rule": {"security_severity_level": "high"}, "secret": "drop-me"},
                {"state": "dismissed", "rule": {"security_severity_level": "medium"}},
            ],
            "secret_scanning": [{"state": "open", "secret": "never-copy-alert-details"}],
            "dependabot": [{"state": "fixed", "security_advisory": {"severity": "critical"}}],
        },
    )
    return fixture


def test_governance_sync_fixture_emits_valid_raw_events(tmp_path: Path) -> None:
    rows = sync_repo_governance(
        "acme/private-agent-api",
        fixture_dir=_fixture(tmp_path),
        collected_at=datetime(2026, 5, 24, 12, 0, tzinfo=UTC),
    )
    assert validate_raw_events(rows) == []
    by_type = {row["event_type"]: row for row in rows}
    assert set(by_type) == {
        "repository.governance.branch_protection",
        "repository.governance.collaborators",
        "repository.governance.security_settings",
        "repository.governance.security_findings",
        "repository.governance.teams",
        "repository.governance.workflow_permissions",
    }
    branch = by_type["repository.governance.branch_protection"]
    assert branch["controls"] == ["SOC2-CC6.1", "ISO27001-A.5.15", "PCI-DSS-7"]
    assert branch["attributes"]["governance"]["required_pull_request_reviews"]["required_approving_review_count"] == 2
    findings = by_type["repository.governance.security_findings"]["attributes"]["governance"]
    assert findings["categories"]["code_scanning"] == {
        "count": 2,
        "by_state": {"dismissed": 1, "open": 1},
        "by_severity": {"high": 1, "medium": 1},
    }
    assert findings["categories"]["secret_scanning"]["count"] == 1
    assert "never-copy-alert-details" not in json.dumps(rows)


def test_governance_sync_redacts_secret_like_fields(tmp_path: Path) -> None:
    rows = sync_repo_governance(
        "acme/private-agent-api",
        fixture_dir=_fixture(tmp_path),
        token="github_app_installation_token_value",
        collected_at=datetime(2026, 5, 24, 12, 0, tzinfo=UTC),
    )
    body = json.dumps(rows, sort_keys=True)
    assert "github_app_installation_token_value" not in body
    assert "do-not-emit" not in body
    assert "sha256:" in body
    collaborators = next(row for row in rows if row["event_type"] == "repository.governance.collaborators")
    assert collaborators["attributes"]["governance"]["items"][0]["token"] == "[redacted]"


def test_governance_sync_requires_fixture_or_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_LAKE_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
    with pytest.raises(ValueError, match="requires --fixture-dir"):
        sync_repo_governance("acme/private-agent-api")


def _mock_response(payload: object, *, status: int = 200) -> object:
    response = MagicMock()
    response.status = status
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__.return_value = response
    return response


def test_github_request_goes_through_ssrf_guard_not_raw_urlopen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every GitHub read must route through netguard (redirect-revalidated), like
    every other HTTP connector — a raw urlopen is an SSRF-via-redirect bypass."""

    def forbidden_urlopen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("raw urllib.request.urlopen used — SSRF guard bypassed")

    monkeypatch.setattr("security_lakehouse.repo_governance.urllib.request.urlopen", forbidden_urlopen)
    client = GitHubGovernanceClient(GovernanceRepoSpec(provider="github", owner="acme", repo="api"), token="t")

    with patch(
        "security_lakehouse.netguard.open_public", return_value=_mock_response({"full_name": "acme/api"})
    ) as guarded:
        out = client.repo()

    assert guarded.called
    assert out["full_name"] == "acme/api"


def test_github_request_retries_transient_error_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    monkeypatch.setattr("security_lakehouse.ingestion.backoff.time.sleep", lambda *_: None)
    client = GitHubGovernanceClient(GovernanceRepoSpec(provider="github", owner="acme", repo="api"), token="t")
    sequence: list[object] = [
        urllib.error.HTTPError("https://api.github.com", 503, "unavailable", {}, None),
        _mock_response({"full_name": "acme/api"}),
    ]

    def flaky(*_args: object, **_kwargs: object) -> object:
        item = sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    with patch("security_lakehouse.netguard.open_public", side_effect=flaky):
        out = client.repo()

    assert out["full_name"] == "acme/api"
    assert sequence == []


def test_gitlab_request_goes_through_ssrf_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_urlopen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("raw urllib.request.urlopen used — SSRF guard bypassed")

    monkeypatch.setattr("security_lakehouse.repo_governance.urllib.request.urlopen", forbidden_urlopen)
    client = GitLabGovernanceClient(GovernanceRepoSpec(provider="gitlab", owner="acme", repo="api"), token="t")

    with patch(
        "security_lakehouse.netguard.open_public",
        return_value=_mock_response({"default_branch": "main", "visibility": "private", "id": 7}),
    ) as guarded:
        out = client.repo()

    assert guarded.called
    assert out["default_branch"] == "main"


def test_github_204_is_still_read_as_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The 204 → {'enabled': True} contract must survive the netguard switch."""
    client = GitHubGovernanceClient(GovernanceRepoSpec(provider="github", owner="acme", repo="api"), token="t")
    response = MagicMock()
    response.status = 204
    response.__enter__.return_value = response

    with patch("security_lakehouse.netguard.open_public", return_value=response):
        assert client.vulnerability_alerts() == {"enabled": True}


def test_github_security_findings_not_truncated_below_1000(monkeypatch: pytest.MonkeyPatch) -> None:
    """The page cap must not silently drop a repo's alerts at 10 pages (1000 rows)."""
    client = GitHubGovernanceClient(GovernanceRepoSpec(provider="github", owner="acme", repo="api"), token="t")

    def fake_request(url: str) -> object:
        # 11 full pages then a short page — 1001 rows, more than the old 10-page cap.
        page = int(url.rsplit("page=", 1)[1])
        return [{"state": "open"}] * 100 if page <= 11 else [{"state": "open"}]

    monkeypatch.setattr(client, "_request", fake_request)
    findings = client.security_findings()
    assert len(findings["code_scanning"]) == 1101  # 11×100 + 1, past the old 10-page (1000) cap


def test_github_security_findings_paginates_with_a_hard_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHubGovernanceClient(
        GovernanceRepoSpec(provider="github", owner="acme", repo="private-agent-api"),
        token="not-persisted",
    )
    requested: list[str] = []

    def fake_request(url: str) -> object:
        requested.append(url)
        if url.endswith("page=1"):
            return [{"state": "open"}] * 100
        return [{"state": "fixed"}]

    monkeypatch.setattr(client, "_request", fake_request)
    findings = client.security_findings()

    assert {key: len(value) for key, value in findings.items()} == {
        "code_scanning": 101,
        "secret_scanning": 101,
        "dependabot": 101,
    }
    assert len(requested) == 6
    assert all("per_page=100" in url for url in requested)


def test_github_security_findings_preserves_partial_permission_results(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHubGovernanceClient(
        GovernanceRepoSpec(provider="github", owner="acme", repo="private-agent-api"),
        token="not-persisted",
    )

    def fake_request(url: str) -> object:
        if "secret-scanning" in url:
            raise urllib.error.HTTPError(url, 403, "forbidden", {}, None)
        return [{"state": "open"}]

    monkeypatch.setattr(client, "_request", fake_request)
    findings = client.security_findings()

    assert findings["code_scanning"] == [{"state": "open"}]
    assert findings["dependabot"] == [{"state": "open"}]
    assert findings["secret_scanning"] == {
        "available": False,
        "requires_scope_or_permission": True,
        "http_status": 403,
        "reason": "authenticated API did not authorize this signal",
    }


def test_gitlab_governance_sync_fixture_emits_valid_raw_events(tmp_path: Path) -> None:
    rows = sync_repo_governance(
        "https://gitlab.com/acme/private-agent-api",
        fixture_dir=_fixture(tmp_path),
        provider="gitlab",
        collected_at=datetime(2026, 5, 24, 12, 0, tzinfo=UTC),
    )
    assert validate_raw_events(rows) == []
    assert rows[0]["source"] == "gitlab-repo-governance"
    assert rows[0]["entity"]["asset_id"] == "gitlab:repo:acme/private-agent-api"
    assert len(rows) == 6


def test_gitlab_governance_sync_redacts_secret_like_fields(tmp_path: Path) -> None:
    rows = sync_repo_governance(
        "acme/private-agent-api",
        fixture_dir=_fixture(tmp_path),
        provider="gitlab",
        token="gitlab_access_token_value",
        collected_at=datetime(2026, 5, 24, 12, 0, tzinfo=UTC),
    )
    body = json.dumps(rows, sort_keys=True)
    assert "gitlab_access_token_value" not in body
    assert rows[0]["attributes"]["source_health"]["provider"] == "gitlab"


def test_governance_sync_cli_writes_jsonl(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "repo-governance.jsonl"
    code = main(
        [
            "repo",
            "governance-sync",
            "acme/private-agent-api",
            "--fixture-dir",
            str(_fixture(tmp_path)),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 6
    rows = read_jsonl(out)
    assert validate_raw_events(rows) == []
