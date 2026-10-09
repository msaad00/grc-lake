"""Public repository audit evidence collector.

This module is intentionally unauthenticated. It is a fast OSS/demo path for
public GitHub repositories and does not pretend to know private branch rules,
secret-scanning state, or org policy state that require a scoped connector.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_json, write_jsonl
from security_lakehouse.models import utc_iso

GITHUB_RE = re.compile(r"^(?:https://github\.com/)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")

CONTROL_MAP = {
    "codeowners": ["SOC2-CC6.1", "ISO27001-A.5.15"],
    "security_policy": ["SOC2-CC7.2", "PCI-DSS-11", "GDPR-Art.32"],
    "ci_workflow": ["SOC2-CC7.2", "ISO27001-A.8.16"],
    "dependency_manifest": ["PCI-DSS-11", "NIST-AI-RMF-MAP-1.5"],
    "container_build": ["PCI-DSS-11", "GDPR-Art.32"],
    "iac": ["SOC2-CC6.1", "ISO27001-A.5.15"],
    "ai_artifact": ["NIST-AI-RMF-MAP-1.5", "EU-AI-ACT-Art.10", "ISO42001-8.1"],
    "release_signal": ["SOC2-CC7.2", "ISO27001-A.8.16"],
}

CODEOWNERS_PATHS = {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}
SECURITY_PATHS = {"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}
DEPENDENCY_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
}
AI_ARTIFACT_NAMES = {
    "modelcard.md",
    "model-card.md",
    "model_card.md",
    "datasheet.md",
    "evals.yaml",
    "evals.yml",
    "prompts.yaml",
    "prompts.yml",
}
INTERESTING_FILE_LIMIT = 40


@dataclass(frozen=True)
class RepoSpec:
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def asset_id(self) -> str:
        return f"github:repo:{self.slug}"


class PublicGitHubClient:
    def __init__(self, owner: str, repo: str) -> None:
        self.spec = RepoSpec(owner=owner, repo=repo)

    def repo(self) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}")

    def languages(self) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}/languages")

    def tree(self, branch: str) -> dict[str, Any]:
        return self._json(f"https://api.github.com/repos/{self.spec.slug}/git/trees/{branch}?recursive=1")

    def file_text(self, branch: str, path: str) -> str | None:
        url = f"https://raw.githubusercontent.com/{self.spec.slug}/{branch}/{path}"
        request = urllib.request.Request(url, headers={"user-agent": "grc-lake"})
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:  # noqa: S310
                return resp.read(200_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    @staticmethod
    def _json(url: str) -> dict[str, Any]:
        request = urllib.request.Request(
            url, headers={"accept": "application/vnd.github+json", "user-agent": "grc-lake"}
        )
        with urllib.request.urlopen(request, timeout=20) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"GitHub returned non-object JSON for {url}")
        return payload


class FixtureRepoClient:
    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture = Path(fixture_dir)

    def repo(self) -> dict[str, Any]:
        return read_json(self.fixture / "repo.json")

    def languages(self) -> dict[str, Any]:
        path = self.fixture / "languages.json"
        return read_json(path) if path.exists() else {}

    def tree(self, _branch: str) -> dict[str, Any]:
        return read_json(self.fixture / "tree.json")

    def file_text(self, _branch: str, path: str) -> str | None:
        candidate = (self.fixture / "files" / path).resolve()
        try:
            candidate.relative_to((self.fixture / "files").resolve())
        except ValueError:
            return None
        return candidate.read_text(encoding="utf-8") if candidate.exists() else None


def parse_repo_spec(value: str) -> RepoSpec:
    match = GITHUB_RE.match(value.strip())
    if not match:
        raise ValueError("repo must be a GitHub URL or OWNER/REPO")
    return RepoSpec(owner=match.group("owner"), repo=match.group("repo"))


def audit_public_repo(
    repo: str,
    *,
    out: str | Path | None = None,
    fixture_dir: str | Path | None = None,
    collected_at: datetime | None = None,
) -> list[dict[str, Any]]:
    spec = parse_repo_spec(repo)
    client: PublicGitHubClient | FixtureRepoClient
    client = FixtureRepoClient(fixture_dir) if fixture_dir else PublicGitHubClient(spec.owner, spec.repo)
    now = collected_at or datetime.now(UTC)
    repo_data = client.repo()
    rows = _build_events(spec, repo_data, client.languages(), client.tree(_default_branch(repo_data)), client, now)
    if out:
        write_jsonl(out, rows)
    return rows


def _build_events(
    spec: RepoSpec,
    repo: dict[str, Any],
    languages: dict[str, Any],
    tree_payload: dict[str, Any],
    client: PublicGitHubClient | FixtureRepoClient,
    collected_at: datetime,
) -> list[dict[str, Any]]:
    branch = _default_branch(repo)
    paths = _tree_paths(tree_payload)
    signals = _classify_paths(paths)
    graph = _build_code_graph(spec, repo, languages, paths, signals)

    events = [
        _event(
            spec,
            collected_at,
            signal="metadata",
            event_type="repository.metadata",
            controls=[],
            evidence_ref=f"https://api.github.com/repos/{spec.slug}",
            attributes={
                "visibility": repo.get("visibility") or ("public" if not repo.get("private") else "private"),
                "default_branch": branch,
                "archived": bool(repo.get("archived")),
                "fork": bool(repo.get("fork")),
                "license": (repo.get("license") or {}).get("spdx_id"),
                "topics": repo.get("topics") or [],
                "language": repo.get("language"),
                "pushed_at": repo.get("pushed_at"),
                "languages": languages,
            },
        ),
        _event(
            spec,
            collected_at,
            signal="code_graph",
            event_type="repository.code_graph",
            controls=[],
            evidence_ref=f"https://api.github.com/repos/{spec.slug}/git/trees/{branch}?recursive=1",
            attributes=graph,
        ),
        _event(
            spec,
            collected_at,
            signal="authenticated_signal_gap",
            event_type="repository.authenticated_signal_gap",
            controls=[],
            status="requires_authenticated_connector",
            evidence_ref=f"https://github.com/{spec.slug}/settings",
            attributes={
                "requires_authenticated_connector": [
                    "branch_protection_rules",
                    "secret_scanning_status",
                    "dependabot_alerts",
                    "code_scanning_alerts",
                    "rulesets",
                    "organization_codeowners_review_rules",
                ],
                "reason": "public unauthenticated GitHub APIs do not expose these controls reliably",
            },
        ),
    ]

    for signal, signal_paths in signals.items():
        if not signal_paths:
            continue
        sample_text = _sample_file_text(client, branch, signal_paths)
        events.append(
            _event(
                spec,
                collected_at,
                signal=signal,
                event_type=f"repository.{signal}",
                controls=CONTROL_MAP.get(signal, []),
                evidence_ref=f"https://github.com/{spec.slug}/tree/{branch}",
                attributes={
                    "paths": signal_paths[:INTERESTING_FILE_LIMIT],
                    "path_count": len(signal_paths),
                    "sample_sha256": _sha(sample_text) if sample_text else None,
                    # Arbitrary source text can contain credentials that pattern
                    # redaction misses. Keep the field for compatibility, but
                    # persist only its sample hash, never the source excerpt.
                    "sample_excerpt": None,
                },
            )
        )
    return events


def _event(
    spec: RepoSpec,
    collected_at: datetime,
    *,
    signal: str,
    event_type: str,
    controls: list[str],
    evidence_ref: str,
    attributes: dict[str, Any],
    status: str = "observed",
) -> dict[str, Any]:
    stable = _sha({"repo": spec.slug, "signal": signal})[:16]
    evidence_body = {"event_type": event_type, "evidence_ref": evidence_ref, "attributes": attributes}
    return {
        "event_id": f"repo-audit-{stable}",
        "tenant_id": "public",
        "event_time": utc_iso(collected_at),
        "source": "github-public-repo",
        "event_type": event_type,
        "entity": {
            "asset_id": spec.asset_id,
            "asset_type": "repository",
            "asset_owner": spec.owner,
            "environment": "public",
            "repo": spec.slug,
        },
        "severity": "info",
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


def _default_branch(repo: dict[str, Any]) -> str:
    return str(repo.get("default_branch") or "main")


def _tree_paths(tree_payload: dict[str, Any]) -> list[str]:
    if tree_payload.get("truncated") is not False:
        raise ValueError("repository tree is incomplete or completeness is unknown; retained evidence was not replaced")
    tree = tree_payload.get("tree")
    if not isinstance(tree, list) or any(
        not isinstance(item, dict)
        or item.get("type") not in {"blob", "tree", "commit"}
        or not isinstance(item.get("path"), str)
        or not item["path"]
        for item in tree
    ):
        raise ValueError("repository tree is malformed; retained evidence was not replaced")
    return sorted(
        str(item.get("path"))
        for item in tree
        if isinstance(item, dict) and item.get("type") == "blob" and item.get("path")
    )


def _classify_paths(paths: list[str]) -> dict[str, list[str]]:
    signals: dict[str, list[str]] = {
        "codeowners": [],
        "security_policy": [],
        "ci_workflow": [],
        "dependency_manifest": [],
        "container_build": [],
        "iac": [],
        "ai_artifact": [],
        "release_signal": [],
    }
    for path in paths:
        name = Path(path).name
        lower = path.lower()
        if path in CODEOWNERS_PATHS:
            signals["codeowners"].append(path)
        if path in SECURITY_PATHS:
            signals["security_policy"].append(path)
        if lower.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
            signals["ci_workflow"].append(path)
        if name in DEPENDENCY_NAMES:
            signals["dependency_manifest"].append(path)
        if name == "Dockerfile" or lower.endswith(".dockerfile"):
            signals["container_build"].append(path)
        if (
            lower.endswith(".tf")
            or "/helm/" in lower
            or lower.startswith("deploy/helm/")
            or lower.endswith(("kustomization.yaml", "kustomization.yml"))
        ):
            signals["iac"].append(path)
        if name.lower() in AI_ARTIFACT_NAMES or lower.startswith(("evals/", "prompts/", "models/")):
            signals["ai_artifact"].append(path)
        if lower.startswith(".github/") and "release" in lower:
            signals["release_signal"].append(path)
    return {key: sorted(set(value)) for key, value in signals.items()}


def _build_code_graph(
    spec: RepoSpec,
    repo: dict[str, Any],
    languages: dict[str, Any],
    paths: list[str],
    signals: dict[str, list[str]],
) -> dict[str, Any]:
    nodes = [
        {"id": spec.asset_id, "kind": "repository", "label": spec.slug, "visibility": repo.get("visibility", "public")}
    ]
    edges: list[dict[str, str]] = []
    dirs = sorted({path.split("/", 1)[0] for path in paths if "/" in path})
    for directory in dirs[:100]:
        node_id = f"{spec.asset_id}:dir:{directory}"
        nodes.append({"id": node_id, "kind": "directory", "label": directory})
        edges.append({"source": spec.asset_id, "target": node_id, "kind": "contains"})
    for language, bytes_count in sorted(languages.items()):
        node_id = f"{spec.asset_id}:language:{language}"
        nodes.append({"id": node_id, "kind": "language", "label": language, "bytes": bytes_count})
        edges.append({"source": spec.asset_id, "target": node_id, "kind": "uses_language"})
    for signal, signal_paths in signals.items():
        if not signal_paths:
            continue
        node_id = f"{spec.asset_id}:signal:{signal}"
        nodes.append({"id": node_id, "kind": "evidence_signal", "label": signal, "path_count": len(signal_paths)})
        edges.append({"source": spec.asset_id, "target": node_id, "kind": "has_signal"})
    return {
        "nodes": nodes,
        "edges": edges,
        "counts": {
            "files": len(paths),
            "directories": len(dirs),
            "languages": len(languages),
            "signals": sum(1 for value in signals.values() if value),
        },
    }


def _sample_file_text(client: PublicGitHubClient | FixtureRepoClient, branch: str, paths: list[str]) -> str | None:
    for path in paths[:3]:
        text = client.file_text(branch, path)
        if text:
            return text
    return None


def _sha(value: object) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
