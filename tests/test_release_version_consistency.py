"""Release 0.3.1 must present one version across every shipped surface."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.3.1"
RELEASE_DATE = "2026-10-09"


def test_release_version_is_consistent_across_package_chart_and_console() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    chart = (ROOT / "deploy" / "helm" / "grc-lake" / "Chart.yaml").read_text(encoding="utf-8")
    brand = (ROOT / "app" / "web" / "src" / "lib" / "brand.ts").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    package = json.loads((ROOT / "app/web/package.json").read_text())
    lock = json.loads((ROOT / "app/web/package-lock.json").read_text())
    assert package["version"] == lock["version"] == lock["packages"][""]["version"] == RELEASE_VERSION
    assert pyproject["project"]["version"] == RELEASE_VERSION
    assert pyproject["tool"]["commitizen"]["version"] == RELEASE_VERSION
    assert re.search(rf"^version: {re.escape(RELEASE_VERSION)}$", chart, re.MULTILINE)
    assert re.search(rf'^appVersion: "{re.escape(RELEASE_VERSION)}"$', chart, re.MULTILINE)
    assert f'version: "{RELEASE_VERSION}"' in brand
    assert f"## {RELEASE_VERSION} - {RELEASE_DATE}" in changelog
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert compose.count(f"ghcr.io/msaad00/grc-lake:${{GRC_LAKE_VERSION:-{RELEASE_VERSION}}}") == 2
    for doc in (
        "docs/CI_GATE.md",
        "docs/playbooks/CI_POSTURE_GATE.md",
        "docs/api/AGENT_SKILLS.md",
        "examples/github-actions/grc-lake-golden-gate.yml",
        "examples/github-actions/grc-lake-posture-gate.yml",
    ):
        text = (ROOT / doc).read_text(encoding="utf-8")
        refs = re.findall(r"posture-gate@v([\d.]+)", text) + re.findall(r"grc-lake\[server\]==([\d.]+)", text)
        assert refs and set(refs) == {RELEASE_VERSION}, (doc, refs)
    # Development after a release may add an Unreleased section without
    # changing the published package/chart/console version.
    if "## Unreleased" in changelog:
        assert changelog.index("## Unreleased") < changelog.index(f"## {RELEASE_VERSION} - {RELEASE_DATE}")


WORKFLOWS = ROOT / ".github" / "workflows"


def _workflow_texts() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml"))}


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([\w-]+):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_every_workflow_action_is_pinned_to_a_commit_sha() -> None:
    unpinned = [
        f"{name}: {line.strip()}"
        for name, text in _workflow_texts().items()
        for line in text.splitlines()
        if re.match(r"^\s*(-\s+)?uses:", line) and not re.search(r"uses: [\w./-]+@[0-9a-f]{40} # v\d+(\.\d+){2}$", line)
    ]
    assert not unpinned, unpinned


def test_every_workflow_job_has_a_timeout() -> None:
    missing = [
        f"{name}:{job}"
        for name, text in _workflow_texts().items()
        for job, block in _jobs(text).items()
        if not re.search(r"^    timeout-minutes: \d+$", block, re.MULTILINE)
    ]
    assert not missing, missing


def test_release_gate_checks_every_versioned_surface_and_the_tested_commit() -> None:
    jobs = _jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    gate = jobs["verify-version"]
    for surface in ("pyproject.toml", "Chart.yaml", "brand.ts", "app/web/package.json", "CHANGELOG.md"):
        assert surface in gate, surface
    tested = jobs["verify-tested-commit"]
    assert "merge-base --is-ancestor" in tested
    assert "actions/workflows/ci.yml/runs?head_sha=" in tested
    assert "needs: [verify-tested-commit, verify-version]" in jobs["build"]
    assert "body_path: release-notes.md" in jobs["github-release"]
    assert "provenance: mode=max" in jobs["image"]
    assert "sbom: true" in jobs["image"]
    assert "cyclonedx" in jobs["build"]


def test_released_version_has_a_non_empty_changelog_section() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    section = changelog.split(f"## {RELEASE_VERSION} - {RELEASE_DATE}\n", 1)[1].split("\n## ", 1)[0]
    assert section.strip().startswith("- ")
