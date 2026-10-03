"""Packaging contract for data catalogs used by installed CLI commands."""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_wheel_data_files_include_runtime_catalogs() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    data_files = pyproject["tool"]["setuptools"]["data-files"]

    expected = {
        "connectors": ["connectors/catalog.json"],
        "controls": [
            "controls/bundle.lock.json",
            "controls/catalog.json",
            "controls/safeguards.json",
            "controls/history.jsonl",
        ],
        "frameworks": ["frameworks/registry.json", "frameworks/verified_article_ids.json"],
        "mappings": [
            "mappings/control_articles.json",
            "mappings/control_map.json",
            "mappings/remediation_guidance.json",
        ],
        "programs": ["programs/catalog.json", "programs/vendor_questionnaires.json"],
        "policy_templates": ["policy_templates/catalog.json"],
    }
    for company in ("ai_lab", "fintech", "golden", "healthcare", "saas"):
        directory = f"mockup_companies/{company}/raw"
        expected[directory] = [f"{directory}/security_events.jsonl"]
    for directory, files in expected.items():
        assert set(files).issubset(data_files[directory])

    for skill in (REPO_ROOT / "agent-skills").glob("*/SKILL.md"):
        directory = str(skill.parent.relative_to(REPO_ROOT))
        assert str(skill.relative_to(REPO_ROOT)) in data_files[directory]

    for files in expected.values():
        for rel_path in files:
            assert (REPO_ROOT / rel_path).is_file(), rel_path


def test_mcp_dependency_excludes_incompatible_major_version() -> None:
    from packaging.requirements import Requirement

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = [Requirement(value) for value in pyproject["project"]["optional-dependencies"]["mcp"]]
    mcp = next(requirement for requirement in dependencies if requirement.name == "mcp")
    assert "2.0.0" not in mcp.specifier, "FastMCP entry point is incompatible with the MCP 2 API"
    assert "1.26.0" in mcp.specifier


def test_every_runtime_data_path_is_packaged() -> None:
    """A data file read through ROOT/_data_root() must ship in the wheel.

    controls/families.json was added to runtime code without a data-files entry,
    so an installed package crashed in `frameworks safeguards`.
    """
    import re

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    shipped = {path for files in pyproject["tool"]["setuptools"]["data-files"].values() for path in files}
    pattern = re.compile(r'(?:\bROOT|_data_root\(\))((?:\s*/\s*"[^"]+")+)')
    referenced: set[str] = set()
    for source in (REPO_ROOT / "src" / "security_lakehouse").rglob("*.py"):
        for match in pattern.finditer(source.read_text(encoding="utf-8")):
            parts = re.findall(r'"([^"]+)"', match.group(1))
            if parts and "." in parts[-1]:
                referenced.add("/".join(parts))
    assert referenced, "pattern found no runtime data paths"
    missing = sorted(path for path in referenced if (REPO_ROOT / path).is_file() and path not in shipped)
    assert missing == [], f"runtime data files missing from [tool.setuptools.data-files]: {missing}"


def test_all_framework_pack_manifests_are_declared_for_distribution() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    declared = pyproject["tool"]["setuptools"]["data-files"]["frameworks/packs/data"]
    shipped = {path.relative_to(REPO_ROOT).as_posix() for pattern in declared for path in REPO_ROOT.glob(pattern)}
    required = {path.relative_to(REPO_ROOT).as_posix() for path in (REPO_ROOT / "frameworks/packs/data").glob("*.json")}
    assert required <= shipped, sorted(required - shipped)
