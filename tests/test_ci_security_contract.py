"""Contracts for dependency auditing in CI."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_dependency_audit_exports_every_installed_extra() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "uv sync --frozen --all-extras" in workflow
    assert "uv export --all-extras --no-emit-project" in workflow


def test_dashboard_smoke_asserts_embedded_assessment_data() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert """grep -q 'id="app-data"'""" in workflow
    assert "Executive trust overview" not in workflow


def test_smoke_gate_rejects_failed_cancelled_or_skipped_dependencies() -> None:
    import itertools
    import os
    import subprocess

    import yaml

    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    gate = jobs["smoke"]
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == {"pipeline-smoke", "python-tests", "pre-commit", "security", "e2e"}
    step = gate["steps"][0]
    assert step["env"] == {
        "PIPELINE_RESULT": "${{ needs.pipeline-smoke.result }}",
        "TEST_RESULT": "${{ needs.python-tests.result }}",
        "HOOK_RESULT": "${{ needs.pre-commit.result }}",
        "SECURITY_RESULT": "${{ needs.security.result }}",
        "E2E_RESULT": "${{ needs.e2e.result }}",
    }
    for results in itertools.product(("success", "failure", "cancelled", "skipped"), repeat=len(step["env"])):
        result = subprocess.run(
            ["bash", "-c", step["run"]],
            env={**os.environ, **dict(zip(step["env"], results, strict=True))},
            check=False,
        )
        assert (result.returncode == 0) == all(value == "success" for value in results)


def test_python_matrix_runs_complete_suite_once_and_preserves_artifact_dependencies() -> None:
    import yaml

    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    tests = jobs["python-tests"]
    shards = tests["strategy"]["matrix"]["shard"]
    assert shards == list(range(1, len(shards) + 1))
    assert len(shards) > 1
    assert tests["strategy"]["fail-fast"] is False
    test_step = next(step for step in tests["steps"] if "--ci-shard" in step.get("run", ""))
    assert test_step["env"]["SHARD"] == "${{ matrix.shard }}/${{ strategy.job-total }}"
    assert '-p tools.pytest_shard --ci-shard="$SHARD"' in test_step["run"]
    for name in ("pipeline-smoke", "python-tests", "e2e"):
        assert jobs[name]["needs"] == "web"
        assert any(step.get("with", {}).get("name") == "web-dist" for step in jobs[name]["steps"])
    for name in ("security", "docker-build"):
        assert "needs" not in jobs[name]
    assert not any("pytest" in step.get("run", "") for step in jobs["pipeline-smoke"]["steps"])


def test_consolidated_copy_artifact_hook_preserves_filename_coverage() -> None:
    import re

    import yaml

    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())
    hook = next(hook for repo in config["repos"] for hook in repo["hooks"] if hook["id"] == "no-editor-copy-artifacts")
    for name in ("models 2.py", "catalog 12.json", "Card 3.tsx", "x copy.ts", "x.py.bak", "x.orig"):
        assert re.search(hook["files"], name), name
    for name in ("models.py", "catalog.json", "Card.tsx"):
        assert not re.search(hook["files"], name), name
