"""CI sharding must run every collected test once and preserve failures."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_pytest(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "tools.pytest_shard", "-q", *args],
        cwd=directory,
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_ADDOPTS": ""},
        text=True,
        capture_output=True,
        check=False,
    )


def test_shards_partition_parametrized_tests_without_splitting_modules(tmp_path: Path) -> None:
    for name, size in [("a", 13), ("b", 7), ("c", 5), ("d", 2), ("new_module", 3)]:
        (tmp_path / f"test_{name}.py").write_text(
            f"import pytest\n@pytest.mark.parametrize('value', range({size}))\n"
            "def test_value(value):\n    assert value >= 0\n"
        )
    full = run_pytest(tmp_path, "--collect-only")
    assert full.returncode == 0, full.stderr + full.stdout
    expected = {line for line in full.stdout.splitlines() if "::" in line}
    seen: set[str] = set()
    module_owner: dict[str, int] = {}
    for index in range(1, 5):
        result = run_pytest(tmp_path, "--collect-only", f"--ci-shard={index}/4")
        assert result.returncode == 0, result.stderr + result.stdout
        selected = {line for line in result.stdout.splitlines() if "::" in line}
        assert selected
        assert not seen & selected
        seen.update(selected)
        for node in selected:
            module = node.split("::", 1)[0]
            assert module_owner.setdefault(module, index) == index
        executed = run_pytest(tmp_path, f"--ci-shard={index}/4")
        assert executed.returncode == 0, executed.stderr + executed.stdout
        assert f"{len(selected)} passed" in executed.stdout
    assert seen == expected
    assert len(seen) == 30


@pytest.mark.parametrize("shard", ["0/4", "5/4", "1/0", "1", "one/four"])
def test_invalid_shard_fails_closed(tmp_path: Path, shard: str) -> None:
    result = run_pytest(tmp_path, f"--ci-shard={shard}")
    assert result.returncode == 4
    assert "--ci-shard" in result.stderr


def test_shard_preserves_test_failures_and_empty_collection(tmp_path: Path) -> None:
    (tmp_path / "test_failure.py").write_text("def test_failure():\n    assert False\n")
    failed = run_pytest(tmp_path, "--ci-shard=1/1")
    assert failed.returncode == 1
    assert "1 failed" in failed.stdout
    empty = run_pytest(tmp_path, "--ci-shard=2/2")
    assert empty.returncode == 5
