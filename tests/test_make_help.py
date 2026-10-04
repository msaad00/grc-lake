"""Contributor command discovery must work before installing project dependencies."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"


def test_every_public_target_is_phony_and_has_an_inline_description() -> None:
    source = MAKEFILE.read_text()
    targets = set(re.findall(r"^([a-zA-Z][\w-]*):", source, re.MULTILINE))
    phony = {name for line in re.findall(r"^\.PHONY:\s*(.*)$", source, re.MULTILINE) for name in line.split()}
    documented = set(re.findall(r"^([a-zA-Z][\w-]*):[^\n]*##\s+\S", source, re.MULTILINE))
    assert targets == phony, f"targets missing .PHONY: {targets - phony}; stale .PHONY: {phony - targets}"
    assert phony == documented, f"targets missing descriptions: {phony - documented}"


def test_help_lists_each_target_once_without_project_dependencies(tmp_path) -> None:
    make = shutil.which("make")
    awk = shutil.which("awk")
    assert make and awk
    bins = tmp_path / "bin"
    bins.mkdir()
    (bins / "awk").symlink_to(awk)
    # A file with the target name must not suppress the help recipe.
    (tmp_path / "help").touch()
    env = {**os.environ, "PATH": str(bins), "MAKEFLAGS": "", "MFLAGS": ""}
    result = subprocess.run(
        [make, "--no-print-directory", "-f", str(MAKEFILE), "help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "Usage: make <target>" in result.stdout
    documented = dict(re.findall(r"^([a-zA-Z][\w-]*):[^\n]*?##\s+(.+)$", MAKEFILE.read_text(), re.MULTILINE))
    rows = re.findall(r"^  ([\w-]+)\s{2,}(.+)$", result.stdout, re.MULTILINE)
    assert dict(rows) == documented
    assert len(rows) == len(documented)


def test_bare_make_shows_help_without_starting_work(tmp_path) -> None:
    assert re.search(r"^\.DEFAULT_GOAL\s*:=\s*help$", MAKEFILE.read_text(), re.MULTILINE)
    command = ["make", "--no-print-directory", "-f", str(MAKEFILE)]
    default = subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True, timeout=10)
    explicit = subprocess.run([*command, "help"], cwd=tmp_path, check=True, capture_output=True, text=True, timeout=10)
    assert default.stdout == explicit.stdout
