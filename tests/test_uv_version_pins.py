"""CI, release, and the container image must build with the same uv."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _dockerfile_uv_version() -> str:
    match = re.search(r"^FROM ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)@", (ROOT / "Dockerfile").read_text(), re.MULTILINE)
    assert match, "Dockerfile must copy uv from a version-pinned ghcr.io/astral-sh/uv image"
    return match.group(1)


def test_workflow_uv_pins_match_the_dockerfile() -> None:
    expected = _dockerfile_uv_version()
    pins: dict[str, list[str]] = {}
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        found = re.findall(
            r'version: "(\d+\.\d+\.\d+)" # keep in step with the Dockerfile uv image', workflow.read_text()
        )
        if found:
            pins[workflow.name] = found
    assert pins, "expected setup-uv version pins in the workflows"
    mismatched = {name: versions for name, versions in pins.items() if set(versions) != {expected}}
    assert not mismatched, f"setup-uv pins must equal the Dockerfile uv {expected}: {mismatched}"
