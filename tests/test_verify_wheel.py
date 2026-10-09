"""The wheel gate that stands between a build and PyPI.

`src/security_lakehouse/web/dist` is gitignored and built by `make web-build`.
A wheel packaged before that step is valid, installable, and silently
consoleless — which is the exact failure the quick start hit in #562, except
published to every user instead of one clone.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from verify_wheel import verify

COMPLETE = {
    "security_lakehouse/web/dist/index.html": "<html></html>",
    "security_lakehouse/web/dist/404.html": "",
    "security_lakehouse/web/dist/_next/a.js": "",
    "security_lakehouse/web/dist/_next/b.js": "",
    "security_lakehouse/web/dist/_next/c.js": "",
    "security_lakehouse/web/dist/_next/d.js": "",
    "trustops-0.2.0.data/data/controls/catalog.json": "{}",
    "trustops-0.2.0.data/data/frameworks/registry.json": "{}",
    "trustops-0.2.0.data/data/connectors/catalog.json": "{}",
    "trustops-0.2.0.data/data/controls/safeguards.json": "{}",
    "trustops-0.2.0.data/data/controls/families.json": "{}",
}

for manifest in (Path(__file__).resolve().parents[1] / "frameworks/packs/data").glob("*.json"):
    COMPLETE[f"trustops-0.2.0.data/data/frameworks/packs/data/{manifest.name}"] = "{}"

for resource in (Path(__file__).resolve().parents[1] / "src/security_lakehouse/resources").rglob("*"):
    if resource.is_file():
        COMPLETE[resource.relative_to(Path(__file__).resolve().parents[1] / "src").as_posix()] = "{}"


def _wheel(tmp_path: Path, members: dict[str, str]) -> Path:
    path = tmp_path / "pkg-0.2.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return path


def test_a_complete_wheel_passes(tmp_path: Path) -> None:
    assert verify(_wheel(tmp_path, COMPLETE)) == []


def test_a_wheel_without_the_console_is_rejected(tmp_path: Path) -> None:
    members = {k: v for k, v in COMPLETE.items() if "/web/dist/" not in k}
    problems = verify(_wheel(tmp_path, members))
    assert any("web/dist/index.html" in p for p in problems)
    assert any("404" in p for p in problems), "the reason should say what breaks for a user"


def test_a_wheel_without_the_control_catalog_is_rejected(tmp_path: Path) -> None:
    members = {k: v for k, v in COMPLETE.items() if "controls/catalog.json" not in k}
    assert any("controls/catalog.json" in p for p in verify(_wheel(tmp_path, members)))


def test_a_truncated_console_is_rejected(tmp_path: Path) -> None:
    """index.html alone is not a console -- a partial export is worse than none."""
    members = {k: v for k, v in COMPLETE.items() if "/_next/" not in k}
    assert any("truncated" in p for p in verify(_wheel(tmp_path, members)))


def test_missing_framework_manifest_is_rejected(tmp_path: Path) -> None:
    members = dict(COMPLETE)
    root = Path(__file__).resolve().parents[1]
    for manifest in (root / "frameworks/packs/data").glob("*.json"):
        members[f"trustops-0.2.0.data/data/frameworks/packs/data/{manifest.name}"] = "{}"
    del members["trustops-0.2.0.data/data/frameworks/packs/data/nist_800_171_rev3.json"]
    assert any("nist_800_171_rev3.json" in problem for problem in verify(_wheel(tmp_path, members)))


def test_missing_cloud_template_is_rejected(tmp_path: Path) -> None:
    members = dict(COMPLETE)
    del members["security_lakehouse/resources/cloud/aws-role.yaml"]
    assert any("aws-role.yaml" in problem for problem in verify(_wheel(tmp_path, members)))


def test_missing_event_schema_is_rejected(tmp_path: Path) -> None:
    members = dict(COMPLETE)
    del members["security_lakehouse/resources/schemas/raw-security-event.schema.json"]
    assert any("raw-security-event.schema.json" in problem for problem in verify(_wheel(tmp_path, members)))
