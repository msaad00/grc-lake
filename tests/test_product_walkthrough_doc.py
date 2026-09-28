"""The walkthrough maps the real console navigation and makes no stale claims."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "PRODUCT_WALKTHROUGH.md"
WEB = ROOT / "app" / "web" / "src" / "lib"


def _nav_labels() -> list[str]:
    copy = (WEB / "console-copy.ts").read_text(encoding="utf-8")
    labels = dict(re.findall(r'"(/[\w-]+)": "([^"]+)"', copy))
    nav = (WEB / "nav.ts").read_text(encoding="utf-8")
    return [labels[href] for href in re.findall(r'href: "(/[\w-]+)"', nav)]


def test_walkthrough_lists_every_navigation_page() -> None:
    doc = DOC.read_text(encoding="utf-8")
    table = doc.split("## Console map", maxsplit=1)[1].split("## ", maxsplit=1)[0]
    labels = _nav_labels()
    assert {"Audit room", "Access reviews", "Mapping review", "Crosswalk", "Policies", "Vendor risk"} <= set(labels)
    for label in labels:
        assert f"| {label} " in table, label


def test_walkthrough_has_no_stale_claims() -> None:
    doc = DOC.read_text(encoding="utf-8")
    for stale in ("managed hosted", "Seven direct runners", "future work", "#evidence-pipeline"):
        assert stale not in doc, stale


def test_walkthrough_links_resolve() -> None:
    doc = DOC.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", doc):
        if target.startswith("http"):
            continue
        assert (DOC.parent / target).resolve().exists(), target
