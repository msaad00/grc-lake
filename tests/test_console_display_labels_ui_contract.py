"""Badges show display labels, never raw enums like "critical" or "in_progress"."""

from __future__ import annotations

import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "app" / "web" / "src"
ENUM_FIELDS = (
    r"(?:status|severity|state|priority|result|decision|risk_level|freshness_status|freshness_state|kind|role)"
)
BADGE_CHILD = re.compile(r"<Badge\b[^>]*>\s*\{([^{}]+)\}\s*</Badge>", re.S)
RAW_ENUM = re.compile(rf"^\s*[\w?.\[\]]+\.{ENUM_FIELDS}\s*$")


def test_badges_render_enums_through_display_label() -> None:
    offenders = []
    for path in sorted(WEB.rglob("*.tsx")):
        text = path.read_text(encoding="utf-8")
        for match in BADGE_CHILD.finditer(text):
            expr = match.group(1)
            if RAW_ENUM.match(expr) or re.search(r'\.replace(All)?\((/_/g|"_")', expr):
                line = text[: match.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(WEB)}:{line}: {expr.strip()}")
    assert not offenders, "\n".join(offenders)


def test_display_map_is_shared() -> None:
    display = (WEB / "lib" / "display.ts").read_text(encoding="utf-8")
    assert "export function displayLabel" in display
    assert "MAPPING_REVIEW_GLOSSARY" in display
