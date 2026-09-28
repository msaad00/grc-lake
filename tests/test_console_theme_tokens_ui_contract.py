"""Contract for the console colour system: one accent, AA contrast, both themes."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WEB = ROOT / "app/web"
CSS = WEB / "src/app/globals.css"
TAILWIND = WEB / "tailwind.config.ts"
STATUSES = ("success", "warning", "serious", "danger", "info")


def _block(css: str, selector: str) -> dict[str, str]:
    start = css.index(selector + " {")
    body = css[start : css.index("}", start)]
    return {name: value.lower() for name, value in re.findall(r"--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", body)}


def _themes() -> dict[str, dict[str, str]]:
    css = CSS.read_text(encoding="utf-8")
    light = _block(css, ":root")
    return {"light": light, "dark": {**light, **_block(css, ".dark")}}


def _luminance(hex_color: str) -> float:
    channels = []
    for i in (1, 3, 5):
        c = int(hex_color[i : i + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_text_tokens_meet_wcag_aa_on_every_surface(theme: str) -> None:
    t = _themes()[theme]
    for surface in ("panel", "rail", "surface", "surface-muted"):
        for text in ("ink", "muted", "brand"):
            assert _contrast(t[text], t[surface]) >= 4.5, (theme, text, surface)
    assert _contrast(t["rail-text"], t["rail"]) >= 4.5
    assert _contrast(t["on-brand"], t["brand"]) >= 4.5
    assert _contrast(t["neutral-fg"], t["neutral-bg"]) >= 4.5
    # Input borders and other UI boundaries: 3:1 (WCAG 1.4.11).
    assert _contrast(t["line-strong"], t["surface"]) >= 3.0


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_status_chips_are_tinted_fills_with_strong_text(theme: str) -> None:
    t = _themes()[theme]
    for status in STATUSES:
        assert _contrast(t[f"{status}-fg"], t[f"{status}-bg"]) >= 4.5, (theme, status)
        assert _contrast(t[f"{status}-fg"], t["surface"]) >= 4.5, (theme, status)
        # Solid marks (dots, meters) stay visible against the card.
        assert _contrast(t[status], t["surface"]) >= 3.0, (theme, status)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_surfaces_step_up_in_elevation_with_visible_borders(theme: str) -> None:
    t = _themes()[theme]
    lum = {name: _luminance(t[name]) for name in ("panel", "surface", "surface-muted")}
    if theme == "dark":
        assert lum["panel"] < lum["surface"] < lum["surface-muted"]
    else:
        assert lum["panel"] < lum["surface"]
    assert _contrast(t["line"], t["surface"]) >= 1.2
    assert len({t["panel"], t["surface"], t["rail"]}) == 3


def test_tailwind_colours_resolve_to_theme_tokens_only() -> None:
    config = TAILWIND.read_text(encoding="utf-8")
    colours = config[config.index("colors: {") : config.index("fontFamily:")]

    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", colours)
    for token in ("brand", "onBrand", "surface", "ink", "muted", *STATUSES):
        assert f"{token}:" in colours
    # A single accent: the old secondary brand hues are gone.
    for retired in ("cyan:", "purple:", "orange:", "green:"):
        assert retired not in colours


def test_touched_surfaces_use_tokens_not_palette_classes() -> None:
    palette = re.compile(
        r"\b(?:bg|text|border|ring)-(?:slate|gray|blue|indigo|violet|purple|sky|cyan|emerald|green|amber|orange|rose|red|yellow|teal)-\d{2,3}\b"
    )
    touched = [
        "components/dashboard/AssessmentOverview.tsx",
        "components/dashboard/ReadinessGrid.tsx",
        "components/dashboard/FixNext.tsx",
        "components/drawers/ViolationDrawer.tsx",
        "components/shell/Sidebar.tsx",
        "components/shell/SidebarFooter.tsx",
        "components/shell/TopBar.tsx",
        "components/ui/badge.tsx",
        "components/ui/button.tsx",
        "components/ui/KpiTile.tsx",
        "components/graph/GraphCanvas.tsx",
        "app/frameworks/page.tsx",
        "app/violations/page.tsx",
        "app/evidence/page.tsx",
        "app/connectors/page.tsx",
    ]
    for rel in touched:
        source = (WEB / "src" / rel).read_text(encoding="utf-8")
        assert not palette.search(source), rel
        # Tokens swap per theme, so no per-class dark: overrides remain.
        assert not re.search(r"(?<![\w-])dark:[a-z]", source), rel
