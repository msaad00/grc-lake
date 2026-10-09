"""Render the repository-grounded GRC Lake README hero and brand lockup."""

from __future__ import annotations

import json
import re
from pathlib import Path

from security_lakehouse.brand_assets import GRC_LAKE_MARK_SVG
from security_lakehouse.framework_provenance import build_framework_view, framework_pack_counts
from security_lakehouse.safeguards import coverage_by_framework

ROOT = Path(__file__).resolve().parents[1]
HERO_OUTPUT = ROOT / "docs" / "images" / "grc-lake-capability-header.svg"
LOGO_OUTPUT = ROOT / "docs" / "images" / "grc-lake-logo.svg"
OG_OUTPUT = ROOT / "app" / "web" / "public" / "og" / "grc-lake-share.svg"

SOURCES = (
    ("AWS", "aws", "#ff9900"),
    ("Azure", "azure", "#29a8ea"),
    ("GCP", "gcp", "#4285f4"),
    ("GitHub", "github", "#f8fafc"),
    ("GitLab", "gitlab", "#fc6d26"),
    ("Okta", "okta", "#38bdf8"),
    ("Snowflake", "snowflake", "#29b5e8"),
    ("ClickHouse", "clickhouse", "#ffcc01"),
)

FRAMEWORKS = (
    "SOC 2",
    "ISO 27001",
    "NIST 800-53",
    "NIST RMF",
    "FedRAMP",
    "CMMC",
    "NIST 800-171",
    "NIST CSF",
    "CIS Controls",
    "CIS AWS",
    "HIPAA",
    "PCI DSS",
    "GDPR",
    "NIS2",
    "DORA",
    "EU AI Act",
    "ISO 27017",
    "ISO 27701",
    "ISO 42001",
    "NIST AI RMF",
)
READ_ONLY_MODES = {"direct_api_read", "existing_lake_read"}

HERO_WIDTH = 1280
# Left and right edge of the common control framework column.
CCF_COLUMN = (704, HERO_WIDTH - 60)
FRAMEWORK_FONT_SIZE = 12
FRAMEWORK_LINE_HEIGHT = 17

# Advance widths in em, rounded up from wide sans-serif faces (Inter,
# SF Pro, Segoe UI at semibold) so wrapped lines fit whichever font GitHub
# falls back to.
_EM_WIDTHS = {" ": 0.3, "·": 0.34, "-": 0.42, ".": 0.32, ",": 0.32, "+": 0.64, "→": 1.0}


def estimate_text_width(text: str, font_size: float, *, letter_spacing: float = 0.0) -> float:
    """Conservative rendered width of one line of hero text, in SVG units."""
    em = 0.0
    for char in text:
        if char in _EM_WIDTHS:
            em += _EM_WIDTHS[char]
        elif char in "MWmw@%":
            em += 0.92
        elif char in "iljtfrI|!:;'":
            em += 0.36
        elif char.isupper():
            em += 0.74
        elif char.isdigit():
            em += 0.64
        else:
            em += 0.6
    return em * font_size + letter_spacing * len(text)


def _wrap(items: tuple[str, ...], width: float, font_size: float, separator: str = " · ") -> list[str]:
    lines: list[str] = []
    for item in items:
        candidate = f"{lines[-1]}{separator}{item}" if lines else item
        if lines and estimate_text_width(candidate, font_size) <= width:
            lines[-1] = candidate
        else:
            lines.append(item)
    return lines


def _pack_counts() -> dict[str, int]:
    return framework_pack_counts(row["pack_state"] for row in build_framework_view())


def _coverage_summary() -> tuple[int, int, int]:
    catalog = json.loads((ROOT / "controls" / "catalog.json").read_text(encoding="utf-8"))
    safeguards = json.loads((ROOT / "controls" / "safeguards.json").read_text(encoding="utf-8"))
    return (
        len(safeguards["safeguards"]),
        len(catalog["controls"]),
        _pack_counts()["seeded_framework_count"],
    )


def _read_only_source_counts() -> tuple[int, int]:
    """(standard, preview) implemented read-only sources."""
    catalog = json.loads((ROOT / "connectors" / "catalog.json").read_text(encoding="utf-8"))
    runnable = [
        entry
        for entry in catalog["connectors"]
        if entry.get("is_implemented") is True and entry["collection_mode"] in READ_ONLY_MODES
    ]
    preview = sum(1 for entry in runnable if entry.get("release_stage") == "preview")
    return len(runnable) - preview, preview


def _framework_lines(top: int) -> str:
    width = CCF_COLUMN[1] - CCF_COLUMN[0]
    return "\n".join(
        f'      <text x="0" y="{top + index * FRAMEWORK_LINE_HEIGHT}" font-size="{FRAMEWORK_FONT_SIZE}" '
        f'font-weight="600" fill="#b4c2d6">{line}</text>'
        for index, line in enumerate(_wrap(FRAMEWORKS, width, FRAMEWORK_FONT_SIZE))
    )


def _brand_symbols() -> str:
    # Compact, self-contained brand marks keep GitHub rendering deterministic.
    mark = '<symbol id="mark" viewBox="0 0 64 64">' + _mark_body() + "</symbol>"
    return (
        mark
        + """    <symbol id="aws" viewBox="0 0 24 24">
      <text x="12" y="13.5" text-anchor="middle" font-size="10" font-weight="850" fill="currentColor">aws</text>
      <path d="M5 16.5c4.1 2.7 9.2 2.8 13.4.2M16.5 15.6l2.4.2-.8 2.2" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>
    </symbol>
    <symbol id="azure" viewBox="0 0 24 24">
      <path d="M8.3 2h6.5l6.6 19H15l-1.6-4.7H7.2L5.6 21H.9L8.3 2Zm.3 10.2h3.5l-1.6-5.1-1.9 5.1Zm3.8 2 3.2 6.8-8.4-4.7h6.1l-.9-2.1Z" fill="currentColor"/>
    </symbol>
    <symbol id="gcp" viewBox="0 0 24 24">
      <path d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c-3.875 2.551-3.922 8.11-.247 10.941a6.717 6.717 0 0 0 4.077 1.356h10.394c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-8.825-6.893Zm-.358 4.146a5.186 5.186 0 0 1 5.348 5.228v.518c3.53-.07 3.53 5.262 0 5.193H6.785a2.597 2.597 0 1 1 2.371-3.698l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24a5.186 5.186 0 0 1 3.722-1.714Z" fill="currentColor"/>
    </symbol>
    <symbol id="github" viewBox="0 0 24 24">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577l-.015-2.04c-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23a10.49 10.49 0 0 1 6 0c2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22l-.015 3.286c0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12Z" fill="currentColor"/>
    </symbol>
    <symbol id="gitlab" viewBox="0 0 24 24">
      <path d="m23.6 9.593-.034-.087L20.3.981a.86.86 0 0 0-1.626.089l-2.205 6.748H7.538L5.332 1.07a.86.86 0 0 0-1.626-.09L.433 9.502l-.032.086a6.066 6.066 0 0 0 2.012 7.01L12 23.35l9.579-6.744a6.068 6.068 0 0 0 2.021-7.013Z" fill="currentColor"/>
    </symbol>
    <symbol id="okta" viewBox="0 0 24 24">
      <path d="M12 0C5.389 0 0 5.35 0 12s5.35 12 12 12 12-5.35 12-12S18.611 0 12 0Zm0 18c-3.325 0-6-2.675-6-6s2.675-6 6-6 6 2.675 6 6-2.675 6-6 6Z" fill="currentColor"/>
    </symbol>
    <symbol id="snowflake" viewBox="0 0 24 24">
      <g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        <path d="M12 2v20M3.34 7l17.32 10M3.34 17 20.66 7"/>
        <path d="m9 4 3 2 3-2M9 20l3-2 3 2M4 10l3-.2.8-2.8M20 14l-3 .2-.8 2.8M4 14l3 .2.8 2.8M20 10l-3-.2-.8-2.8"/>
      </g>
    </symbol>
    <symbol id="clickhouse" viewBox="0 0 24 24">
      <path d="M21.333 10H24v4h-2.667ZM16 1.335h2.667v21.33H16Zm-5.333 0h2.666v21.33h-2.666ZM0 22.665V1.335h2.667v21.33Zm5.333-21.33H8v21.33H5.333Z" fill="currentColor"/>
    </symbol>"""
    )


def _source_tiles() -> str:
    tiles: list[str] = []
    for index, (name, symbol, color) in enumerate(SOURCES):
        x = 60 + index * 76
        tiles.append(
            f"""    <g transform="translate({x} 274)" style="color:{color}">
      <rect width="58" height="58" rx="15" fill="#0f192b" stroke="#2b3c57"/>
      <use x="12" y="12" width="34" height="34" href="#{symbol}"/>
      <text x="29" y="78" text-anchor="middle" font-size="11" font-weight="650" fill="#cbd5e1">{name}</text>
    </g>"""
        )
    return "\n".join(tiles)


def _brand_lockup() -> str:
    return """    <g transform="translate(60 24)">
      <use width="44" height="44" href="#mark"/>
      <text x="58" y="32" font-size="27" font-weight="830" letter-spacing="-1.1" fill="#f8fafc">Trust<tspan fill="url(#brand)">Ops</tspan></text>
    </g>"""


def render_social_preview() -> str:
    safeguard_count, requirement_count, framework_count = _coverage_summary()
    standard_sources, preview_sources = _read_only_source_counts()
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="420" viewBox="0 0 1280 420" role="img" aria-labelledby="title desc">
  <!-- Generated by tools/render_readme_header.py; do not edit by hand. -->
  <title id="title">GRC Lake — collect, evaluate, resolve, and export</title>
  <desc id="desc">Read-only evidence from {standard_sources + preview_sources} implemented sources, including {preview_sources} marked preview, deterministic control evaluation through a common control framework, owned findings, and hash-chained, verifiable audit records.</desc>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#060b16"/><stop offset="1" stop-color="#091b2c"/></linearGradient>
    <linearGradient id="brand" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#6d8cff"/><stop offset="1" stop-color="#2dd4bf"/></linearGradient>
{_brand_symbols()}
    <style>.font {{ font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}</style>
  </defs>
  <rect width="1280" height="420" fill="url(#bg)"/>
  <circle cx="1190" cy="-40" r="210" fill="none" stroke="#27456c" stroke-width="2" opacity=".38"/>
  <g class="font">
{_brand_lockup()}
    <text x="1220" y="48" text-anchor="end" font-size="11" font-weight="760" letter-spacing="1.6" fill="#6bd5df">OPEN SOURCE · SELF-HOSTED</text>
    <text x="60" y="126" font-size="43" font-weight="840" letter-spacing="-1.8" word-spacing="6" fill="#f8fafc" xml:space="preserve">Collect. Evaluate. Resolve. <tspan fill="url(#brand)">Export.</tspan></text>
    <text x="60" y="159" font-size="17" font-weight="520" fill="#94a3b8">Read-only evidence → deterministic controls → owned findings → assessment exports.</text>
    <g transform="translate(60 181)">
      <rect width="170" height="36" rx="18" fill="#0f192b" stroke="#5274e8"/><text x="85" y="24" text-anchor="middle" font-size="13" font-weight="700" fill="#9db6ff">cloud + identity</text>
      <rect x="182" width="132" height="36" rx="18" fill="#0f192b" stroke="#2e9fc2"/><text x="248" y="24" text-anchor="middle" font-size="13" font-weight="700" fill="#77d9eb">code + CI</text>
      <rect x="326" width="154" height="36" rx="18" fill="#0f192b" stroke="#2ab7aa"/><text x="403" y="24" text-anchor="middle" font-size="13" font-weight="700" fill="#79e4d6">evidence lakes</text>
      <rect x="492" width="142" height="36" rx="18" fill="#0f192b" stroke="#8b72d9"/><text x="563" y="24" text-anchor="middle" font-size="13" font-weight="700" fill="#c4b5fd">GRC + agents</text>
    </g>
    <text x="60" y="253" font-size="11" font-weight="760" letter-spacing="1.5" fill="#64748b">STANDARD READ-ONLY SOURCES</text>
    <text x="{60 + (len(SOURCES) - 1) * 76 + 58}" y="253" text-anchor="end" font-size="11" font-weight="700" fill="#94a3b8">{standard_sources + preview_sources} read-only source adapters ({preview_sources} preview)</text>
{_source_tiles()}
    <line x1="674" y1="246" x2="674" y2="371" stroke="#2b3c57"/>
    <g transform="translate({CCF_COLUMN[0]} 246)">
      <text x="0" y="10" font-size="11" font-weight="780" letter-spacing="1.5" fill="#6bd5df">COMMON CONTROL FRAMEWORK</text>
      <text x="0" y="52" font-size="31" font-weight="840" fill="#f8fafc">{framework_count}<tspan dx="8" font-size="15" font-weight="650" fill="#94a3b8">framework packs</tspan></text>
      <text x="0" y="79" font-size="13" font-weight="650" fill="#cbd5e1">{safeguard_count:,} safeguards · {requirement_count:,} catalogued requirements</text>
{_framework_lines(102)}
    </g>
    <text x="1220" y="402" text-anchor="end" font-size="12" font-weight="650" fill="#53657e">Console · API · CLI · MCP · CI</text>
  </g>
</svg>
"""


def _mark_body() -> str:
    return re.sub(r"^<svg[^>]*><title[^>]*>.*?</title><desc[^>]*>.*?</desc>", "", GRC_LAKE_MARK_SVG).removesuffix(
        "</svg>"
    )


def _render_brand_template(name: str) -> str:
    template = (ROOT / "tools" / "templates" / "brand" / f"{name}.svg").read_text(encoding="utf-8")
    return template.replace("{mark}", _mark_body())


def render_logo() -> str:
    return _render_brand_template("logo")


def render_open_graph() -> str:
    return _render_brand_template("open-graph")


def render_readme_summary() -> str:
    coverage = coverage_by_framework()
    taxonomy = json.loads((ROOT / "controls" / "families.json").read_text(encoding="utf-8"))
    families = taxonomy["families"]
    categories = taxonomy["categories"]
    safeguard_count, requirement_count, framework_count = _coverage_summary()
    grouped = "\n".join(
        f"- **{category['label']}:** "
        + " · ".join(family["label"] for family in families if family["category"] == category["category_id"])
        for category in categories
    )
    stubs = _pack_counts()["stub_framework_count"]
    stub_note = f" {stubs} more registry entries are planned or superseded and hold no requirements." if stubs else ""
    return (
        f"**{framework_count} framework packs · {safeguard_count} reusable safeguards · "
        f"{len(families)} control families in {len(categories)} categories · "
        f"{requirement_count:,} catalogued requirements.**{stub_note}\n\n"
        f"{coverage['covered']:,} requirements have safeguard mappings; **{coverage['reviewed']:,} have reviewed mappings**. "
        "Catalog coverage and evaluated customer posture are separate measures.\n\n"
        f"Control families by category:\n\n{grouped}"
    )


def render_readme_glance() -> str:
    coverage = coverage_by_framework()
    safeguard_count, requirement_count, framework_count = _coverage_summary()
    standard_sources, preview_sources = _read_only_source_counts()
    return (
        f"- **{framework_count} framework packs, {requirement_count:,} catalogued requirements,** linked through "
        f"{safeguard_count} common safeguards. {coverage['covered']:,} requirements have safeguard mappings; "
        f"{coverage['reviewed']:,} have reviewed mappings and the other {coverage['proposed']:,} are proposed.\n"
        f"- **{standard_sources + preview_sources} read-only source adapters ({preview_sources} in preview)**, "
        "plus OCSF presets for existing security lakes.\n"
        "- **Fails closed:** missing, stale, or partial evidence never produces a pass, and proposed mappings "
        "are not attestable.\n"
        "- **One engine, four surfaces:** console, REST API, CLI, and MCP server. Agents propose; humans approve."
    )


def _replace_block(text: str, name: str, body: str) -> str:
    begin, end = f"<!-- BEGIN README {name} -->", f"<!-- END README {name} -->"
    return re.sub(
        f"{re.escape(begin)}.*?{re.escape(end)}",
        lambda _match: f"{begin}\n\n{body}\n\n{end}",
        text,
        flags=re.DOTALL,
    )


def update_readme_summary() -> None:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    text = _replace_block(text, "AT A GLANCE", render_readme_glance())
    text = _replace_block(text, "CCF SUMMARY", render_readme_summary())
    readme.write_text(text, encoding="utf-8")


def main() -> int:
    for relative in (
        "docs/images/grc-lake-mark.svg",
        "app/web/src/app/icon.svg",
        "src/security_lakehouse/static/grc-lake-mark.svg",
    ):
        (ROOT / relative).write_text(GRC_LAKE_MARK_SVG + "\n", encoding="utf-8")
    HERO_OUTPUT.write_text(render_social_preview(), encoding="utf-8")
    LOGO_OUTPUT.write_text(render_logo(), encoding="utf-8")
    OG_OUTPUT.write_text(render_open_graph(), encoding="utf-8")
    update_readme_summary()
    print(f"wrote {HERO_OUTPUT.relative_to(ROOT)}")
    print(f"wrote {LOGO_OUTPUT.relative_to(ROOT)}")
    print(f"wrote {OG_OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
