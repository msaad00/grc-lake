"""README hero assets stay sharp, accessible, and wired into the product story."""

import json
from pathlib import Path
from xml.etree import ElementTree

import pytest
from tools.render_readme_header import (
    CCF_COLUMN,
    estimate_text_width,
    render_logo,
    render_open_graph,
    render_readme_summary,
    render_social_preview,
)

from security_lakehouse.safeguards import coverage_by_framework

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ASSETS = (
    ROOT / "docs" / "images" / "trustops-capability-header.svg",
    ROOT / "docs" / "images" / "trustops-logo.svg",
    ROOT / "docs" / "images" / "trustops-readme-banner.svg",
    ROOT / "app" / "web" / "public" / "og" / "trustops-share.svg",
)


def test_readme_header_leads_with_the_product_and_live_build_status() -> None:
    readme = README.read_text(encoding="utf-8")
    header = readme.split("## Quick start", maxsplit=1)[0]
    assert 'src="docs/images/trustops-capability-header.svg"' in header
    assert "**Open-source, self-hosted compliance automation.**" in header
    assert "Open, self-hosted GRC for cloud and AI." not in header, "one tagline only"
    assert "Quick start" in header
    assert "ci.yml?branch=main&amp;label=CI" in header
    opening_tags = readme.count("<details>") + readme.count("<details open>")
    assert opening_tags == readme.count("</details>") >= 6


def test_readme_hero_names_only_shipped_capabilities() -> None:
    root = ElementTree.parse(ASSETS[0]).getroot()
    copy = " ".join(text.strip() for text in root.itertext() if text.strip())
    coverage = coverage_by_framework()

    assert "Collect. Evaluate. Resolve. Export." in copy
    assert "TrustOps" in copy
    assert "Read-only evidence" in copy
    assert "deterministic controls" in copy
    assert "owned findings" in copy
    assert "assessment exports" in copy
    assert f"{coverage['safeguards']:,} safeguards · {coverage['controls']:,} catalogued requirements" in copy
    assert f"{len(coverage['frameworks'])} framework packs" in copy
    assert "Console · API · CLI · MCP · CI" in copy
    source_ids = {
        "AWS": "aws-posture",
        "Azure": "azure-posture",
        "GCP": "gcp-posture",
        "GitHub": "github-security",
        "GitLab": "gitlab-security",
        "Okta": "okta-identity",
        "Snowflake": "snowflake-evidence-lake",
        "ClickHouse": "clickhouse-telemetry-lake",
    }
    connector_payload = json.loads((ROOT / "connectors" / "catalog.json").read_text(encoding="utf-8"))
    connectors = {entry["connector_id"]: entry for entry in connector_payload["connectors"]}
    for source, connector_id in source_ids.items():
        assert source in copy
        assert connectors[connector_id]["is_implemented"] is True
        assert connectors[connector_id]["collection_mode"] in {"direct_api_read", "existing_lake_read"}
    for framework in (
        "SOC 2",
        "ISO 27001",
        "FedRAMP",
        "CMMC",
        "NIST CSF",
        "CIS AWS",
        "HIPAA",
        "PCI DSS",
        "GDPR",
        "EU AI Act",
        "ISO 27017",
        "ISO 42001",
        "NIST AI RMF",
    ):
        assert framework in copy


SVG = "{http://www.w3.org/2000/svg}"


def _translate(element: ElementTree.Element) -> tuple[float, float]:
    transform = element.attrib.get("transform", "")
    if not transform.startswith("translate("):
        return 0.0, 0.0
    x, _, y = transform.removeprefix("translate(").removesuffix(")").partition(" ")
    return float(x), float(y or 0)


def _placed_text(element: ElementTree.Element, origin: tuple[float, float] = (0.0, 0.0)):
    """Yield (absolute left, absolute right, text) for every <text> in the hero."""
    dx, dy = _translate(element)
    origin = (origin[0] + dx, origin[1] + dy)
    for child in element:
        if child.tag == f"{SVG}text":
            copy = "".join(child.itertext())
            size = float(child.attrib.get("font-size", "16"))
            spacing = float(child.attrib.get("letter-spacing", "0"))
            width = estimate_text_width(copy, size, letter_spacing=spacing)
            x = origin[0] + float(child.attrib.get("x", "0"))
            anchor = child.attrib.get("text-anchor", "start")
            left = x - width if anchor == "end" else x - width / 2 if anchor == "middle" else x
            yield left, left + width, copy
        elif child.tag == f"{SVG}g":
            yield from _placed_text(child, origin)


def test_readme_hero_text_fits_the_view_box_and_the_ccf_column() -> None:
    root = ElementTree.parse(ASSETS[0]).getroot()
    width = float(root.attrib["viewBox"].split()[2])
    column_left, column_right = CCF_COLUMN
    placed = list(_placed_text(root))
    for left, right, copy in placed:
        assert left >= 0 and right <= width, f"{copy!r} overflows the header"
    column = [(left, right, copy) for left, right, copy in placed if left >= column_left - 1 and "Console" not in copy]
    assert any("framework packs" in copy for _, _, copy in column)
    for _, right, copy in column:
        assert right <= column_right, f"{copy!r} overflows the control framework column"


@pytest.mark.parametrize(
    ("copy", "size", "rendered"),
    [
        # Widths Chromium rendered for these hero lines with the system-ui fallback.
        ("SOC 2 · ISO 27001 · NIST 800-53 · NIST RMF · FedRAMP · CMMC · NIST CSF", 12, 446),
        ("CIS Controls · CIS AWS · HIPAA · PCI DSS · GDPR · EU AI Act · ISO 27017", 12, 422),
        ("78 safeguards · 2,031 catalogued requirements", 13, 302),
        ("Read-only evidence → deterministic controls → owned findings → assessment exports.", 17, 678),
    ],
)
def test_estimated_text_width_never_undershoots_a_real_render(copy: str, size: float, rendered: int) -> None:
    assert estimate_text_width(copy, size) >= rendered
    assert estimate_text_width("", size) == 0


def test_readme_hero_counts_the_read_only_sources_it_leaves_out() -> None:
    root = ElementTree.parse(ASSETS[0]).getroot()
    copy = " ".join(text.strip() for text in root.itertext() if text.strip())
    connectors = json.loads((ROOT / "connectors" / "catalog.json").read_text(encoding="utf-8"))["connectors"]
    generally_available = [
        entry
        for entry in connectors
        if entry.get("is_implemented") is True
        and entry.get("release_stage") != "preview"
        and entry["collection_mode"] in {"direct_api_read", "existing_lake_read"}
    ]
    preview = [
        entry
        for entry in connectors
        if entry.get("is_implemented") is True
        and entry.get("release_stage") == "preview"
        and entry["collection_mode"] in {"direct_api_read", "existing_lake_read"}
    ]
    assert "GENERALLY AVAILABLE READ-ONLY SOURCES" in copy
    assert f"+{len(generally_available) - 8} more · +{len(preview)} in preview" in copy
    # GA + preview is the executable count the README states once.
    executable = [entry for entry in connectors if entry.get("is_implemented") is True]
    assert len(generally_available) + len(preview) == len(executable)
    readme = README.read_text(encoding="utf-8")
    assert f"{len(executable)} executable" in readme


def test_readme_hero_does_not_repeat_itself() -> None:
    root = ElementTree.parse(ASSETS[0]).getroot()
    texts = ["".join(node.itertext()) for node in root.iter(f"{SVG}text")]
    # The subtitle already says evidence -> controls -> findings -> exports.
    assert not any("evidence → controls → findings → proof" in text for text in texts)
    # One text run for the headline, so the browser spaces the words evenly.
    headline = [text for text in texts if text.startswith("Collect.")]
    assert headline == ["Collect. Evaluate. Resolve. Export."]


def test_readme_visuals_are_accessible_scalable_svg_assets() -> None:
    for path in ASSETS:
        assert path.is_file(), f"README visual is missing: {path.relative_to(ROOT)}"
        root = ElementTree.parse(path).getroot()
        assert root.attrib.get("viewBox"), f"{path.name} needs a viewBox for crisp scaling"
        assert root.attrib.get("role") == "img"
        labelled_by = root.attrib.get("aria-labelledby", "").split()
        assert labelled_by == ["title", "desc"]

        children = {child.tag.rsplit("}", 1)[-1]: child for child in root}
        assert children["title"].text
        assert children["desc"].text


def test_readme_hero_matches_the_deterministic_renderer() -> None:
    assert ASSETS[0].read_text(encoding="utf-8") == render_social_preview()


def test_readme_logo_matches_the_deterministic_renderer() -> None:
    assert ASSETS[1].read_text(encoding="utf-8") == render_logo()


def test_open_graph_image_matches_the_deterministic_renderer() -> None:
    assert ASSETS[3].read_text(encoding="utf-8") == render_open_graph()


def test_operating_loop_uses_concrete_actions() -> None:
    readme = README.read_text(encoding="utf-8")
    section = readme.split("## How it works", maxsplit=1)[1].split("## Explore", maxsplit=1)[0]
    for action in ("Collect", "Evaluate", "Resolve", "Export"):
        assert action in section


def test_product_preview_is_collapsible_and_uses_fixture_evidence() -> None:
    readme = README.read_text(encoding="utf-8")
    preview = readme.split("01 · Product tour", maxsplit=1)[1].split("</details>", maxsplit=1)[0]
    assert "not live customer evidence" in preview
    for image in ("dashboard", "frameworks", "evidence", "connectors", "audit-room"):
        assert f"trustops-demo-{image}.png" in preview


def test_readme_ccf_summary_matches_the_generator_and_names_every_family() -> None:
    readme = README.read_text(encoding="utf-8")
    block = readme.split("<!-- BEGIN README CCF SUMMARY -->", maxsplit=1)[1].split(
        "<!-- END README CCF SUMMARY -->", maxsplit=1
    )[0]
    assert block == f"\n\n{render_readme_summary()}\n\n"

    families = json.loads((ROOT / "controls" / "families.json").read_text(encoding="utf-8"))["families"]
    assert len(families) == 21
    for family in families:
        assert family["label"] in block
    coverage = coverage_by_framework()
    assert f"{coverage['controls']:,} catalogued requirements" in block
