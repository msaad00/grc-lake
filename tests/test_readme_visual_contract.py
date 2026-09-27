"""README hero assets stay sharp, accessible, and wired into the product story."""

import json
from pathlib import Path
from xml.etree import ElementTree

from tools.render_readme_header import render_logo, render_open_graph, render_readme_summary, render_social_preview

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
    assert "Open, self-hosted GRC for cloud and AI." in header
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
    assert f"{coverage['safeguards']} safeguards · {coverage['controls']} catalogued requirements" in copy
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
