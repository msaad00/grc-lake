"""GRC Lake brand asset tests."""

from __future__ import annotations

from security_lakehouse.brand_assets import (
    MCP_SERVER_NAME,
    grc_lake_mark_data_uri,
    human_tool_title,
    mcp_icons,
)


def test_grc_lake_mark_data_uri_is_embedded_svg() -> None:
    uri = grc_lake_mark_data_uri()
    assert uri.startswith("data:image/svg+xml;base64,")
    assert "GRC Lake" not in uri  # binary payload, not raw svg text


def test_mcp_icons_include_embedded_fallback() -> None:
    icons = mcp_icons()
    assert len(icons) >= 1
    assert any(icon.src.startswith("data:image/svg+xml") for icon in icons)
    assert icons[-1].mimeType == "image/svg+xml"


def test_mcp_icons_add_hosted_url_when_api_url_set(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_API_URL", "https://grc-lake.example.com")
    icons = mcp_icons()
    assert icons[0].src == "https://grc-lake.example.com/brand/grc-lake-mark.svg"


def test_human_tool_title() -> None:
    assert human_tool_title("get_posture") == "Get Posture"
    assert MCP_SERVER_NAME == "grc-lake"


def test_distributed_marks_match_the_approved_identity() -> None:
    import base64
    from pathlib import Path
    from xml.etree import ElementTree

    root = Path(__file__).resolve().parents[1]
    approved = (root / "docs/images/grc-lake-mark.svg").read_text().strip()
    embedded = base64.b64decode(grc_lake_mark_data_uri().split(",", 1)[1]).decode()
    assert embedded == approved
    for file in ("app/web/src/app/icon.svg", "src/security_lakehouse/static/grc-lake-mark.svg"):
        assert (root / file).read_text().strip() == approved
    nodes = ElementTree.fromstring(approved)
    assert nodes.find("{http://www.w3.org/2000/svg}title").text == "GRC Lake"
    assert "evidence-lake waves" in nodes.find("{http://www.w3.org/2000/svg}desc").text
