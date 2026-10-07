"""Advertised MCP tools must be usable, bounded, and honest about authority."""

import json

import anyio
import pytest

pytest.importorskip("mcp")
from security_lakehouse import mcp_server
from test_mcp_server import _seeded_server, call_tool


@pytest.mark.parametrize("name", ["get_ccf_assessment", "get_mapping_review_queue"])
def test_unfiltered_assurance_tools_return_bounded_pages(tmp_path, name):
    server = _seeded_server(tmp_path)
    result = call_tool(server, name)
    assert len(json.dumps(result).encode()) < 256 * 1024
    assert result["pagination"]["limit"] == 25
    second = call_tool(server, name, limit=25, offset=25)
    assert second["pagination"]["offset"] == 25


def test_local_discovery_does_not_advertise_server_only_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_MCP_MODE", "local")
    server = mcp_server.build_server(tmp_path)
    tools = anyio.run(server.list_tools)
    names = {tool.name for tool in tools}
    assert "list_controls" in names
    assert "list_access_reviews" not in names
    assert "list_operations" not in names


def test_remote_discovery_excludes_human_attestations(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_MCP_MODE", "remote")
    monkeypatch.setenv("TRUSTOPS_API_URL", "https://example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "fixture")
    tools = anyio.run(mcp_server.build_server(tmp_path).list_tools)
    names = {tool.name for tool in tools}
    assert "list_access_reviews" in names
    assert not names & {
        "record_access_review_decision",
        "acknowledge_policy",
        "approve_agent_decision",
        "reject_agent_decision",
    }
    assert len(json.dumps([tool.model_dump(mode="json") for tool in tools]).encode()) < 160 * 1024


def test_server_identity_reports_the_installed_trustops_version(tmp_path):
    from security_lakehouse import __version__

    options = mcp_server.build_server(tmp_path)._mcp_server.create_initialization_options()
    assert options.server_version == __version__


def test_core_only_entrypoint_explains_the_missing_extra(monkeypatch):
    def missing():
        raise ModuleNotFoundError("No module named mcp", name="mcp")

    monkeypatch.setattr(mcp_server, "build_server", missing)
    with pytest.raises(SystemExit, match="pip install.*mcp"):
        mcp_server.main()
