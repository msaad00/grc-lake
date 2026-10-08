"""Contract tests for the agent-native MCP write tools.

These exercise the lake-backed write tools (snapshot, workflow discovery, and
workflow execution) directly against a seeded lake, reusing the same seed
helper and the async FastMCP driver as the read-tool tests. The whole module
is guarded behind ``importorskip("mcp")`` so the rest of the suite passes
without the optional ``mcp`` dependency installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("mcp")

import anyio
from mcp.server.fastmcp.exceptions import ToolError

from security_lakehouse import mcp_server, workflows
from test_api_v1 import _seed_lake
from test_mcp_server import call_tool, structured_result, tool_names


async def _call_struct_async(server, name, arguments):
    # Return the structured payload verbatim. Unlike test_mcp_server.call_tool,
    # this does NOT unwrap a top-level ``result`` key, because a workflow run
    # record legitimately carries ``result`` ("ok"/"error") as a field.
    return structured_result(await server.call_tool(name, arguments))


def call_tool_struct(server, name: str, **arguments):
    """Invoke a tool and return its full structured dict (no result-key unwrap)."""
    return anyio.run(_call_struct_async, server, name, arguments)


WRITE_TOOLS = {
    "create_snapshot",
    "list_workflows",
    "get_workflow",
    "list_workflow_actions",
    "run_workflow",
}


def _seeded_server(tmp_path: Path):
    lake = tmp_path / "lake"
    lake.mkdir(parents=True, exist_ok=True)
    _seed_lake(lake)
    return lake, mcp_server.build_server(lake)


def _save_trivial_workflow(lake: Path, workflow_id: str = "wf-check") -> dict:
    """Persist a one-node workflow that checks a control's pass state."""
    return workflows.save_workflow(
        lake,
        workflow_id=workflow_id,
        name="Check SOC2 control",
        description="trivial single-node check workflow",
        nodes=[
            {
                "id": "n1",
                "node_type": "check.control_pass",
                "params": {"control_id": "SOC2-CC6.1"},
            }
        ],
        edges=[],
        actor="console",
    )


def test_write_tools_registered(tmp_path):
    _, server = _seeded_server(tmp_path)
    assert tool_names(server) >= WRITE_TOOLS


def test_create_snapshot_writes_file(tmp_path):
    lake, server = _seeded_server(tmp_path)
    result = call_tool(server, "create_snapshot", reason="unit_test")
    assert result["reason"] == "unit_test"
    snapshot_path = Path(result["snapshot_path"])
    assert snapshot_path.exists()
    # The snapshot now shows up through the read surface too.
    snapshots = call_tool(server, "list_snapshots")
    assert any(s.get("reason") == "unit_test" for s in snapshots)


def test_create_snapshot_default_reason(tmp_path):
    _, server = _seeded_server(tmp_path)
    result = call_tool(server, "create_snapshot")
    assert result["reason"] == "mcp_request"


def test_list_workflow_actions_shape(tmp_path):
    _, server = _seeded_server(tmp_path)
    actions = call_tool(server, "list_workflow_actions")
    assert actions
    sample = actions[0]
    assert {"node_type", "kind", "label", "description"} <= set(sample)
    node_types = {a["node_type"] for a in actions}
    assert "check.control_pass" in node_types


def test_list_and_get_workflow(tmp_path):
    lake, server = _seeded_server(tmp_path)
    _save_trivial_workflow(lake)
    listed = call_tool(server, "list_workflows")
    ids = {w["workflow_id"] for w in listed}
    assert "wf-check" in ids

    fetched = call_tool(server, "get_workflow", workflow_id="wf-check")
    assert fetched["workflow_id"] == "wf-check"
    assert fetched["nodes"][0]["node_type"] == "check.control_pass"


def test_get_workflow_unknown_raises(tmp_path):
    _, server = _seeded_server(tmp_path)
    with pytest.raises(ToolError):
        call_tool(server, "get_workflow", workflow_id="does-not-exist")


def test_run_workflow_returns_node_results(tmp_path):
    lake, server = _seeded_server(tmp_path)
    _save_trivial_workflow(lake)
    run = call_tool_struct(server, "run_workflow", workflow_id="wf-check")
    assert run["workflow_id"] == "wf-check"
    assert run["actor"] == "api"
    assert run["result"] in {"ok", "error"}
    assert run["node_results"]
    node = run["node_results"][0]
    assert node["node_id"] == "n1"
    assert node["node_type"] == "check.control_pass"
    # The run was persisted to the gold zone.
    assert workflows.list_runs(lake, "wf-check")


def test_run_workflow_unknown_raises(tmp_path):
    _, server = _seeded_server(tmp_path)
    with pytest.raises(ToolError):
        call_tool(server, "run_workflow", workflow_id="nope")
