"""Remote MCP mode must never fall back to the operator's local lake."""

import pytest

pytest.importorskip("mcp")

from security_lakehouse import mcp_server

CASES = [
    ("get_posture", {}, "GET", "/api/v1/posture/current"),
    ("list_evidence", {}, "GET", "/api/v1/evidence"),
    ("list_controls", {}, "GET", "/api/v1/controls"),
    ("get_snapshot_detail", {"snapshot_id": "remote"}, "GET", "/api/v1/snapshots/remote"),
    ("list_audit_log", {}, "GET", "/api/v1/audit-log"),
    ("list_frameworks", {}, "GET", "/api/v1/frameworks"),
    ("get_framework_coverage", {}, "GET", "/api/v1/frameworks/coverage"),
    ("get_mapping_review_queue", {}, "GET", "/api/v1/mapping-reviews/report"),
    ("list_connector_runs", {}, "GET", "/api/v1/connector-runs"),
    ("get_repository_graph", {}, "GET", "/api/v1/repo-graph"),
    ("get_framework_detail", {"framework_id": "soc2"}, "GET", "/api/v1/frameworks/soc2/detail"),
    ("list_workflows", {}, "GET", "/api/v1/workflows"),
    ("get_workflow", {"workflow_id": "remote"}, "GET", "/api/v1/workflows/remote"),
    ("list_workflow_actions", {}, "GET", "/api/v1/workflows/actions"),
    ("run_workflow", {"workflow_id": "remote"}, "POST", "/api/v1/workflows/remote/run"),
    ("create_snapshot", {}, "POST", "/api/v1/snapshots"),
    ("run_lake_eval", {}, "POST", "/api/v1/ingestion/eval"),
    ("run_scheduler_tick", {}, "POST", "/api/v1/scheduler/tick"),
    ("sync_connector", {"connector_id": "github-security"}, "POST", "/api/v1/connectors/github-security/sync"),
    (
        "configure_connector",
        {"connector_id": "github-security", "state": "disabled"},
        "POST",
        "/api/v1/connectors/github-security/configure",
    ),
]


def _structured(result):
    structured = result.structuredContent
    return structured.get("result", structured)


@pytest.mark.parametrize("name,args,method,path", CASES)
def test_tenant_tool_uses_remote_api_without_local_access(tmp_path, monkeypatch, name, args, method, path):
    monkeypatch.setenv("TRUSTOPS_API_URL", "https://remote.example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "fixture-token")
    calls = []

    def remote(verb, route, body=None, **params):
        calls.append((verb, route))
        return {"data": {"remote": True}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", remote)
    server = mcp_server.build_server(tmp_path)
    result = _structured(server._tool_manager.get_tool(name).fn(**args))
    assert result["remote"] is True
    assert calls == [(method, path)]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("missing", ["TRUSTOPS_API_URL", "TRUSTOPS_API_KEY"])
def test_incomplete_remote_configuration_cannot_read_local_lake(tmp_path, monkeypatch, missing):
    monkeypatch.setenv("TRUSTOPS_API_URL", "https://remote.example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "fixture-token")
    monkeypatch.delenv(missing)
    monkeypatch.setattr(
        mcp_server.api_v1, "handle_get", lambda *a, **kw: pytest.fail("remote mode fell back to local data")
    )
    with pytest.raises(ValueError, match=missing):
        mcp_server._get("/api/v1/posture/current", tmp_path)


def test_private_api_requires_explicit_operator_opt_in(monkeypatch):
    monkeypatch.setenv("TRUSTOPS_API_URL", "http://127.0.0.1:8787")
    monkeypatch.delenv("TRUSTOPS_API_ALLOW_PRIVATE", raising=False)
    with pytest.raises(ValueError):
        mcp_server.resolve_api_base_url()
    monkeypatch.setenv("TRUSTOPS_API_ALLOW_PRIVATE", "1")
    assert mcp_server.resolve_api_base_url() == "http://127.0.0.1:8787"


@pytest.mark.parametrize("name,args", [("list_trust_shares", {}), ("create_trust_share", {})])
def test_remote_share_tools_do_not_touch_local_lake(tmp_path, monkeypatch, name, args):
    monkeypatch.setenv("TRUSTOPS_API_URL", "https://remote.example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "fixture-token")
    calls = []

    def remote(method, path, body=None, **params):
        calls.append((method, path))
        return {"data": {"remote": True}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", remote)
    result = _structured(mcp_server.build_server(tmp_path)._tool_manager.get_tool(name).fn(**args))
    assert result["remote"] is True
    assert calls == [("GET" if name.startswith("list") else "POST", "/api/v1/trust-shares")]
    assert list(tmp_path.iterdir()) == []


def test_explicit_local_mode_ignores_remote_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_MCP_MODE", "local")
    monkeypatch.setenv("TRUSTOPS_API_URL", "https://remote.example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "fixture-token")
    monkeypatch.setattr(
        mcp_server, "_server_api_request", lambda *a, **kw: pytest.fail("explicit local mode used remote API")
    )
    monkeypatch.setattr(mcp_server.api_v1, "handle_get", lambda *a, **kw: (200, {"data": {"local": True}}))
    assert mcp_server._get_lake_or_remote("/api/v1/posture/current", tmp_path) == {"local": True}


def test_explicit_remote_mode_requires_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_MCP_MODE", "remote")
    monkeypatch.delenv("TRUSTOPS_API_URL", raising=False)
    monkeypatch.delenv("TRUSTOPS_API_KEY", raising=False)
    with pytest.raises(ValueError, match="TRUSTOPS_API_URL"):
        mcp_server._get("/api/v1/posture/current", tmp_path)
