"""Agent-native MCP server contract tests.

These exercise the FastMCP read tools directly against a seeded lake (no live
stdio client needed). The whole module is guarded behind ``importorskip("mcp")``
so the rest of the suite passes without the optional ``mcp`` dependency.

The async FastMCP coroutines are driven via ``anyio.run`` so the tests need no
pytest-asyncio plugin or extra configuration (``anyio`` ships with the MCP SDK).
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402

from security_lakehouse import mcp_server, netguard  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _no_ssrf_check(url: str, **_kw: object) -> str:
    return url.split("//", 1)[1].split("/")[0]


EXPECTED_TOOLS = {
    "get_posture",
    "posture_as_of",
    "list_controls",
    "list_control_tests",
    "list_evidence",
    "list_assets",
    "list_violations",
    "list_snapshots",
    "get_snapshots_integrity",
    "get_snapshot_detail",
    "get_tracking_integrity",
    "list_audit_log",
    "list_frameworks",
    "get_ingestion_status",
    "list_eval_runs",
    "run_lake_eval",
    "run_scheduler_tick",
    "list_connectors",
    "probe_connector",
    "discover_connector",
    "configure_connector",
    "sync_connector",
    "list_connector_runs",
    "get_framework_detail",
    "describe_api",
    "list_agent_runs",
    "create_agent_run",
    "get_agent_run",
    "approve_agent_decision",
    "reject_agent_decision",
    "get_audit_readiness",
    "get_ai_governance",
    "list_ai_inventory",
    "get_evidence_freshness_summary",
    "list_evidence_freshness",
    "get_repository_graph",
    "escalate_stale_evidence",
    "request_stale_evidence",
    "get_insights_timeseries",
    "get_insights_remediation",
    "get_insights_framework_trends",
    "get_insights_sla_heatmap",
    "capture_insights_point",
    "list_vendor_assessments",
    "get_vendor_assessment",
    "create_vendor_assessment",
    "submit_vendor_assessment",
    "list_vendor_questionnaires",
    "get_vendor_questionnaire",
    "get_poc_readiness",
    "get_platform_usage",
    "list_policies",
    "list_policy_templates",
    "get_policy_template",
    "get_policy",
    "list_access_reviews",
    "get_access_review",
    "list_access_review_items",
    "create_access_review",
    "seed_access_review",
    "record_access_review_decision",
    "get_access_reviews_coverage",
    "list_evidence_requests",
    "list_trust_shares",
    "create_trust_share",
    "get_policy_attestation_summary",
    "adopt_policy",
    "publish_policy",
    "list_policy_acknowledgments",
    "acknowledge_policy",
    "list_tags",
    "list_tag_entities",
    "attach_tag",
    "detach_tag",
    "list_saved_views",
    "list_risks",
    "create_risk",
    "update_risk",
    "delete_risk",
    "list_remediation_exceptions",
    "create_remediation_exception",
    "revoke_remediation_exception",
    "get_policies_coverage",
    "list_remediation_tasks",
    "get_remediation_task",
    "create_remediation_task",
    "update_remediation_task",
    "create_evidence_request",
    "update_evidence_request",
    "get_sprs_score",
    "list_poam_items",
    "create_poam_item",
    "update_poam_item",
    "sync_poam_from_posture",
    "get_control_remediation",
    "get_framework_coverage",
    "get_mapping_review_queue",
    "list_mapping_review_decisions",
}


def _seeded_server(tmp_path: Path):
    lake = tmp_path / "lake"
    lake.mkdir(parents=True, exist_ok=True)
    _seed_lake(lake)
    return mcp_server.build_server(lake)


async def _call_async(server, name, arguments):
    result = await server.call_tool(name, arguments)
    # FastMCP returns (content_blocks, structured_result) for newer SDKs and a
    # single value for older ones; normalize to the structured payload.
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured:
        return structured["result"]
    return structured


def call_tool(server, name: str, **arguments):
    """Synchronously invoke a registered FastMCP tool, returning its result."""
    return anyio.run(_call_async, server, name, arguments)


def call_tool_payload(server, name: str, **arguments):
    """Return the full structured MCP tool payload (no result-key unwrap)."""

    async def _inner() -> object:
        result = await server.call_tool(name, arguments)
        return result[1] if isinstance(result, tuple) else result

    return anyio.run(_inner)


def tool_names(server) -> set[str]:
    tools = anyio.run(server.list_tools)
    return {tool.name for tool in tools}


def test_mcp_server_branding(tmp_path: Path) -> None:
    server = _seeded_server(tmp_path)
    assert server.icons
    assert len(server.icons) >= 1
    tools = anyio.run(server.list_tools)
    assert tools
    assert all(getattr(tool, "icons", None) for tool in tools)
    assert all(getattr(tool, "title", None) for tool in tools)


def test_resolve_lake_dir_defaults(monkeypatch):
    monkeypatch.delenv("TRUSTOPS_LAKE", raising=False)
    assert mcp_server.resolve_lake_dir() == Path("./lake").expanduser().resolve()
    monkeypatch.setenv("TRUSTOPS_LAKE", "/tmp/some-lake")
    assert mcp_server.resolve_lake_dir() == Path("/tmp/some-lake").resolve()


def test_resolve_api_base_url(monkeypatch):
    monkeypatch.delenv("TRUSTOPS_API_URL", raising=False)
    with pytest.raises(ValueError):
        mcp_server.resolve_api_base_url()
    monkeypatch.setenv("TRUSTOPS_API_URL", "file:///tmp/lake")
    with pytest.raises(ValueError):
        mcp_server.resolve_api_base_url()
    monkeypatch.setenv("TRUSTOPS_API_URL", "https://trustops.example.test/")
    monkeypatch.setattr(netguard, "assert_url_is_public", _no_ssrf_check)
    assert mcp_server.resolve_api_base_url() == "https://trustops.example.test"


def test_expected_tools_registered(tmp_path):
    server = _seeded_server(tmp_path)
    assert tool_names(server) >= EXPECTED_TOOLS


def test_get_posture_has_score(tmp_path):
    server = _seeded_server(tmp_path)
    posture = call_tool(server, "get_posture")
    assert "posture" in posture
    assert isinstance(posture["posture"]["score"], (int, float))


def test_get_framework_equivalence_resolves(tmp_path):
    """This tool dispatched to a pre-v1 path that the v1 engine never served.

    ``_get`` routes through ``api_v1.handle_get`` and raises on any non-200, so
    the tool raised ValueError on every call from the day it was added. Nothing
    covered it, because the equivalence builder was tested directly instead.
    """
    server = _seeded_server(tmp_path)
    equivalence = call_tool(server, "get_framework_equivalence")
    assert equivalence["group_count"] >= 1
    assert equivalence["groups"]


def test_mapping_review_queue_can_scope_a_cross_framework_category(tmp_path):
    server = _seeded_server(tmp_path)
    report = call_tool(server, "get_mapping_review_queue", risk_domain="governance")

    assert set(report["by_risk_domain"]) == {"governance"}
    assert {item["risk_domain"] for item in report["items"]} == {"governance"}
    assert report["source_backed_mapping_count"] + report["unsourced_mapping_count"] == report["proposed_mapping_count"]


def test_mcp_tools_do_not_call_pre_v1_paths():
    """The MCP engine only serves /api/v1; a pre-v1 string here is a dead tool."""
    source = Path(mcp_server.__file__).read_text(encoding="utf-8")
    stale = [line.strip() for line in source.splitlines() if '_get("/api/' in line and '_get("/api/v1/' not in line]
    assert stale == []


def test_get_ingestion_status_includes_scale(tmp_path):
    server = _seeded_server(tmp_path)
    status = call_tool(server, "get_ingestion_status")
    assert "scale" in status
    assert status["scale"]["mode"]
    assert "eval_accuracy" in status
    assert "catalog_coverage" in status
    assert status["catalog_coverage"]["total"] >= 1


def test_get_ai_governance_local_lake(tmp_path):
    server = _seeded_server(tmp_path)
    status = call_tool(server, "get_ai_governance")
    assert status["frameworks_total"] == 3
    assert "governance_score" in status
    assert status["aibom"]["shipped"] is True


def test_list_eval_runs_returns_list(tmp_path):
    server = _seeded_server(tmp_path)
    runs = call_tool(server, "list_eval_runs", limit=10)
    assert isinstance(runs, list)


def test_run_lake_eval_via_mcp_records_accuracy(tmp_path: Path) -> None:
    from security_lakehouse.scale_synthesis import write_audit_scale_fixture

    lake = tmp_path / "lake"
    lake.mkdir()
    (lake / "raw").mkdir()
    write_audit_scale_fixture(
        lake / "raw" / "connector_events.jsonl",
        12,
        controls_per_event=1,
        open_ratio=0.15,
        seed=8,
    )
    server = mcp_server.build_server(lake)
    result = call_tool_payload(server, "run_lake_eval", actor="mcp-test")
    assert isinstance(result, dict)
    assert result["result"] == "ok"
    assert result["mode"] in {"local_full", "local_incremental"}

    runs = call_tool(server, "list_eval_runs", limit=3)
    assert runs
    latest = runs[0]
    assert latest.get("control_tests_total") is not None
    assert latest.get("pass_rate") is not None

    status = call_tool(server, "get_ingestion_status")
    assert status["eval_accuracy"]["total_tests"] > 0
    assert status["catalog_coverage"]["contract_only"] >= 1


def test_list_connectors_includes_contract_only_entries(tmp_path):
    server = _seeded_server(tmp_path)
    connectors = call_tool(server, "list_connectors", limit=50)
    assert any(row["connector_id"] == "clickhouse-telemetry-lake" for row in connectors)
    contract_only = [row for row in connectors if not row.get("is_implemented")]
    assert len(contract_only) >= 1


def test_posture_as_of_after_snapshot(tmp_path):
    server = _seeded_server(tmp_path)
    call_tool(server, "create_snapshot", reason="mcp-as-of")
    result = call_tool(server, "posture_as_of", as_of="2030-01-01")
    assert result["found"] is True
    assert result["assessment_hash"]


def test_list_controls_returns_seeded_ids(tmp_path):
    server = _seeded_server(tmp_path)
    controls = call_tool(server, "list_controls")
    ids = {row["control_id"] for row in controls}
    assert {"SOC2-CC6.1", "NIST-AI-RMF-MAP-1.5"} <= ids


def test_list_control_tests_shapes(tmp_path):
    server = _seeded_server(tmp_path)
    tests = call_tool(server, "list_control_tests")
    assert {row["test_id"] for row in tests} == {"test-soc2", "test-ai"}


def test_list_evidence_limit(tmp_path):
    server = _seeded_server(tmp_path)
    evidence = call_tool(server, "list_evidence", limit=1)
    assert len(evidence) == 1


def test_list_assets_returns_rows(tmp_path):
    server = _seeded_server(tmp_path)
    assets = call_tool(server, "list_assets")
    assert {row["asset_id"] for row in assets} == {"aws:iam:role/admin", "model:reranker"}


def test_list_violations_open_only(tmp_path):
    server = _seeded_server(tmp_path)
    violations = call_tool(server, "list_violations")
    assert violations
    assert all(row["state"] == "open" for row in violations)
    assert any(row["control_id"] == "SOC2-CC6.1" for row in violations)


def test_list_snapshots_empty_without_snapshots(tmp_path):
    server = _seeded_server(tmp_path)
    assert call_tool(server, "list_snapshots") == []


def test_get_snapshots_integrity_returns_chain(tmp_path):
    server = _seeded_server(tmp_path)
    integrity = call_tool(server, "get_snapshots_integrity")
    assert integrity["ok"] is True
    assert integrity["length"] == 0


def test_get_tracking_integrity_returns_chain(tmp_path):
    server = _seeded_server(tmp_path)
    integrity = call_tool(server, "get_tracking_integrity")
    assert integrity["ok"] is True
    assert "length" in integrity


def test_get_snapshot_detail_after_create(tmp_path):
    server = _seeded_server(tmp_path)
    created = call_tool(server, "create_snapshot", reason="mcp-detail")
    snapshot_path = created["snapshot_path"]
    snapshot_id = Path(snapshot_path).stem
    detail = call_tool(server, "get_snapshot_detail", snapshot_id=snapshot_id)
    assert detail["snapshot_id"] == snapshot_id
    assert "posture" in detail


def test_list_connector_runs_reads_lake(tmp_path):
    server = _seeded_server(tmp_path)
    runs = call_tool(server, "list_connector_runs", connector_id="aws-posture", limit=10)
    assert isinstance(runs, list)


def test_list_connectors_returns_catalog(tmp_path):
    server = _seeded_server(tmp_path)
    connectors = call_tool(server, "list_connectors", limit=25)
    assert isinstance(connectors, list)
    assert any(row.get("connector_id") == "aws-posture" for row in connectors)


def test_probe_connector_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_post(path, payload, lake_dir):
        calls.append({"path": path, "payload": payload, "lake": lake_dir})
        return HTTPStatus.CREATED, {"data": {"connector_id": "aws-posture", "result": "ok"}, "errors": []}

    monkeypatch.setattr(mcp_server.api_v1, "handle_post", fake_post)
    result = call_tool(
        server,
        "probe_connector",
        connector_id="aws-posture",
        credentials_json='{"role_arn":"arn:aws:iam::123:role/TrustOps"}',
    )
    assert result == "ok"
    assert calls[0]["path"].endswith("/aws-posture/probe")
    assert calls[0]["payload"]["credentials"]["role_arn"].startswith("arn:aws")


def test_discover_connector_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_post(path, payload, lake_dir):
        assert path.endswith("/github-security/discover")
        return HTTPStatus.CREATED, {"data": {"connector_id": "github-security", "kind": "discover"}, "errors": []}

    monkeypatch.setattr(mcp_server.api_v1, "handle_post", fake_post)
    result = call_tool(server, "discover_connector", connector_id="github-security")
    assert result["kind"] == "discover"


def test_configure_connector_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_post(path, payload, lake_dir):
        assert path.endswith("/aws-posture/configure")
        assert payload["state"] == "enabled"
        assert payload["options"]["sync_schedule"] == "every 15m"
        return HTTPStatus.CREATED, {"data": {"connector_id": "aws-posture", "state": "enabled"}, "errors": []}

    monkeypatch.setattr(mcp_server.api_v1, "handle_post", fake_post)
    result = call_tool(
        server,
        "configure_connector",
        connector_id="aws-posture",
        options_json='{"sync_schedule":"every 15m"}',
    )
    assert result["state"] == "enabled"


def test_list_frameworks_non_empty(tmp_path):
    server = _seeded_server(tmp_path)
    frameworks = call_tool(server, "list_frameworks")
    assert isinstance(frameworks, list)
    assert frameworks


def test_describe_api_lists_resources(tmp_path):
    server = _seeded_server(tmp_path)
    catalog = call_tool(server, "describe_api")
    paths = {row["path"] for row in catalog}
    assert "/api/v1/posture/current" in paths
    assert "/api/v1/controls" in paths
    assert "/api/v1/audit-log" in paths
    assert "/api/v1/platform/audit-readiness" in paths
    assert "/api/v1/platform/ai-governance" in paths
    assert "/api/v1/insights/remediation" in paths
    assert "/api/v1/vendor-assessments" in paths


def test_list_audit_log_returns_entries(tmp_path):
    server = _seeded_server(tmp_path)
    entries = call_tool(server, "list_audit_log", limit=10)
    assert isinstance(entries, list)
    if entries:
        assert "event_id" in entries[0]
        assert "occurred_at" in entries[0]


def test_get_audit_readiness_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/platform/audit-readiness"
        return {"data": {"audit_score": 88, "state": "audit_ready"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_audit_readiness")
    assert result["data"]["audit_score"] == 88


def test_get_framework_detail_soc2(tmp_path):
    server = _seeded_server(tmp_path)
    detail = call_tool(server, "get_framework_detail", framework_id="soc2")
    assert detail["framework"]["framework_id"] == "soc2"
    assert detail["summary"]["control_count"] >= 1
    assert detail["controls"]


def test_get_control_remediation_known_control(tmp_path):
    server = _seeded_server(tmp_path)
    guidance = call_tool(server, "get_control_remediation", control_id="SOC2-CC6.1")
    assert guidance["control_id"] == "SOC2-CC6.1"
    assert guidance["steps"]


def test_get_insights_remediation_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/insights/remediation"
        return {"data": {"open": 3, "overdue": 1}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_insights_remediation")
    assert result["data"]["open"] == 3


def test_get_insights_framework_trends_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/insights/framework-trends"
        assert params.get("limit") == "30"
        return {"data": {"frameworks": ["soc2"], "points": []}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_insights_framework_trends", limit=30)
    assert result["data"]["frameworks"] == ["soc2"]


def test_get_insights_sla_heatmap_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/insights/sla-heatmap"
        return {"data": {"columns": [], "rows": []}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "get_insights_sla_heatmap")


def test_list_vendor_questionnaires_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/vendor-questionnaires"
        return {"data": [{"template_id": "soc2-vendor"}], "meta": {"count": 1}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "list_vendor_questionnaires")
    assert result["data"][0]["template_id"] == "soc2-vendor"


def test_get_poc_readiness_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/platform/poc-readiness"
        return {"data": {"demo_kit": {"ready": True}}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_poc_readiness")
    assert result["data"]["demo_kit"]["ready"] is True


def test_get_vendor_questionnaire_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/vendor-questionnaires/soc2-vendor"
        return {"data": {"template_id": "soc2-vendor"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_vendor_questionnaire", template_id="soc2-vendor")
    assert result["data"]["template_id"] == "soc2-vendor"


def test_get_platform_usage_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/platform/usage"
        return {"data": {"plan": "pilot"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_platform_usage")
    assert result["data"]["plan"] == "pilot"


def test_capture_insights_point_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/insights/capture"
        return {"data": {"score": 82}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "capture_insights_point")
    assert result["data"]["score"] == 82


def test_list_vendor_assessments_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "params": params})
        return {"data": [], "meta": {"count": 0}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "list_vendor_assessments", status="completed", limit=25)
    assert calls[0]["path"] == "/api/v1/vendor-assessments"
    assert calls[0]["params"]["status"] == "completed"
    assert calls[0]["params"]["limit"] == 25


def test_get_vendor_assessment_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/vendor-assessments/va-99"
        return {"data": {"assessment_id": "va-99"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_vendor_assessment", assessment_id="va-99")
    assert result["data"]["assessment_id"] == "va-99"


def test_create_vendor_assessment_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/vendor-assessments"
        assert body["vendor_name"] == "Acme SaaS"
        return {"data": {"assessment_id": "va-new"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "create_vendor_assessment", vendor_name="Acme SaaS", template_id="soc2-vendor")
    assert result["data"]["assessment_id"] == "va-new"


def test_submit_vendor_assessment_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/vendor-assessments/va-99/submit"
        return {"data": {"assessment_id": "va-99", "status": "submitted"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "submit_vendor_assessment", assessment_id="va-99")
    assert result["data"]["status"] == "submitted"


def test_list_policy_templates_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/policy-templates"
        return {"data": [{"template_id": "acceptable-use"}], "meta": {"count": 1}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "list_policy_templates")
    assert result["data"][0]["template_id"] == "acceptable-use"


def test_get_policy_template_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/policy-templates/acceptable-use"
        return {"data": {"template_id": "acceptable-use"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_policy_template", template_id="acceptable-use")
    assert result["data"]["template_id"] == "acceptable-use"


def test_get_policy_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/policies/doc-123"
        return {"data": {"document_id": "doc-123"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_policy", document_id="doc-123")
    assert result["data"]["document_id"] == "doc-123"


def test_list_access_reviews_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "params": params})
        return {"data": [], "meta": {"count": 0}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "list_access_reviews", status="active", limit=10)
    assert calls[0]["path"] == "/api/v1/access-reviews"
    assert calls[0]["params"]["status"] == "active"
    assert calls[0]["params"]["limit"] == 10


def test_get_access_review_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/access-reviews/camp-1"
        return {"data": {"campaign_id": "camp-1"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_access_review", campaign_id="camp-1")
    assert result["data"]["campaign_id"] == "camp-1"


def test_create_access_review_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/access-reviews"
        assert body["name"] == "Q3 SaaS access"
        return {"data": {"campaign_id": "camp-new"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "create_access_review", campaign_name="Q3 SaaS access")
    assert result["data"]["campaign_id"] == "camp-new"


def test_seed_access_review_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/access-reviews/camp-1/seed"
        return {"data": {"seeded": 12}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "seed_access_review", campaign_id="camp-1")
    assert result["data"]["seeded"] == 12


def test_record_access_review_decision_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/access-reviews/items/item-7/decision"
        assert body == {"decision": "certify", "note": "still needed"}
        return {"data": {"item_id": "item-7", "decision": "certify"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "record_access_review_decision", item_id="item-7", decision="certify", note="still needed")


def test_list_access_review_items_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/access-reviews/camp-1/items"
        assert params.get("decision") == "pending"
        return {"data": [{"item_id": "item-1"}], "meta": {"count": 1}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "list_access_review_items", campaign_id="camp-1", decision="pending")
    assert result["data"][0]["item_id"] == "item-1"


def test_get_access_reviews_coverage_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/access-reviews/coverage"
        return {"data": [{"control_id": "CC6.1"}], "meta": {"count": 1}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_access_reviews_coverage")
    assert result["meta"]["count"] == 1


def test_list_risks_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "params": params})
        return {"data": [], "meta": {"count": 0}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "list_risks", status="open", severity="high", owner="alice", limit=50)
    assert calls[0]["path"] == "/api/v1/risks"
    assert calls[0]["params"]["status"] == "open"
    assert calls[0]["params"]["severity"] == "high"
    assert calls[0]["params"]["owner"] == "alice"
    assert calls[0]["params"]["limit"] == 50


def test_create_risk_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/risks"
        assert body["title"] == "Third-party API outage"
        assert body["severity"] == "high"
        return {"data": {"id": "risk-1", "title": "Third-party API outage"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "create_risk",
        title="Third-party API outage",
        severity="high",
        owner="security@example.com",
    )
    assert result["data"]["id"] == "risk-1"


def test_update_risk_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "PATCH"
        assert path == "/api/v1/risks/risk-1"
        assert body == {"status": "mitigated", "owner": "grc@example.com"}
        return {"data": {"id": "risk-1", "status": "mitigated"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "update_risk",
        risk_id="risk-1",
        status="mitigated",
        owner="grc@example.com",
    )
    assert result["data"]["status"] == "mitigated"


def test_delete_risk_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "DELETE"
        assert path == "/api/v1/risks/risk-9"
        return {"data": {"id": "risk-9", "deleted": True}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "delete_risk", risk_id="risk-9")
    assert result["data"]["deleted"] is True


def test_create_remediation_exception_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/remediation/exceptions"
        assert body["control_id"] == "SOC2-CC6.1"
        assert body["reason"] == "Compensating IAM review"
        return {"data": {"id": "exc-1", "control_id": "SOC2-CC6.1"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "create_remediation_exception",
        control_id="SOC2-CC6.1",
        reason="Compensating IAM review",
    )
    assert result["data"]["id"] == "exc-1"


def test_revoke_remediation_exception_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "DELETE"
        assert path == "/api/v1/remediation/exceptions/exc-1"
        return {"data": {"id": "exc-1", "active": False}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "revoke_remediation_exception", exception_id="exc-1")
    assert result["data"]["active"] is False


def test_list_remediation_exceptions_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "params": params})
        return {"data": [], "meta": {"count": 0}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "list_remediation_exceptions", active_only=True, limit=25)
    assert calls[0]["path"] == "/api/v1/remediation/exceptions"
    assert calls[0]["params"]["active"] == "true"
    assert calls[0]["params"]["limit"] == 25


def test_get_policies_coverage_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/policies/coverage"
        return {"data": [{"control_id": "SOC2-CC6.1"}], "meta": {"count": 1}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_policies_coverage")
    assert result["data"][0]["control_id"] == "SOC2-CC6.1"


def test_get_remediation_task_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/remediation/tasks/task-42"
        return {"data": {"id": "task-42", "title": "Fix CC6.1"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_remediation_task", task_id="task-42")
    assert result["data"]["id"] == "task-42"


def test_update_remediation_task_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "PATCH"
        assert path == "/api/v1/remediation/tasks/task-42"
        assert body == {"status": "closed", "owner": "secops@example.com"}
        return {"data": {"id": "task-42", "status": "closed"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "update_remediation_task",
        task_id="task-42",
        status="closed",
        owner="secops@example.com",
    )
    assert result["data"]["status"] == "closed"


def test_update_evidence_request_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "PATCH"
        assert path == "/api/v1/remediation/evidence-requests/req-7"
        assert body == {"status": "fulfilled"}
        return {"data": {"id": "req-7", "status": "fulfilled"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "update_evidence_request", request_id="req-7", status="fulfilled")
    assert result["data"]["status"] == "fulfilled"


def test_list_evidence_requests_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "params": params})
        return {"data": [], "meta": {"count": 0}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "list_evidence_requests", status="open", limit=5)
    assert calls[0]["path"] == "/api/v1/remediation/evidence-requests"
    assert calls[0]["params"]["status"] == "open"


def test_list_trust_shares_reads_lake(tmp_path):
    server = _seeded_server(tmp_path)
    result = call_tool(server, "list_trust_shares")
    assert isinstance(result, list)


def test_create_trust_share_writes_lake(tmp_path):
    server = _seeded_server(tmp_path)
    share = call_tool(server, "create_trust_share", expires_in_hours=48, idempotency_key="mcp-share-1")
    assert share["share_id"]
    assert share["token"].startswith("trust_")
    again = call_tool(server, "create_trust_share", idempotency_key="mcp-share-1")
    assert again.get("idempotent_replay") is True


def test_get_policy_attestation_summary_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "GET"
        assert path == "/api/v1/policies/attestation-summary"
        return {"data": {"published": 2, "unattested": 1}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "get_policy_attestation_summary")
    assert result["data"]["unattested"] == 1


def test_adopt_policy_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "body": body})
        return {"data": {"document_id": "doc-1"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "adopt_policy", template_id="acceptable-use", owner="security@example.com")
    assert calls[0]["path"] == "/api/v1/policies"
    assert calls[0]["body"]["template_id"] == "acceptable-use"


def test_publish_policy_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/policies/doc-1/publish"
        return {"data": {"document_id": "doc-1", "status": "published"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "publish_policy", document_id="doc-1")
    assert result["data"]["status"] == "published"


def test_acknowledge_policy_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/policies/doc-1/acknowledgments"
        assert body == {"display_name": "Alice", "user_email": "alice@example.com"}
        return {"data": {"user_email": "alice@example.com"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    call_tool(server, "acknowledge_policy", document_id="doc-1", user_email="alice@example.com", display_name="Alice")


def test_mcp_agent_run_tools_call_authenticated_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)
    calls = []

    def fake_request(method, path, body=None, **params):
        calls.append({"method": method, "path": path, "body": body, "params": params})
        return {"data": {"ok": True}, "meta": {"resource": "agent-runs"}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)

    listed = call_tool(server, "list_agent_runs", limit=7, harness="posture_review", status="completed")
    assert listed["data"]["ok"] is True
    created = call_tool(
        server,
        "create_agent_run",
        harness="soc_triage",
        objective="triage current alerts",
        role="read_only",
        idempotency_key="mcp-run-1",
        orchestrator="sequential",
        use_model=False,
        max_fact_items=5,
    )
    assert created["meta"]["resource"] == "agent-runs"
    fetched = call_tool(server, "get_agent_run", run_id="run/id with space")
    approved = call_tool(server, "approve_agent_decision", run_id="run/id with space", decision_index=2, note="ok")
    assert fetched["data"]["ok"] is True
    assert approved["data"]["ok"] is True

    assert calls[0] == {
        "method": "GET",
        "path": "/api/v1/agent-runs",
        "body": None,
        "params": {"limit": 7, "harness": "posture_review", "status": "completed"},
    }
    assert calls[1]["method"] == "POST"
    assert calls[1]["path"] == "/api/v1/agent-runs"
    assert calls[1]["body"] == {
        "harness": "soc_triage",
        "objective": "triage current alerts",
        "role": "read_only",
        "idempotency_key": "mcp-run-1",
        "orchestrator": "sequential",
        "use_model": False,
        "max_fact_items": 5,
    }
    assert calls[2]["path"] == "/api/v1/agent-runs/run%2Fid%20with%20space"
    assert calls[3]["path"] == "/api/v1/agent-runs/run%2Fid%20with%20space/decisions/2/approve"
    assert calls[3]["body"] == {"note": "ok"}

    rejected = call_tool(
        server, "reject_agent_decision", run_id="run/id with space", decision_index=1, reason="covered elsewhere"
    )
    assert rejected["data"]["ok"] is True
    assert calls[4]["path"] == "/api/v1/agent-runs/run%2Fid%20with%20space/decisions/1/reject"
    assert calls[4]["body"] == {"reason": "covered elsewhere"}


def test_list_evidence_freshness_reads_lake(tmp_path):
    server = _seeded_server(tmp_path)
    rows = call_tool(server, "list_evidence_freshness", limit=10)
    assert isinstance(rows, list)


def test_get_repository_graph_reads_lake(tmp_path):
    server = _seeded_server(tmp_path)
    graph = call_tool(server, "get_repository_graph")
    assert isinstance(graph, dict)
    assert "nodes" in graph and "edges" in graph
    assert isinstance(graph["nodes"], list)


def test_create_poam_item_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/gov-compliance/poam"
        assert body["requirement_id"] == "3.1.1"
        assert body["title"] == "MFA gap"
        return {"data": {"id": "poam-1", "title": "MFA gap"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "create_poam_item",
        requirement_id="3.1.1",
        control_id="CMMC-AC-1",
        title="MFA gap",
    )
    assert result["data"]["id"] == "poam-1"


def test_update_poam_item_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "PATCH"
        assert path == "/api/v1/gov-compliance/poam/poam-1"
        assert body == {"status": "closed", "owner": "ciso@example.com"}
        return {"data": {"id": "poam-1", "status": "closed"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "update_poam_item",
        item_id="poam-1",
        status="closed",
        owner="ciso@example.com",
    )
    assert result["data"]["status"] == "closed"


def test_attach_tag_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/tags/attach"
        assert body == {"tag_id": "tag-1", "entity_type": "control", "entity_id": "SOC2-CC6.1"}
        return {"data": {"tag_id": "tag-1"}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(
        server,
        "attach_tag",
        tag_id="tag-1",
        entity_type="control",
        entity_id="SOC2-CC6.1",
    )
    assert result["data"]["tag_id"] == "tag-1"


def test_detach_tag_calls_api(tmp_path, monkeypatch):
    server = _seeded_server(tmp_path)

    def fake_request(method, path, body=None, **params):
        assert method == "POST"
        assert path == "/api/v1/tags/detach"
        assert body == {"tag_id": "tag-1", "entity_type": "control", "entity_id": "SOC2-CC6.1"}
        return {"data": {"detached": True}, "meta": {}, "errors": []}

    monkeypatch.setattr(mcp_server, "_server_api_request", fake_request)
    result = call_tool(server, "detach_tag", tag_id="tag-1", entity_type="control", entity_id="SOC2-CC6.1")
    assert result["data"]["detached"] is True
