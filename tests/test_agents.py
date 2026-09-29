"""Optional agent harness tests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from security_lakehouse.agents import AgentBudgetPolicy, build_posture_review_graph, run_posture_review, run_soc_triage
from security_lakehouse.agents import model_client as agent_model_client
from security_lakehouse.agents.evaluations import evaluate_agent_run
from security_lakehouse.agents.model_client import ModelClientError
from security_lakehouse.agents.model_contract import build_model_context, validate_model_output
from security_lakehouse.agents.providers import ModelProviderConfig, provider_from_env
from security_lakehouse.agents.state import AgentDecision
from security_lakehouse.agents.tools import assess_data_readiness
from security_lakehouse.cli import main
from test_api_v1 import _seed_lake


def _seed_gap(lake: Path) -> None:
    _seed_lake(lake)
    rows = [
        {
            "test_id": "test-soc2",
            "control_id": "SOC2-CC6.1",
            "framework": "SOC 2",
            "owner": "security-platform",
            "status": "needs_evidence",
            "missing_evidence_types": ["identity.access_review"],
            "stale_evidence_types": [],
            "expired_evidence_types": ["mfa.status"],
            "freshness_status": "expired",
        }
    ]
    (lake / "gold" / "control_tests.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def _seed_soc_alerts(lake: Path) -> None:
    _seed_lake(lake)
    rows = [
        {
            "event_id": "det-001",
            "event_time": "2026-06-01T10:00:00Z",
            "event_type": "detection.alert",
            "source": "siem",
            "asset_id": "host:api-1",
            "asset_type": "host",
            "asset_owner": "secops",
            "environment": "prod",
            "status": "open",
            "severity": "critical",
            "severity_score": 100,
            "control_ids": ["SOC2-CC7.2"],
            "evidence_ref": "s3://evidence/det-001.json",
            "raw_sha256": "aaa",
        },
        {
            "event_id": "vuln-001",
            "event_time": "2026-06-01T09:00:00Z",
            "event_type": "vulnerability.finding",
            "source": "scanner",
            "asset_id": "container:web",
            "asset_type": "container",
            "asset_owner": "appsec",
            "environment": "prod",
            "status": "open",
            "severity": "high",
            "severity_score": 80,
            "control_ids": ["SOC2-CC7.2"],
            "evidence_ref": "s3://evidence/vuln-001.json",
            "raw_sha256": "bbb",
        },
        {
            "event_id": "runtime-001",
            "event_time": "2026-06-01T08:00:00Z",
            "event_type": "runtime.policy_decision",
            "source": "gateway",
            "asset_id": "agent:helpdesk",
            "asset_type": "agent",
            "asset_owner": "it",
            "environment": "prod",
            "status": "open",
            "severity": "medium",
            "severity_score": 50,
            "control_ids": ["NIST-AI-RMF-MEASURE-2.7"],
            "evidence_ref": "s3://evidence/runtime-001.json",
            "raw_sha256": "ccc",
        },
        {
            "event_id": "closed-001",
            "event_time": "2026-06-01T07:00:00Z",
            "event_type": "detection.alert",
            "source": "siem",
            "asset_id": "host:old",
            "asset_type": "host",
            "asset_owner": "secops",
            "environment": "prod",
            "status": "resolved",
            "severity": "critical",
            "severity_score": 100,
            "control_ids": ["SOC2-CC7.2"],
            "evidence_ref": "s3://evidence/closed-001.json",
            "raw_sha256": "ddd",
        },
    ]
    (lake / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_posture_review_runs_without_langgraph_or_llm(tmp_path: Path) -> None:
    _seed_gap(tmp_path)

    state = run_posture_review(tmp_path, role="read_only")

    assert state["mode"] == "rules_only"
    assert state["posture"]["posture"]["control_count"] >= 1
    assert state["evidence_gaps"][0]["control_id"] == "SOC2-CC6.1"
    assert state["decisions"][0].action == "create_evidence_request"
    assert state["decisions"][0].requires_approval is True
    assert state["decisions"][0].status == "proposed"
    assert state["evaluation"]["ok"] is True
    assert state["evaluation"]["confidence"] == "high"
    assert state["evaluation"]["score"] == 100
    assert state["evaluation"]["coverage"]["evidence_gap_coverage"] == 1.0


def test_posture_review_uses_role_redaction(tmp_path: Path) -> None:
    _seed_gap(tmp_path)

    state = run_posture_review(tmp_path, role="auditor")

    assert state["evidence_gaps"][0]["owner"] == "[redacted]"


def test_data_readiness_reports_empty_lake_next_steps_without_path_leak(tmp_path: Path) -> None:
    readiness = assess_data_readiness(tmp_path, role="read_only", harness="posture_review")

    assert readiness["status"] == "needs_ingestion"
    assert readiness["ready_for_harness"] is False
    assert readiness["required_artifacts"] == ["gold.control_tests", "silver.normalized_events"]
    assert readiness["missing_required_artifacts"] == ["gold.control_tests", "silver.normalized_events"]
    silver_status = next(row for row in readiness["artifact_status"] if row["artifact"] == "silver.normalized_events")
    assert silver_status == {
        "artifact": "silver.normalized_events",
        "relative_path": "silver/normalized_events.jsonl",
        "rows": 0,
        "required": True,
        "present": False,
    }
    commands = [step["command"] for step in readiness["recommended_next_steps"]]
    assert "security-lakehouse connectors list --lake <lake>" in commands
    assert "security-lakehouse pipeline run --raw <raw_events.jsonl> --out <lake>" in commands
    assert str(tmp_path) not in json.dumps(readiness, sort_keys=True)


def test_data_readiness_reports_partial_lake_gold_gap(tmp_path: Path) -> None:
    rows = [{"event_id": f"event-{index}", "severity": "medium"} for index in range(4)]
    (tmp_path / "silver").mkdir(parents=True, exist_ok=True)
    (tmp_path / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )

    readiness = assess_data_readiness(tmp_path, role="read_only", harness="posture_review")

    assert readiness["status"] == "partial_lake"
    assert readiness["ready_for_harness"] is False
    assert readiness["missing_required_artifacts"] == ["gold.control_tests"]
    assert readiness["artifact_counts"]["silver.normalized_events"] == 4
    actions = [step["action"] for step in readiness["recommended_next_steps"]]
    assert actions == ["materialize_control_evidence"]


def test_langgraph_builder_is_optional() -> None:
    if importlib.util.find_spec("langgraph") is not None:
        assert build_posture_review_graph() is not None
        return

    with pytest.raises(RuntimeError, match="install trustops-security-data-lake\\[agents\\]"):
        build_posture_review_graph()


def test_posture_review_langgraph_orchestrator_is_explicit(tmp_path: Path) -> None:
    _seed_gap(tmp_path)

    if importlib.util.find_spec("langgraph") is None:
        with pytest.raises(RuntimeError, match="install trustops-security-data-lake\\[agents\\]"):
            run_posture_review(tmp_path, role="read_only", orchestrator="langgraph")
        return

    state = run_posture_review(tmp_path, role="read_only", orchestrator="langgraph")

    assert state["mode"] == "langgraph"
    assert state["orchestrator"] == "langgraph"
    assert state["decisions"][0].action == "create_evidence_request"
    assert state["decisions"][0].requires_approval is True
    assert state["evaluation"]["ok"] is True


def test_posture_review_langgraph_skips_proposals_without_gaps(tmp_path: Path) -> None:
    _seed_lake(tmp_path)

    if importlib.util.find_spec("langgraph") is None:
        with pytest.raises(RuntimeError, match="install trustops-security-data-lake\\[agents\\]"):
            run_posture_review(tmp_path, role="read_only", orchestrator="langgraph")
        return

    state = run_posture_review(tmp_path, role="read_only", orchestrator="langgraph")

    assert state["mode"] == "langgraph"
    assert state["decisions"] == []
    assert state["evaluation"]["ok"] is True


def test_soc_triage_langgraph_orchestrator_is_explicit(tmp_path: Path) -> None:
    _seed_soc_alerts(tmp_path)

    if importlib.util.find_spec("langgraph") is None:
        with pytest.raises(RuntimeError, match="install trustops-security-data-lake\\[agents\\]"):
            run_soc_triage(tmp_path, role="read_only", orchestrator="langgraph")
        return

    state = run_soc_triage(tmp_path, role="read_only", orchestrator="langgraph")

    assert state["mode"] == "langgraph"
    assert state["orchestrator"] == "langgraph"
    assert state["decisions"]
    assert state["evaluation"]["ok"] is True


def test_provider_configured_without_use_model_stays_deterministic(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    provider = ModelProviderConfig(provider="ollama", model="llama3.1", base_url="http://127.0.0.1:11434")

    state = run_posture_review(tmp_path, role="read_only", provider=provider)

    assert state["mode"] == "rules_only"
    assert state["model_provider"]["configured"] is True
    assert state["model_provider"]["use_model"] is False
    assert state["model_context"]["policy"]["compliance_truth"].startswith("TrustOps deterministic")
    assert "model_output" not in state
    assert state["errors"] == []


def test_model_assisted_run_validates_model_output(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    provider = ModelProviderConfig(
        provider="ollama",
        model="llama3.1",
        base_url="http://127.0.0.1:11434",
        use_model=True,
    )

    def fake_model(context: dict, configured: ModelProviderConfig) -> dict:
        assert configured.provider == "ollama"
        assert context["facts"]["evidence_gaps"][0]["control_id"] == "SOC2-CC6.1"
        return {
            "summary": "Evidence is missing for access review.",
            "confidence": 0.99,
            "priorities": [{"control_id": "SOC2-CC6.1", "reason": "expired MFA status", "rank": 1}],
            "proposed_tool_calls": [
                {
                    "name": "create_remediation_task",
                    "arguments": {"control_id": "SOC2-CC6.1", "reason": "owner follow-up"},
                },
                {"name": "mark_control_passed", "arguments": {"control_id": "SOC2-CC6.1"}},
            ],
        }

    state = run_posture_review(tmp_path, role="read_only", provider=provider, model_client=fake_model)

    assert state["mode"] == "model_assisted"
    assert state["model_output"]["summary"] == "Evidence is missing for access review."
    assert "confidence" not in state["model_output"]
    assert state["evaluation"]["confidence"] == "medium"
    assert state["evaluation"]["coverage"]["model_rejected_tool_calls"] == 1
    assert state["model_output"]["priorities"][0]["control_id"] == "SOC2-CC6.1"
    assert state["model_output"]["proposed_tool_calls"][0]["requires_approval"] is True
    assert state["model_output"]["rejected_tool_calls"] == ["mark_control_passed"]
    assert state["decisions"][0].requires_approval is True
    assert state["decisions"][0].status == "proposed"


def test_model_context_budget_compacts_fact_lists() -> None:
    provider = ModelProviderConfig(provider="ollama", model="llama3.1", base_url="http://127.0.0.1:11434")
    state = {
        "objective": "triage",
        "role": "read_only",
        "alerts": [
            {
                "event_id": f"det-{index:03d}",
                "severity": "critical",
                "detail": "x" * 500,
            }
            for index in range(12)
        ],
        "decisions": [],
    }

    context = build_model_context(
        state,
        provider,
        use_case="soc_triage",
        budget=AgentBudgetPolicy(max_context_chars=6_000, max_fact_items=2, max_output_tokens=128),
    )

    assert len(context["facts"]["alerts"]) == 2
    assert context["budget"]["status"] == "within_budget"
    assert context["budget"]["max_output_tokens"] == 128
    assert context["budget"]["omitted"]["facts.alerts"] == 10


def test_model_client_receives_output_token_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_post_json(url: str, payload: dict, *, headers: dict[str, str], timeout: float) -> dict:
        captured["url"] = url
        captured["payload"] = payload
        return {"message": {"content": "{}"}}

    monkeypatch.setattr(agent_model_client, "_post_json", fake_post_json)
    provider = ModelProviderConfig(provider="ollama", model="llama3.1", base_url="http://127.0.0.1:11434")

    assert agent_model_client.call_model_json({"budget": {"max_output_tokens": 128}}, provider) == {}

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["options"] == {"num_predict": 128}


def test_openai_compatible_choice_without_message_is_a_model_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post_json(url: str, payload: dict, *, headers: dict[str, str], timeout: float) -> dict:
        return {"choices": [{"finish_reason": "length"}]}

    monkeypatch.setattr(agent_model_client, "_post_json", fake_post_json)
    monkeypatch.setattr(agent_model_client.netguard, "assert_url_is_public", lambda *_a, **_k: None)
    monkeypatch.setenv("TRUSTOPS_TEST_MODEL_KEY", "test-key")
    provider = ModelProviderConfig(
        provider="openai_compatible",
        model="gpt-test",
        base_url="https://models.example.com/v1",
        api_key_env="TRUSTOPS_TEST_MODEL_KEY",
    )

    with pytest.raises(ModelClientError, match="non-JSON"):
        agent_model_client.call_model_json({}, provider)


def test_model_call_is_skipped_when_context_exceeds_budget(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    provider = ModelProviderConfig(
        provider="ollama",
        model="llama3.1",
        base_url="http://127.0.0.1:11434",
        use_model=True,
    )

    def unexpected_model(_context: dict, _configured: ModelProviderConfig) -> dict:
        raise AssertionError("model should not be called when context is over budget")

    state = run_posture_review(
        tmp_path,
        role="read_only",
        provider=provider,
        budget=AgentBudgetPolicy(max_context_chars=256, max_fact_items=1, max_output_tokens=64),
        model_client=unexpected_model,
    )

    assert state["mode"] == "rules_only"
    assert state["model_context"]["budget"]["status"] == "over_budget"
    assert state["errors"] == ["model_skipped: context_budget_exceeded"]
    assert "model_output" not in state
    assert state["evaluation"]["ok"] is True
    assert state["evaluation"]["coverage"]["model_budget_status"] == "over_budget"


def test_posture_model_rejects_soc_only_tools(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    provider = ModelProviderConfig(
        provider="ollama",
        model="llama3.1",
        base_url="http://127.0.0.1:11434",
        use_model=True,
    )

    def fake_model(_context: dict, _configured: ModelProviderConfig) -> dict:
        return {"proposed_tool_calls": [{"name": "create_soc_case", "arguments": {"event_id": "det-001"}}]}

    state = run_posture_review(tmp_path, role="read_only", provider=provider, model_client=fake_model)

    assert state["model_output"]["proposed_tool_calls"] == []
    assert state["model_output"]["rejected_tool_calls"] == ["create_soc_case"]
    assert state["evaluation"]["confidence"] == "medium"


def test_agent_evaluation_flags_unsafe_write_actions() -> None:
    result = evaluate_agent_run(
        {
            "mode": "rules_only",
            "decisions": [
                AgentDecision(
                    action="freeze_snapshot",
                    reason="unsafe test",
                    requires_approval=False,
                    payload={"reason": "unsafe test"},
                    status="executed",
                )
            ],
            "errors": [],
        },
        use_case="posture_review",
    )

    assert result["ok"] is False
    assert result["confidence"] == "low"
    assert result["risk_level"] == "critical"
    assert result["failures"][0]["check"] == "writes_are_approval_gated"


def test_soc_triage_harness_is_deterministic_and_evaluated(tmp_path: Path) -> None:
    _seed_soc_alerts(tmp_path)

    state = run_soc_triage(tmp_path, role="read_only")

    assert state["mode"] == "rules_only"
    assert [alert["event_id"] for alert in state["alerts"]] == ["det-001", "vuln-001", "runtime-001"]
    assert state["evaluation"]["ok"] is True
    assert state["evaluation"]["confidence"] == "high"
    assert state["evaluation"]["score"] == 100
    assert state["evaluation"]["coverage"]["high_priority_coverage"] == 1.0
    assert {decision.action for decision in state["decisions"]} >= {"create_soc_case", "assign_owner", "enrich_alert"}
    assert all(decision.requires_approval for decision in state["decisions"])
    covered = {decision.payload["event_id"] for decision in state["decisions"]}
    assert {"det-001", "vuln-001"}.issubset(covered)


def test_soc_triage_uses_role_redaction(tmp_path: Path) -> None:
    _seed_soc_alerts(tmp_path)

    state = run_soc_triage(tmp_path, role="auditor")

    assert state["alerts"][0]["asset_owner"] == "[redacted]"
    owner_decisions = [decision for decision in state["decisions"] if decision.action == "assign_owner"]
    assert owner_decisions[0].payload["owner"] == "[redacted]"


def test_soc_model_output_is_limited_to_soc_tools(tmp_path: Path) -> None:
    _seed_soc_alerts(tmp_path)
    provider = ModelProviderConfig(
        provider="ollama",
        model="llama3.1",
        base_url="http://127.0.0.1:11434",
        use_model=True,
    )

    def fake_model(context: dict, configured: ModelProviderConfig) -> dict:
        assert configured.provider == "ollama"
        assert context["use_case"] == "soc_triage"
        assert context["facts"]["alerts"][0]["event_id"] == "det-001"
        return {
            "summary": "Critical alert should be opened as a SOC case.",
            "proposed_tool_calls": [
                {"name": "create_soc_case", "arguments": {"event_id": "det-001", "reason": "critical"}},
                {"name": "delete_evidence", "arguments": {"event_id": "det-001"}},
            ],
        }

    state = run_soc_triage(tmp_path, role="read_only", provider=provider, model_client=fake_model)

    assert state["mode"] == "model_assisted"
    assert state["model_output"]["proposed_tool_calls"][0]["name"] == "create_soc_case"
    assert state["model_output"]["proposed_tool_calls"][0]["requires_approval"] is True
    assert state["model_output"]["rejected_tool_calls"] == ["delete_evidence"]
    assert state["evaluation"]["ok"] is True
    assert state["evaluation"]["confidence"] == "medium"


def test_model_client_error_is_non_fatal(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    provider = ModelProviderConfig(
        provider="ollama",
        model="llama3.1",
        base_url="http://127.0.0.1:11434",
        use_model=True,
    )

    def failing_model(_context: dict, _configured: ModelProviderConfig) -> dict:
        raise ModelClientError("offline")

    state = run_posture_review(tmp_path, role="read_only", provider=provider, model_client=failing_model)

    assert state["mode"] == "rules_only"
    assert state["errors"] == ["model_error: offline"]
    assert state["decisions"][0].action == "create_evidence_request"


def test_validate_model_output_rejects_unsupported_tools() -> None:
    output = validate_model_output(
        {
            "summary": "x",
            "priorities": [{"control_id": "SOC2-CC7.2"}],
            "proposed_tool_calls": [
                {"name": "freeze_snapshot", "arguments": {"reason": "audit"}},
                {"name": "delete_evidence", "arguments": {}},
            ],
        }
    )

    assert output["proposed_tool_calls"] == [
        {"name": "freeze_snapshot", "arguments": {"reason": "audit"}, "requires_approval": True, "status": "proposed"}
    ]
    assert output["rejected_tool_calls"] == ["delete_evidence"]


def test_provider_env_requires_explicit_model_use(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AGENT_PROVIDER", "ollama")
    monkeypatch.setenv("TRUSTOPS_AGENT_MODEL", "llama3.1")
    monkeypatch.delenv("TRUSTOPS_AGENT_USE_MODEL", raising=False)

    provider = provider_from_env()

    assert provider.provider == "ollama"
    assert provider.enabled is True
    assert provider.should_call_model is False


def test_provider_public_metadata_does_not_expose_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AGENT_PROVIDER", "openai")
    monkeypatch.setenv("TRUSTOPS_AGENT_MODEL", "gpt-test")
    monkeypatch.setenv("TRUSTOPS_AGENT_API_KEY_ENV", "TRUSTOPS_TEST_OPENAI_KEY")
    monkeypatch.setenv("TRUSTOPS_TEST_OPENAI_KEY", "secret-test-value")

    provider = provider_from_env()
    metadata = provider.public_dict()

    assert metadata["configured"] is True
    assert metadata["credential_env_configured"] is True
    assert metadata["credential_present"] is True
    assert "api_key_env" not in metadata
    assert "TRUSTOPS_TEST_OPENAI_KEY" not in json.dumps(metadata)
    assert "secret-test-value" not in json.dumps(metadata)


def test_posture_review_cli_outputs_json(tmp_path: Path, capsys) -> None:
    _seed_gap(tmp_path)

    assert main(["agents", "posture-review", "--lake", str(tmp_path), "--role", "auditor"]) == 0
    out = json.loads(capsys.readouterr().out)

    assert out["mode"] == "rules_only"
    assert out["role"] == "auditor"
    assert out["evaluation"]["confidence"] == "high"
    assert out["evidence_gaps"][0]["owner"] == "[redacted]"
    assert out["decisions"][0]["requires_approval"] is True


def test_posture_review_cli_langgraph_orchestrator_requires_extra(tmp_path: Path, capsys) -> None:
    if importlib.util.find_spec("langgraph") is not None:
        pytest.skip("covered by direct LangGraph execution test when the optional extra is installed")
    _seed_gap(tmp_path)

    assert main(["agents", "posture-review", "--lake", str(tmp_path), "--orchestrator", "langgraph"]) == 1
    assert "install trustops-security-data-lake[agents]" in capsys.readouterr().err


def test_posture_review_cli_can_build_model_context_without_call(tmp_path: Path, capsys) -> None:
    _seed_gap(tmp_path)

    assert (
        main(
            [
                "agents",
                "posture-review",
                "--lake",
                str(tmp_path),
                "--provider",
                "ollama",
                "--model",
                "llama3.1",
                "--base-url",
                "http://127.0.0.1:11434",
            ]
        )
        == 0
    )
    out = json.loads(capsys.readouterr().out)

    assert out["mode"] == "rules_only"
    assert out["model_provider"]["configured"] is True
    assert out["model_context"]["tool_manifest"][0]["name"] == "load_redacted_posture"


def test_soc_triage_cli_outputs_evaluated_run(tmp_path: Path, capsys) -> None:
    _seed_soc_alerts(tmp_path)

    assert main(["agents", "soc-triage", "--lake", str(tmp_path), "--role", "auditor"]) == 0
    out = json.loads(capsys.readouterr().out)

    assert out["mode"] == "rules_only"
    assert out["evaluation"]["ok"] is True
    assert out["alerts"][0]["asset_owner"] == "[redacted]"
    assert out["decisions"][0]["requires_approval"] is True


def test_posture_review_cli_does_not_print_model_key_env(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_gap(tmp_path)
    monkeypatch.setenv("TRUSTOPS_TEST_OPENAI_KEY", "secret-test-value")

    assert (
        main(
            [
                "agents",
                "posture-review",
                "--lake",
                str(tmp_path),
                "--provider",
                "openai",
                "--model",
                "gpt-test",
                "--api-key-env",
                "TRUSTOPS_TEST_OPENAI_KEY",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    out = json.loads(output)

    assert out["model_provider"]["configured"] is True
    assert out["model_provider"]["credential_present"] is True
    assert out["model_context"]["provider"]["credential_env_configured"] is True
    assert "api_key_env" not in output
    assert "TRUSTOPS_TEST_OPENAI_KEY" not in output
    assert "secret-test-value" not in output


def test_soc_triage_cli_applies_budget_flags(tmp_path: Path, capsys) -> None:
    _seed_soc_alerts(tmp_path)

    assert (
        main(
            [
                "agents",
                "soc-triage",
                "--lake",
                str(tmp_path),
                "--provider",
                "ollama",
                "--model",
                "llama3.1",
                "--base-url",
                "http://127.0.0.1:11434",
                "--max-fact-items",
                "1",
                "--max-output-tokens",
                "128",
            ]
        )
        == 0
    )
    out = json.loads(capsys.readouterr().out)

    assert out["agent_budget"]["max_fact_items"] == 1
    assert out["model_context"]["budget"]["max_output_tokens"] == 128
    assert out["model_context"]["budget"]["omitted"]["facts.alerts"] == 2
