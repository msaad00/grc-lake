"""BYO cloud model providers: Bedrock, Vertex AI, and Snowflake Cortex.

These providers authenticate through an ambient credential chain (an IAM role,
Application Default Credentials, or a Snowflake key-pair) instead of an API key,
so the tests cover config semantics, dispatch, and the credential-missing error
paths. Live inference is validated against real accounts out of band.
"""

from __future__ import annotations

from typing import Any

import pytest

from security_lakehouse.agents import model_client
from security_lakehouse.agents.model_client import ModelClientError, call_model_json
from security_lakehouse.agents.providers import (
    SUPPORTED_PROVIDERS,
    ModelProviderConfig,
    normalize_provider,
    provider_from_env,
)

CLOUD_PROVIDERS = ("bedrock", "vertex", "snowflake_cortex")


# --- registration + normalization -------------------------------------------


@pytest.mark.parametrize("name", CLOUD_PROVIDERS)
def test_cloud_providers_are_registered(name: str) -> None:
    assert name in SUPPORTED_PROVIDERS
    assert normalize_provider(name) == name


def test_unknown_provider_falls_back_to_rules_only() -> None:
    assert normalize_provider("totally-made-up") == "rules_only"


# --- enabled / ambient-credential semantics ---------------------------------


def test_bedrock_enabled_on_model_alone() -> None:
    cfg = ModelProviderConfig(provider="bedrock", model="anthropic.claude-3-5-sonnet-20240620-v1:0")
    assert cfg.enabled is True
    assert cfg.uses_ambient_credentials is True
    # No API key env is consulted for ambient-credential providers.
    assert cfg.public_dict()["ambient_credentials"] is True


def test_vertex_requires_project_to_be_configured() -> None:
    assert ModelProviderConfig(provider="vertex", model="gemini-1.5-pro").enabled is False
    assert ModelProviderConfig(provider="vertex", model="gemini-1.5-pro", project="acme-prod").enabled is True


def test_cortex_enabled_on_model_alone() -> None:
    assert ModelProviderConfig(provider="snowflake_cortex", model="mistral-large2").enabled is True


def test_public_dict_carries_no_secrets() -> None:
    cfg = ModelProviderConfig(provider="vertex", model="gemini-1.5-pro", project="acme-prod", location="us-east4")
    meta = cfg.public_dict()
    assert meta["project"] == "acme-prod"
    assert meta["location"] == "us-east4"
    assert "api_key" not in meta
    assert "private_key" not in str(meta).lower()


def test_provider_from_env_reads_cloud_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_LAKE_AGENT_PROVIDER", "vertex")
    monkeypatch.setenv("GRC_LAKE_AGENT_MODEL", "gemini-1.5-pro")
    monkeypatch.setenv("GRC_LAKE_AGENT_PROJECT", "acme-prod")
    monkeypatch.delenv("GRC_LAKE_AGENT_LOCATION", raising=False)
    cfg = provider_from_env()
    assert cfg.provider == "vertex"
    assert cfg.project == "acme-prod"
    assert cfg.location == "us-central1"  # sensible default for vertex
    assert cfg.enabled is True


def test_provider_from_env_bedrock_inherits_aws_region(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_LAKE_AGENT_PROVIDER", "bedrock")
    monkeypatch.delenv("GRC_LAKE_AGENT_REGION", raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert provider_from_env().region == "eu-west-1"


# --- dispatch ---------------------------------------------------------------


@pytest.mark.parametrize("name", CLOUD_PROVIDERS)
def test_call_model_json_dispatches_to_cloud_provider(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
        seen["provider"] = provider.provider
        return {"ok": True}

    monkeypatch.setattr(model_client, f"_call_{'cortex' if name == 'snowflake_cortex' else name}", fake)
    result = call_model_json({}, ModelProviderConfig(provider=name, model="m", project="p"))
    assert result == {"ok": True}
    assert seen["provider"] == name


# --- credential / config error paths (no SDKs required) ---------------------


def test_bedrock_without_region_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    cfg = ModelProviderConfig(provider="bedrock", model="anthropic.claude-3-5-sonnet-20240620-v1:0")
    with pytest.raises(ModelClientError, match="region"):
        call_model_json({}, cfg)


def test_vertex_without_project_raises_clear_error() -> None:
    with pytest.raises(ModelClientError, match="project"):
        call_model_json({}, ModelProviderConfig(provider="vertex", model="gemini-1.5-pro"))


def test_cortex_without_snowflake_env_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY_FILE"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ModelClientError, match="SNOWFLAKE_ACCOUNT"):
        call_model_json({}, ModelProviderConfig(provider="snowflake_cortex", model="mistral-large2"))


def test_missing_model_raises_for_each_cloud_provider() -> None:
    for name in CLOUD_PROVIDERS:
        with pytest.raises(ModelClientError, match="GRC_LAKE_AGENT_MODEL"):
            call_model_json({}, ModelProviderConfig(provider=name, project="p"))


# --- Cortex runs inside the warehouse ---------------------------------------


class _CortexCursor:
    def __init__(self, answer: str | None) -> None:
        self.answer = answer
        self.calls: list[tuple[str, Any]] = []

    def execute(self, sql: str, params: Any = None) -> None:
        self.calls.append((sql, params))

    def fetchone(self) -> tuple[Any]:
        return (self.answer,)

    def close(self) -> None:
        pass


class _CortexConn:
    def __init__(self, answer: str | None) -> None:
        self.cur = _CortexCursor(answer)
        self.closed = False

    def cursor(self) -> _CortexCursor:
        return self.cur

    def close(self) -> None:
        self.closed = True


class _CortexConnector:
    def __init__(self, answer: str | None) -> None:
        self.conn = _CortexConn(answer)

    def connect(self, **_kwargs: Any) -> _CortexConn:
        return self.conn


def _cortex_sink(answer: str | None) -> Any:
    from security_lakehouse.sinks.snowflake_sink import SnowflakeSink, SnowflakeSinkConfig

    cfg = SnowflakeSinkConfig(account="acct", user="svc", private_key_file="/unused")
    connector = _CortexConnector(answer)
    sink = SnowflakeSink(cfg, connector=connector, private_key_der=b"der")
    return sink, connector


def test_cortex_complete_runs_in_warehouse_and_closes_connection() -> None:
    sink, connector = _cortex_sink('{"summary": "ok"}')
    out = sink.cortex_complete("mistral-large2", "redacted prompt")
    assert out == '{"summary": "ok"}'
    sql, params = connector.conn.cur.calls[0]
    assert "SNOWFLAKE.CORTEX.COMPLETE" in sql
    assert params == {"model": "mistral-large2", "prompt": "redacted prompt"}
    assert connector.conn.closed is True


def test_cortex_complete_raises_on_empty_response() -> None:
    sink, _connector = _cortex_sink(None)
    with pytest.raises(RuntimeError, match="no content"):
        sink.cortex_complete("mistral-large2", "p")
