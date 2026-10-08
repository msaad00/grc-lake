"""Small dependency-free clients for optional model-assisted agent runs."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.agents.model_contract import model_messages
from security_lakehouse.agents.providers import ModelProviderConfig


class ModelClientError(RuntimeError):
    """Raised when an optional model provider cannot return usable JSON."""


def call_model_json(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    """Call the configured provider and return parsed JSON.

    This is deliberately optional and dependency-free. TrustOps remains useful
    when this function is never called.
    """
    if provider.provider == "ollama":
        return _call_ollama(context, provider)
    if provider.provider in {"openai", "openai_compatible"}:
        return _call_openai_compatible(context, provider)
    if provider.provider == "anthropic":
        return _call_anthropic(context, provider)
    if provider.provider == "bedrock":
        return _call_bedrock(context, provider)
    if provider.provider == "vertex":
        return _call_vertex(context, provider)
    if provider.provider == "snowflake_cortex":
        return _call_cortex(context, provider)
    raise ModelClientError(f"unsupported model provider: {provider.provider}")


def _max_output_tokens(context: dict[str, Any], default: int = 600) -> int:
    budget = context.get("budget")
    if not isinstance(budget, dict):
        budget = {}
    value = budget.get("max_output_tokens") if isinstance(budget, dict) else None
    try:
        return max(64, min(int(value or default), 8_000))
    except (TypeError, ValueError):
        return default


def _post_json(url: str, payload: dict[str, Any], *, headers: dict[str, str], timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        raise ModelClientError(str(exc)) from exc


def _parse_json_content(content: str) -> dict[str, Any]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ModelClientError("model returned non-JSON content") from exc
    if not isinstance(payload, dict):
        raise ModelClientError("model returned JSON that is not an object")
    return payload


def _call_ollama(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    if not provider.model:
        raise ModelClientError("TRUSTOPS_AGENT_MODEL is required for ollama")
    url = provider.base_url.rstrip("/") + "/api/chat"
    payload = {
        "model": provider.model,
        "messages": model_messages(context),
        "format": "json",
        "options": {"num_predict": _max_output_tokens(context)},
        "stream": False,
    }
    response = _post_json(url, payload, headers={"Content-Type": "application/json"}, timeout=provider.timeout_seconds)
    message = response.get("message")
    if not isinstance(message, dict):
        message = {}
    return _parse_json_content(str(message.get("content") or ""))


def _call_openai_compatible(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    if not provider.model:
        raise ModelClientError("TRUSTOPS_AGENT_MODEL is required for OpenAI-compatible providers")
    api_key = os.environ.get(provider.api_key_env)
    if not api_key:
        raise ModelClientError(f"{provider.api_key_env} is not set")
    base_url = provider.base_url.rstrip("/") if provider.base_url else "https://api.openai.com/v1"
    try:
        netguard.assert_url_is_public(base_url, label="TRUSTOPS_AGENT_BASE_URL")
    except ValueError as exc:
        raise ModelClientError(str(exc)) from exc
    payload = {
        "model": provider.model,
        "messages": model_messages(context),
        "response_format": {"type": "json_object"},
        "max_tokens": _max_output_tokens(context),
    }
    response = _post_json(
        base_url + "/chat/completions",
        payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        timeout=provider.timeout_seconds,
    )
    choices = response.get("choices")
    if not isinstance(choices, list):
        choices = []
    first = choices[0] if choices else None
    message = first.get("message") if isinstance(first, dict) else None
    if not isinstance(message, dict):
        message = {}
    return _parse_json_content(str(message.get("content") or ""))


def _call_anthropic(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    if not provider.model:
        raise ModelClientError("TRUSTOPS_AGENT_MODEL is required for anthropic")
    api_key = os.environ.get(provider.api_key_env)
    if not api_key:
        raise ModelClientError(f"{provider.api_key_env} is not set")
    anthropic_base = provider.base_url.rstrip("/") if provider.base_url else "https://api.anthropic.com"
    try:
        netguard.assert_url_is_public(anthropic_base, label="TRUSTOPS_AGENT_BASE_URL")
    except ValueError as exc:
        raise ModelClientError(str(exc)) from exc
    messages = model_messages(context)
    payload = {
        "model": provider.model,
        "max_tokens": _max_output_tokens(context),
        "system": messages[0]["content"],
        "messages": [{"role": "user", "content": messages[1]["content"]}],
    }
    response = _post_json(
        anthropic_base + "/v1/messages",
        payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        timeout=provider.timeout_seconds,
    )
    blocks = response.get("content")
    if not isinstance(blocks, list):
        blocks = []
    first = blocks[0] if blocks and isinstance(blocks[0], dict) else {}
    return _parse_json_content(str(first.get("text") or ""))


def _bedrock_runtime_client(region: str) -> Any:
    """Build a Bedrock runtime client. Split out so tests can inject a fake."""
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - exercised only without the aws extra
        raise ModelClientError("install boto3 (the 'aws' extra) to use the bedrock provider") from exc
    return boto3.client("bedrock-runtime", region_name=region)


def _call_bedrock(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    """Call Amazon Bedrock through the model-agnostic Converse API.

    Credentials come from the ambient AWS chain (IAM role / IRSA / env), so no
    API key is held by TrustOps. Converse normalizes the request across model
    families, so any Bedrock chat model works without a per-family schema.
    """
    if not provider.model:
        raise ModelClientError("TRUSTOPS_AGENT_MODEL is required for bedrock")
    region = provider.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        raise ModelClientError("bedrock requires a region (TRUSTOPS_AGENT_REGION or AWS_REGION)")
    messages = model_messages(context)
    client = _bedrock_runtime_client(region)
    try:
        response = client.converse(
            modelId=provider.model,
            system=[{"text": messages[0]["content"]}],
            messages=[{"role": "user", "content": [{"text": messages[1]["content"]}]}],
            inferenceConfig={"maxTokens": _max_output_tokens(context)},
        )
    except Exception as exc:  # botocore ClientError + friends
        raise ModelClientError(f"bedrock: {exc}") from exc
    blocks = response.get("output", {}).get("message", {}).get("content", [])
    text = blocks[0].get("text") if blocks and isinstance(blocks[0], dict) else ""
    return _parse_json_content(str(text or ""))


def _vertex_access_token() -> str:
    """Mint a GCP access token from Application Default Credentials.

    Split out so tests can inject a token without google-auth installed.
    """
    try:
        import google.auth
        import google.auth.transport.requests
    except ImportError as exc:  # pragma: no cover - exercised only without the gcp extra
        raise ModelClientError("install google-auth (the 'gcp' extra) to use the vertex provider") from exc
    credentials, _project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    credentials.refresh(google.auth.transport.requests.Request())
    return str(credentials.token)


def _call_vertex(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    """Call Vertex AI ``generateContent`` with an ADC-minted bearer token."""
    if not provider.model:
        raise ModelClientError("TRUSTOPS_AGENT_MODEL is required for vertex")
    if not provider.project:
        raise ModelClientError("vertex requires a project (TRUSTOPS_AGENT_PROJECT)")
    location = provider.location or "us-central1"
    token = _vertex_access_token()
    messages = model_messages(context)
    url = (
        f"https://{location}-aiplatform.googleapis.com/v1/projects/{provider.project}"
        f"/locations/{location}/publishers/google/models/{provider.model}:generateContent"
    )
    payload = {
        "systemInstruction": {"parts": [{"text": messages[0]["content"]}]},
        "contents": [{"role": "user", "parts": [{"text": messages[1]["content"]}]}],
        "generationConfig": {
            "maxOutputTokens": _max_output_tokens(context),
            "responseMimeType": "application/json",
        },
    }
    response = _post_json(
        url,
        payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        timeout=provider.timeout_seconds,
    )
    candidates = response.get("candidates")
    if not isinstance(candidates, list):
        candidates = []
    content = candidates[0].get("content") if candidates and isinstance(candidates[0], dict) else {}
    parts = content.get("parts") if isinstance(content, dict) and isinstance(content.get("parts"), list) else []
    text = parts[0].get("text") if parts and isinstance(parts[0], dict) else ""
    return _parse_json_content(str(text or ""))


def _call_cortex(context: dict[str, Any], provider: ModelProviderConfig) -> dict[str, Any]:
    """Run inference in-warehouse via Snowflake Cortex so evidence never leaves the lake.

    Reuses the same Snowflake key-pair connection as the medallion sink, so the
    redacted prompt is the only thing that crosses into Snowflake and the
    completion is generated next to the data.
    """
    if not provider.model:
        raise ModelClientError("TRUSTOPS_AGENT_MODEL is required for snowflake_cortex")
    from security_lakehouse.sinks.snowflake_sink import SnowflakeSink, SnowflakeSinkConfig

    config = SnowflakeSinkConfig.from_env(dict(os.environ))
    if config is None:
        raise ModelClientError(
            "snowflake_cortex requires SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, and SNOWFLAKE_PRIVATE_KEY_FILE"
        )
    messages = model_messages(context)
    prompt = f"{messages[0]['content']}\n\n{messages[1]['content']}"
    try:
        text = SnowflakeSink(config).cortex_complete(provider.model, prompt)
    except Exception as exc:
        raise ModelClientError(f"snowflake_cortex: {exc}") from exc
    return _parse_json_content(text)
