"""Model provider configuration for optional agent runs."""

from __future__ import annotations

from dataclasses import dataclass

from security_lakehouse.runtime_environment import runtime_env

SUPPORTED_PROVIDERS = {
    "rules_only",
    "ollama",
    "openai",
    "openai_compatible",
    "anthropic",
    "bedrock",
    "vertex",
    "snowflake_cortex",
}

# Providers that authenticate through an ambient credential chain (an IAM role,
# Application Default Credentials, or a Snowflake key-pair) rather than a single
# ``*_API_KEY`` environment variable. They are "configured" when a model is named;
# the credential itself is resolved and validated at call time.
_AMBIENT_CREDENTIAL_PROVIDERS = {"bedrock", "vertex", "snowflake_cortex"}


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = runtime_env().get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_provider(value: str) -> str:
    provider = value.strip().lower()
    if provider in {"", "none", "off"}:
        return "rules_only"
    if provider not in SUPPORTED_PROVIDERS:
        return "rules_only"
    return provider


@dataclass(frozen=True)
class ModelProviderConfig:
    """LLM provider settings.

    ``rules_only`` means no model is configured. Agent graphs must still run in
    this mode using deterministic GRC Lake facts.
    """

    provider: str = "rules_only"
    model: str = ""
    base_url: str = ""
    api_key_env: str = ""
    use_model: bool = False
    timeout_seconds: float = 20.0
    region: str = ""  # bedrock (AWS region)
    project: str = ""  # vertex (GCP project id)
    location: str = ""  # vertex (GCP location/region)

    @property
    def enabled(self) -> bool:
        if self.provider in {"", "rules_only"}:
            return False
        if self.provider == "ollama":
            return bool(self.base_url)
        if self.provider == "bedrock":
            return bool(self.model)
        if self.provider == "vertex":
            return bool(self.model and self.project)
        if self.provider == "snowflake_cortex":
            return bool(self.model)
        return bool(self.api_key_env and runtime_env().get(self.api_key_env))

    @property
    def should_call_model(self) -> bool:
        """Whether the harness should make a provider request."""
        return self.enabled and self.use_model

    @property
    def uses_ambient_credentials(self) -> bool:
        """True when the provider authenticates via a credential chain, not an API key env."""
        return self.provider in _AMBIENT_CREDENTIAL_PROVIDERS

    def public_dict(self) -> dict[str, object]:
        """Return non-secret provider metadata suitable for audit output."""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "configured": self.enabled,
            "credential_env_configured": bool(self.api_key_env),
            "credential_present": bool(self.api_key_env and runtime_env().get(self.api_key_env)),
            "ambient_credentials": self.uses_ambient_credentials,
            "region": self.region,
            "project": self.project,
            "location": self.location,
            "use_model": self.use_model,
            "timeout_seconds": self.timeout_seconds,
        }


def provider_from_env() -> ModelProviderConfig:
    """Load optional model settings from environment."""
    provider = normalize_provider(runtime_env().get("GRC_LAKE_AGENT_PROVIDER", "rules_only"))
    default_key_env = {
        "openai": "OPENAI_API_KEY",
        "openai_compatible": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
    }.get(provider, "")
    timeout = runtime_env().get("GRC_LAKE_AGENT_TIMEOUT_SECONDS", "20")
    try:
        timeout_seconds = max(1.0, min(float(timeout), 120.0))
    except ValueError:
        timeout_seconds = 20.0
    # Vertex needs a location; default to the most common region when unset so a
    # caller only has to supply project + model.
    location = runtime_env().get("GRC_LAKE_AGENT_LOCATION", "us-central1" if provider == "vertex" else "")
    region = runtime_env().get("GRC_LAKE_AGENT_REGION") or runtime_env().get("AWS_REGION", "")
    return ModelProviderConfig(
        provider=provider,
        model=runtime_env().get("GRC_LAKE_AGENT_MODEL", ""),
        base_url=runtime_env().get(
            "GRC_LAKE_AGENT_BASE_URL",
            "http://127.0.0.1:11434" if provider == "ollama" else "",
        ),
        api_key_env=runtime_env().get("GRC_LAKE_AGENT_API_KEY_ENV", default_key_env),
        use_model=_env_bool("GRC_LAKE_AGENT_USE_MODEL"),
        timeout_seconds=timeout_seconds,
        region=region,
        project=runtime_env().get("GRC_LAKE_AGENT_PROJECT", ""),
        location=location,
    )
