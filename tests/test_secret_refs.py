"""Server-mode policy for ``*_ref`` credential fields that name an env var."""

from __future__ import annotations

import pytest

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution
from security_lakehouse.secret_refs import (
    ALLOWLIST_ENV,
    SecretRefPolicyError,
    resolve_provider_default,
    resolve_secret_ref,
    secret_ref_denial,
    tenant_secret_prefix,
)

TENANT = "3f2b8c1e-9a4d-4c2b-8f1e-2a6b7c8d9e0f"
TENANT_PREFIX = "TRUSTOPS_TENANT_3F2B8C1E_9A4D_4C2B_8F1E_2A6B7C8D9E0F_"


@pytest.fixture(autouse=True)
def _no_hosted_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)


def test_tenant_prefix_is_upper_snake_of_tenant_id() -> None:
    assert tenant_secret_prefix(TENANT) == TENANT_PREFIX


def test_local_mode_resolves_any_name_unchanged() -> None:
    env = {"TRUSTOPS_COOKIE_SIGNING_KEY": "local-ok"}
    assert secret_ref_denial("TRUSTOPS_COOKIE_SIGNING_KEY", env=env) is None
    assert resolve_secret_ref("TRUSTOPS_COOKIE_SIGNING_KEY", env) == "local-ok"


@pytest.mark.parametrize(
    "name",
    [
        "TRUSTOPS_COOKIE_SIGNING_KEY",
        "TRUSTOPS_COOKIE_SIGNING_KEY_FILE",
        "DATABASE_URL",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "STRIPE_SECRET_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "TRUSTOPS_TENANT_OTHER_TENANT_TOKEN",
    ],
)
def test_server_mode_denies_server_secrets_even_when_allowlisted(name: str) -> None:
    env = {name: "server-secret", ALLOWLIST_ENV: f"{name},*"}
    with server_execution(TENANT):
        assert secret_ref_denial(name, env=env)
        with pytest.raises(SecretRefPolicyError) as excinfo:
            resolve_secret_ref(name, env)
    assert isinstance(excinfo.value, ConnectorConfigError)
    assert "server-secret" not in str(excinfo.value)


def test_server_mode_denies_names_outside_the_allowlist() -> None:
    env = {"OKTA_API_TOKEN": "operator-global"}
    with server_execution(TENANT), pytest.raises(SecretRefPolicyError, match=ALLOWLIST_ENV):
        resolve_secret_ref("OKTA_API_TOKEN", env)


def test_server_mode_rejects_non_env_names() -> None:
    with server_execution(TENANT):
        assert secret_ref_denial("../etc/passwd", env={})
        assert secret_ref_denial("A B", env={})


def test_server_mode_resolves_explicitly_allowlisted_names_and_patterns() -> None:
    env = {ALLOWLIST_ENV: "ACME_JAMF_SECRET, ACME_SIEM_*", "ACME_JAMF_SECRET": "s1", "ACME_SIEM_TOKEN": "s2"}
    with server_execution(TENANT):
        assert resolve_secret_ref("ACME_JAMF_SECRET", env) == "s1"
        assert resolve_secret_ref("ACME_SIEM_TOKEN", env) == "s2"
        with pytest.raises(SecretRefPolicyError):
            resolve_secret_ref("ACME_OTHER", env)


def test_server_mode_resolves_own_tenant_prefix_file_first(tmp_path) -> None:
    secret_file = tmp_path / "jamf"
    secret_file.write_text("from-file\n", encoding="utf-8")
    name = f"{TENANT_PREFIX}JAMF_SECRET"
    env = {f"{name}_FILE": str(secret_file), name: "inline"}
    with server_execution(TENANT):
        assert resolve_secret_ref(name, env) == "from-file"
        assert resolve_secret_ref(name, env, file_first=False) == "inline"


def test_server_mode_without_tenant_only_honours_explicit_allowlist() -> None:
    name = f"{TENANT_PREFIX}JAMF_SECRET"
    with server_execution(None):
        assert secret_ref_denial(name, env={name: "x"})


def test_provider_default_is_skipped_not_raised_in_server_mode() -> None:
    env = {"JAMF_CLIENT_SECRET": "operator-global"}
    assert resolve_provider_default("JAMF_CLIENT_SECRET", env) == "operator-global"
    with server_execution(TENANT):
        assert resolve_provider_default("JAMF_CLIENT_SECRET", env) is None


def test_hosted_flag_applies_policy_without_request_context() -> None:
    env = {COMMERCIAL_HOSTED_ENV: "1", "DATABASE_URL": "postgres://x"}
    with pytest.raises(SecretRefPolicyError):
        resolve_secret_ref("DATABASE_URL", env)
