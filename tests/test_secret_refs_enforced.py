"""Every env var whose *name* comes from data must go through secret_refs.

A connector credential such as ``client_secret_ref`` names an env var. If any
code path reads ``env.get(<that name>)`` directly, a hosted tenant can point it
at a server secret and send the value to a host they control. This test walks
the package AST and fails on any env lookup keyed by a non-constant name
outside the resolver and the operator-only modules listed below.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from security_lakehouse.connector_state import configure_payload_error
from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "security_lakehouse"

# Modules allowed to read env vars by computed name, with the reason. None of
# these names are tenant-controlled.
EXEMPT = {
    "secret_refs.py": "the policed resolver itself",
    "agents/budgets.py": "operator-set agent budget knobs",
    "agents/model_client.py": "operator-set model provider key env",
    "agents/providers.py": "operator-set model provider key env",
    "auth/idp_roles.py": "operator-set IdP role map env",
    "auth/saml.py": "operator-set SAML config env",
    "commercial/billing.py": "operator-set Stripe config",
    "workflows.py": "workflow secrets: TRUSTOPS_SECRET_ locally, the tenant's own prefix in server mode",
}

_ENV_RECEIVERS = {"env", "environment", "environ", "source_env", "process_env"}


def _is_env(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _ENV_RECEIVERS
    if isinstance(node, ast.Attribute):
        return node.attr in _ENV_RECEIVERS
    return False


def _is_static_name(arg: ast.AST) -> bool:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return True
    if isinstance(arg, ast.Name | ast.Attribute):
        name = arg.id if isinstance(arg, ast.Name) else arg.attr
        return name.isupper()
    if isinstance(arg, ast.JoinedStr) and arg.values:
        # A code-chosen literal namespace (``f"SNOWFLAKE_VIEW_{key}"``).
        first = arg.values[0]
        return isinstance(first, ast.Constant) and isinstance(first.value, str) and len(first.value) >= 4
    return False


def dynamic_env_lookups(source: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        arg: ast.AST | None = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
            if node.func.attr == "get" and _is_env(node.func.value) or node.func.attr == "getenv":
                arg = node.args[0]
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) and _is_env(node.value):
            arg = node.slice
        if arg is not None and not _is_static_name(arg):
            hits.append((node.lineno, ast.unparse(arg)))
    return hits


def test_scanner_flags_a_dynamic_lookup() -> None:
    assert dynamic_env_lookups("def f(env, creds):\n    return env.get(creds['credential_ref'])\n")
    assert dynamic_env_lookups("import os\ndef f(n):\n    return os.environ[n]\n")
    assert not dynamic_env_lookups("import os\ndef f():\n    return os.environ.get('X') or os.getenv(X_ENV)\n")


def test_no_module_resolves_an_env_name_outside_secret_refs() -> None:
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(PACKAGE).as_posix()
        if rel in EXEMPT:
            continue
        for line, expr in dynamic_env_lookups(path.read_text(encoding="utf-8")):
            offenders.append(f"{rel}:{line} env lookup by {expr}")
    assert offenders == [], "route these through security_lakehouse.secret_refs:\n" + "\n".join(offenders)


# Every credential field that names an env var across the implemented connectors.
REF_FIELDS = (
    "credential_ref",
    "client_secret_ref",
    "refresh_token_ref",
    "oauth_token_ref",
    "private_key_ref",
    "private_key_file_ref",
    "private_key_file_pwd_ref",
    "kubeconfig_ref",
)


@pytest.mark.parametrize("connector_id", sorted(load_connector_catalog()))
@pytest.mark.parametrize("field", REF_FIELDS)
def test_every_connector_rejects_a_server_secret_ref_at_configure_time(
    connector_id: str, field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)
    credentials = {field: "TRUSTOPS_COOKIE_SIGNING_KEY"}
    with server_execution("tenant-a"):
        error = configure_payload_error(connector_id=connector_id, state="enabled", credentials=credentials, options={})
    assert error is not None and "server secret" in error
    # Local mode keeps accepting the same reference (other fields may still be missing).
    local_error = configure_payload_error(
        connector_id=connector_id, state="enabled", credentials=credentials, options={}
    )
    assert local_error is None or "server secret" not in local_error


def test_configure_rejects_token_env_option_in_server_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)
    with server_execution("tenant-a"):
        error = configure_payload_error(
            connector_id="github-security",
            state="enabled",
            credentials={},
            options={"repo": "o/r", "token_env": "DATABASE_URL"},
        )
    assert error is not None and "server secret" in error
