"""Single resolution point for credential references that name an env var.

Connector credentials never store a secret; they store a reference such as
``client_secret_ref: "JAMF_CLIENT_SECRET"`` and the runner reads the value
from the process environment (or a ``<NAME>_FILE`` mount). Locally the process
belongs to the operator, so any name resolves.

In hosted server mode the process environment holds the server's own secrets
(cookie signing key, database URL, billing keys, cloud credentials), and a
tenant chooses both the reference and the host the resolved value is sent to.
There, a name resolves only when it is

* under the tenant's own prefix ``TRUSTOPS_TENANT_<TENANT_ID>_`` (tenant id
  upper-cased, non-alphanumerics replaced by ``_``), or
* listed by the operator in ``TRUSTOPS_CONNECTOR_SECRET_REFS`` (comma-separated
  exact names, or ``PREFIX*`` patterns),

and never when it matches the server-secret denylist below, whatever the
allowlist says. A provider-default variable (for example ``JAMF_CLIENT_SECRET``
when no ref is configured) is the operator's global credential and follows the
same rule, except that a denied default is skipped rather than raised.

Every connector reads env-named secrets through :func:`resolve_secret_ref` or
:func:`resolve_provider_default`; ``tests/test_secret_refs_enforced.py`` fails
if a connector reads a dynamically named env var any other way.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.execution_mode import in_server_mode, server_tenant_id

logger = logging.getLogger(__name__)

ALLOWLIST_ENV = "TRUSTOPS_CONNECTOR_SECRET_REFS"
TENANT_PREFIX_ROOT = "TRUSTOPS_TENANT_"
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Server-side secrets and runtime identity. Denied in server mode even when an
# operator's allowlist pattern would match. ``TRUSTOPS_`` covers every core
# setting except the calling tenant's own ``TRUSTOPS_TENANT_<id>_`` prefix.
DENIED_PREFIXES = (
    "TRUSTOPS_",
    "AWS_",
    "AMAZON_",
    "ECS_CONTAINER_",
    "GOOGLE_",
    "GCLOUD_",
    "CLOUDSDK_",
    "GCE_",
    "AZURE_",
    "ARM_",
    "MSI_",
    "IDENTITY_",
    "STRIPE_",
    "DATABASE_",
    "POSTGRES",
    "PG",
    "MYSQL_",
    "REDIS_",
    "SMTP_",
    "SENDGRID_",
    "KUBERNETES_",
    "KUBECONFIG",
    "VAULT_",
    "SENTRY_",
    "GITHUB_",
    "ACTIONS_",
    "SSH_",
    "OTEL_",
)
DENIED_NAMES = frozenset({"SECRET_KEY", "DJANGO_SECRET_KEY", "FLASK_SECRET_KEY", "HOME", "PATH"})

# Credential/option keys whose value names an environment variable.
REF_KEY_SUFFIXES = ("_ref", "_env")


class SecretRefPolicyError(ConnectorConfigError):
    """A credential reference names an env var this tenant may not read."""


def tenant_secret_prefix(tenant_id: str) -> str:
    return TENANT_PREFIX_ROOT + re.sub(r"[^A-Z0-9]", "_", tenant_id.upper()) + "_"


def _allowlist(env: dict[str, str] | os._Environ[str]) -> tuple[frozenset[str], tuple[str, ...]]:
    # Operator config lives in the process env; a caller's env snapshot (a
    # probe passes an empty one) only overrides it when it carries the key.
    raw = env.get(ALLOWLIST_ENV) if ALLOWLIST_ENV in env else os.environ.get(ALLOWLIST_ENV)
    exact: set[str] = set()
    prefixes: list[str] = []
    for item in str(raw or "").split(","):
        entry = item.strip()
        if not entry:
            continue
        if entry.endswith("*"):
            prefixes.append(entry[:-1])
        else:
            exact.add(entry)
    return frozenset(exact), tuple(prefixes)


def _denied_as_server_secret(name: str, tenant_prefix: str | None) -> bool:
    upper = name.upper()
    if tenant_prefix and upper.startswith(tenant_prefix):
        return False
    base = upper[: -len("_FILE")] if upper.endswith("_FILE") else upper
    return base in DENIED_NAMES or upper in DENIED_NAMES or upper.startswith(DENIED_PREFIXES)


def secret_ref_denial(
    name: str,
    *,
    env: dict[str, str] | None = None,
    field: str | None = None,
) -> str | None:
    """Why ``name`` may not be resolved in the current mode, or ``None``.

    The message never echoes the name, which an operator may have filled with
    the secret itself.
    """
    source: dict[str, str] | os._Environ[str] = os.environ if env is None else env
    if not in_server_mode(dict(source) if env is None else env):
        return None
    label = field or "credential reference"
    candidate = (name or "").strip()
    if not ENV_NAME_RE.fullmatch(candidate):
        return f"{label} must name an environment variable"
    tenant_id = server_tenant_id()
    tenant_prefix = tenant_secret_prefix(tenant_id) if tenant_id else None
    if _denied_as_server_secret(candidate, tenant_prefix):
        return f"{label} names a server secret; hosted connectors cannot read server credentials"
    if tenant_prefix and candidate.upper().startswith(tenant_prefix):
        return None
    exact, prefixes = _allowlist(source)
    if candidate in exact or any(prefix and candidate.startswith(prefix) for prefix in prefixes):
        return None
    hint = f"use the tenant prefix {tenant_prefix}" if tenant_prefix else "use a tenant-prefixed name"
    return f"{label} is not permitted in hosted mode; {hint} or ask the operator to add it to {ALLOWLIST_ENV}"


def _read_env_value(name: str, env: dict[str, str], *, file_first: bool) -> str | None:
    if file_first:
        file_path = env.get(f"{name}_FILE")
        if file_path:
            try:
                file_value = Path(file_path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                logger.warning("a configured *_FILE secret mount is unreadable (%s)", exc.__class__.__name__)
                return None
            return file_value or None
    inline = env.get(name)
    return inline.strip() if inline and inline.strip() else None


def resolve_secret_ref(
    name: str | None,
    env: dict[str, str],
    *,
    field: str | None = None,
    file_first: bool = True,
) -> str | None:
    """Resolve an explicit credential reference; raise if policy forbids it.

    ``file_first`` reads ``<NAME>_FILE`` (a mounted secret path) before
    ``<NAME>``; pass ``False`` when the variable itself holds a path.
    """
    candidate = (name or "").strip()
    if not candidate:
        return None
    denial = secret_ref_denial(candidate, env=env, field=field)
    if denial:
        raise SecretRefPolicyError(denial)
    return _read_env_value(candidate, env, file_first=file_first)


def resolve_provider_default(name: str, env: dict[str, str], *, file_first: bool = True) -> str | None:
    """Resolve a connector's built-in default variable; skip it if policy forbids it."""
    if secret_ref_denial(name, env=env) is not None:
        return None
    return _read_env_value(name, env, file_first=file_first)


def resolve_ref_or_default(
    ref: str | None,
    default: str,
    env: dict[str, str],
    *,
    field: str | None = None,
    file_first: bool = True,
) -> str | None:
    """An explicit ``ref`` wins (and is policed); otherwise the provider default."""
    if (ref or "").strip():
        return resolve_secret_ref(ref, env, field=field, file_first=file_first)
    return resolve_provider_default(default, env, file_first=file_first)


def ref_payload_error(credentials: dict[str, Any], options: dict[str, Any]) -> str | None:
    """Configure-time check of every ``*_ref``/``*_env`` value in a payload."""
    for payload in (credentials, options):
        for key, value in (payload or {}).items():
            if not isinstance(key, str) or not key.lower().endswith(REF_KEY_SUFFIXES):
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            denial = secret_ref_denial(value, field=key)
            if denial:
                return denial
    return None


__all__ = [
    "ALLOWLIST_ENV",
    "DENIED_NAMES",
    "DENIED_PREFIXES",
    "ENV_NAME_RE",
    "SecretRefPolicyError",
    "ref_payload_error",
    "resolve_provider_default",
    "resolve_ref_or_default",
    "resolve_secret_ref",
    "secret_ref_denial",
    "tenant_secret_prefix",
]
