"""Which trust boundary the current call runs under: local/CLI or hosted server.

Local and CLI runs act for the operator who owns the process, so they may use
the process environment and ambient cloud identity. Server mode acts for an
authenticated tenant, who must never reach the server's own secrets, runtime
identity, or filesystem. ``server_app`` enters :func:`server_execution` around
every tenant request it dispatches into the shared handlers; the connector,
lake, and review code consult :func:`in_server_mode` to pick the stricter path.

The flag is a :class:`contextvars.ContextVar`, so it is scoped to one request
(or one worker-thread call made through :func:`run_in_server_mode`) and never
leaks into another tenant's or the CLI's calls in the same process.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import ParamSpec, TypeVar

from security_lakehouse.runtime_environment import runtime_env

P = ParamSpec("P")
R = TypeVar("R")

# Set by hosted deployments (see commercial/signup.py). When it is on, a call
# that arrives without request context (a CLI command or daemon run against
# the server's lake root) is still treated as tenant-controlled configuration.
COMMERCIAL_HOSTED_ENV = "GRC_LAKE_COMMERCIAL_HOSTED"


@dataclass(frozen=True)
class ServerContext:
    tenant_id: str | None


_SERVER_CONTEXT: ContextVar[ServerContext | None] = ContextVar("trustops_server_context", default=None)


@contextmanager
def server_execution(tenant_id: str | None) -> Iterator[ServerContext]:
    """Run the enclosed block as a hosted-server call on behalf of ``tenant_id``."""
    context = ServerContext(tenant_id=(tenant_id or None))
    token = _SERVER_CONTEXT.set(context)
    try:
        yield context
    finally:
        _SERVER_CONTEXT.reset(token)


def run_in_server_mode(tenant_id: str | None, func: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
    """Call ``func`` inside :func:`server_execution`.

    Use this as the target of ``run_in_threadpool`` so the flag is set inside
    the worker thread itself rather than relying on context propagation.
    """
    with server_execution(tenant_id):
        return func(*args, **kwargs)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def in_server_mode(env: dict[str, str] | None = None) -> bool:
    """True when the current call acts for a tenant rather than the operator."""
    env = runtime_env(env)
    if _SERVER_CONTEXT.get() is not None:
        return True
    source = runtime_env() if env is None else env
    return _truthy(source.get(COMMERCIAL_HOSTED_ENV))


def server_tenant_id(lake_dir: str | Path | None = None) -> str | None:
    """The tenant the current server call acts for, if known.

    Request context wins. Without it (a hosted daemon run), the tenant is read
    from a ``<root>/tenants/<tenant_id>`` lake path; anything else is unknown.
    """
    context = _SERVER_CONTEXT.get()
    if context is not None and context.tenant_id:
        return context.tenant_id
    if lake_dir is not None:
        parts = Path(lake_dir).parts
        for index in range(len(parts) - 2, -1, -1):
            if parts[index] == "tenants" and parts[index + 1]:
                return parts[index + 1]
    return None


__all__ = [
    "COMMERCIAL_HOSTED_ENV",
    "ServerContext",
    "in_server_mode",
    "run_in_server_mode",
    "server_execution",
    "server_tenant_id",
]


def evaluation_tenant_id(lake_dir: str | Path, requested: str | None = None) -> str:
    """Bind assessment ownership to the platform principal, not source accounts."""
    if not in_server_mode():
        return requested or "default"
    bound = server_tenant_id(lake_dir)
    if not bound:
        raise ValueError("evaluation requires a bound platform tenant")
    if requested is not None and requested != bound:
        raise ValueError("evaluation tenant conflicts with authenticated tenant")
    return bound
