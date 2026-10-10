"""Shared deployment guard for HTTP and isolated operation execution."""

import logging

from security_lakehouse.runtime_environment import runtime_env

PRODUCTION_ENVS = frozenset({"production", "prod", "staging"})
NO_AUTH_ENVS = frozenset({"dev", "development", "local", "demo", "test"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def insecure_requested() -> bool:
    return runtime_env().get("GRC_LAKE_ALLOW_INSECURE_NO_AUTH", "").lower() in {"1", "true", "yes"}


def _deployment_env() -> str:
    return runtime_env().get("GRC_LAKE_ENV", "").strip().lower()


def production_env_blocked() -> bool:
    return _deployment_env() in PRODUCTION_ENVS


def is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS or host.startswith("127.")


def assert_insecure_allowed(*, require_auth: bool, host: str | None = None) -> None:
    """Fail closed unless unauthenticated mode is plainly a local or named non-production run.

    Allowed only when ``GRC_LAKE_ENV`` is one of :data:`NO_AUTH_ENVS`, or when it
    is unset and the server binds loopback. ``host`` is ``None`` when the caller
    does not bind a socket (an app factory or an isolated operation child); the
    bind itself is checked by the code that opens it.
    """
    if require_auth and not insecure_requested():
        return
    env = _deployment_env()
    if env in PRODUCTION_ENVS:
        raise RuntimeError("Unauthenticated server mode is forbidden when GRC_LAKE_ENV is production or staging")
    if env and env not in NO_AUTH_ENVS:
        raise RuntimeError(
            f"Unauthenticated server mode is forbidden when GRC_LAKE_ENV={env!r}; it is allowed only for "
            f"GRC_LAKE_ENV in {sorted(NO_AUTH_ENVS)}. Configure authentication, or set GRC_LAKE_ENV=dev "
            "for a development server."
        )
    if not env and host is not None and not is_loopback(host):
        raise RuntimeError(
            f"Refusing unauthenticated server mode on {host}: without GRC_LAKE_ENV it binds loopback only "
            "(127.0.0.1, ::1, localhost). Bind --host 127.0.0.1, configure authentication, or for a local "
            "demo container set GRC_LAKE_ENV=demo."
        )
    logging.getLogger(__name__).warning("Unauthenticated server mode is enabled: every request runs as synthetic admin")
