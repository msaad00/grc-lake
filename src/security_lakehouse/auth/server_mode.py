"""Shared deployment guard for HTTP and isolated operation execution."""

import logging
import os


def insecure_requested() -> bool:
    return os.environ.get("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", "").lower() in {"1", "true", "yes"}


def production_env_blocked() -> bool:
    env = os.environ.get("TRUSTOPS_ENV", "").strip().lower()
    return env in {"production", "prod", "staging"}


def assert_insecure_allowed(*, require_auth: bool) -> None:
    insecure = not require_auth or insecure_requested()
    if insecure and production_env_blocked():
        raise RuntimeError("Unauthenticated server mode is forbidden when TRUSTOPS_ENV is production or staging")
    if insecure:
        logging.getLogger(__name__).warning(
            "Unauthenticated server mode is enabled: every request runs as synthetic admin"
        )
