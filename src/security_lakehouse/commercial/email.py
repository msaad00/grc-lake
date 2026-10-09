"""Email delivery adapters for hosted invite flows."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Protocol

from security_lakehouse.runtime_environment import runtime_env

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailMessage:
    to: str
    subject: str
    body_text: str
    body_html: str = ""


class EmailDelivery(Protocol):
    def send(self, message: EmailMessage) -> None:
        pass


class LogEmailDelivery:
    """Development / OSS default — logs invite payloads instead of sending mail."""

    def send(self, message: EmailMessage) -> None:
        logger.info(
            "trustops.email (log-only): %s",
            json.dumps({"to": message.to, "subject": message.subject}, sort_keys=True),
        )


def email_delivery_from_env() -> EmailDelivery:
    provider = runtime_env().get("GRC_LAKE_EMAIL_PROVIDER", "log").strip().lower()
    if provider in {"log", "none", ""}:
        return LogEmailDelivery()
    raise ValueError(
        f"unsupported GRC_LAKE_EMAIL_PROVIDER {provider!r}; configure log (default) or extend commercial.email"
    )


def commercial_hosted_enabled() -> bool:
    return runtime_env().get("GRC_LAKE_COMMERCIAL_HOSTED", "").lower() in {"1", "true", "yes"}


__all__ = ["EmailDelivery", "EmailMessage", "LogEmailDelivery", "commercial_hosted_enabled", "email_delivery_from_env"]
