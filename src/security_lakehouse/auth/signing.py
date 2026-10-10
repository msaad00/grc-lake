"""Shared minimum strength for operator-configured cookie signing secrets."""

from __future__ import annotations


def validate_signing_secret(secret: str, *, name: str) -> str:
    """Reject short secrets; operators must still generate them randomly."""
    secret = secret.strip()
    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(f"{name} must contain at least 32 bytes (generate with: openssl rand -hex 32)")
    return secret
