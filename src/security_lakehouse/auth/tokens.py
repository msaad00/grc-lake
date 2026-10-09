"""API token generation and hashing.

Tokens look like ``tops_<48 hex chars>``. Only a derived lookup digest is
persisted; the plaintext is returned once at creation and never stored.

Tokens carry 192 random bits, so a keyed SHA-256 digest is as strong as a
slow KDF here and keeps every lookup cheap. Rows written before that change
hold a PBKDF2 digest (``hash_version`` 1) and are upgraded on first use.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

TOKEN_PREFIX = "tops_"
TOKEN_HASH_VERSION = 2
LEGACY_TOKEN_HASH_VERSION = 1
_TOKEN_HASH_KEY = b"trustops-api-token-v3"
_LEGACY_TOKEN_HASH_SALT = b"trustops-api-token-v2"
_LEGACY_TOKEN_HASH_ITERATIONS = 210_000
_TOKEN_PATTERN = re.compile(r"tops_[0-9a-f]{48}")


def generate_token() -> tuple[str, str, str]:
    """Return ``(token, prefix, key_hash)`` for a freshly minted credential."""
    token = f"{TOKEN_PREFIX}{secrets.token_hex(24)}"
    return token, display_prefix(token), hash_token(token)


def is_well_formed_token(token: str) -> bool:
    return _TOKEN_PATTERN.fullmatch(token) is not None


def hash_token(token: str) -> str:
    """Keyed SHA-256 lookup digest of a token (the only form persisted)."""
    return hmac.new(_TOKEN_HASH_KEY, token.encode("utf-8"), hashlib.sha256).hexdigest()


def legacy_hash_token(token: str) -> str:
    """PBKDF2 digest stored for tokens minted before ``TOKEN_HASH_VERSION`` 2."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        token.encode("utf-8"),
        _LEGACY_TOKEN_HASH_SALT,
        _LEGACY_TOKEN_HASH_ITERATIONS,
    ).hex()


def display_prefix(token: str) -> str:
    """Non-secret handle shown in listings (e.g. ``tops_ab12cd34``)."""
    return token[:12]
