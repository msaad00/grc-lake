"""Browser session tokens and cookie helpers.

Sessions are opaque tokens (``tops_sess_<hex>``) delivered to the browser in an
httpOnly cookie. Only a keyed SHA-256 lookup digest is persisted, so a database
leak never exposes a live session; the 256-bit random token makes a slow KDF
unnecessary. Rows minted before that change hold a PBKDF2 digest and are
upgraded on first use. Cookie values are
always signed with ``TRUSTOPS_COOKIE_SIGNING_KEY`` when authentication is enabled.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets

from itsdangerous import BadData, URLSafeTimedSerializer

SESSION_COOKIE = "trustops_session"
SESSION_TOKEN_PREFIX = "tops_sess_"
DEFAULT_SESSION_TTL_HOURS = 12
_COOKIE_SIGNING_SALT = "trustops-session-cookie"


_SESSION_HASH_KEY = b"trustops-session-token-v3"
_LEGACY_SESSION_HASH_SALT = b"trustops-session-token-v2"
_LEGACY_SESSION_HASH_ITERATIONS = 210_000
_SESSION_TOKEN_PATTERN = re.compile(r"tops_sess_[0-9a-f]{64}")


def generate_session_token() -> tuple[str, str]:
    """Return ``(token, token_hash)`` for a new browser session."""
    token = f"{SESSION_TOKEN_PREFIX}{secrets.token_hex(32)}"
    return token, hash_session_token(token)


def is_well_formed_session_token(token: str) -> bool:
    return _SESSION_TOKEN_PATTERN.fullmatch(token) is not None


def hash_session_token(token: str) -> str:
    """Keyed SHA-256 lookup digest of a session token (the only form persisted)."""
    return hmac.new(_SESSION_HASH_KEY, token.encode("utf-8"), hashlib.sha256).hexdigest()


def legacy_hash_session_token(token: str) -> str:
    """PBKDF2 digest stored for sessions minted before the keyed digest."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        token.encode("utf-8"),
        _LEGACY_SESSION_HASH_SALT,
        _LEGACY_SESSION_HASH_ITERATIONS,
    ).hex()


def cookie_signing_key() -> str:
    """Return the configured cookie signing secret (empty when unset)."""
    return os.environ.get("TRUSTOPS_COOKIE_SIGNING_KEY", "").strip()


def ensure_cookie_signing_configured() -> None:
    """Fail fast when auth is enabled but the signing key is missing."""
    if not cookie_signing_key():
        raise RuntimeError(
            "TRUSTOPS_COOKIE_SIGNING_KEY is required when authentication is enabled "
            "(generate with: openssl rand -hex 32)"
        )


def _serializer() -> URLSafeTimedSerializer:
    key = cookie_signing_key()
    if not key:
        raise RuntimeError("TRUSTOPS_COOKIE_SIGNING_KEY is required for signed session cookies")
    return URLSafeTimedSerializer(key, salt=_COOKIE_SIGNING_SALT)


def encode_session_cookie(token: str) -> str:
    """Return a signed cookie value for ``token``."""
    return _serializer().dumps(token)


def decode_session_cookie(cookie_value: str) -> str | None:
    """Decode a signed session cookie value back to the raw session token."""
    raw = cookie_value.strip()
    if not raw:
        return None
    if not cookie_signing_key():
        return None
    try:
        data = _serializer().loads(raw, max_age=DEFAULT_SESSION_TTL_HOURS * 3600)
    except BadData:
        return None
    return data if isinstance(data, str) and data.startswith(SESSION_TOKEN_PREFIX) else None
