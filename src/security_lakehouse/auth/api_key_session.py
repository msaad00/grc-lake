"""Exchange a presented API key for a browser session (CodeQL auth boundary).

Raw bearer material is hashed before any database lookup or persistence. Only
the digest crosses the repository boundary — the plaintext token is never stored.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from security_lakehouse.auth.tokens import hash_token
from security_lakehouse.db import repository
from security_lakehouse.db.models import User


class ApiKeySessionError(Exception):
    """Raised when an API key cannot be turned into a browser session."""


def exchange_api_key_for_browser_session(
    session: Session,
    *,
    raw_token: str,
    now: datetime | None = None,
) -> tuple[User, str]:
    """Validate an API key and mint a browser session token."""
    moment = now or datetime.now(UTC)
    presented = raw_token.strip()
    if not presented:
        raise ApiKeySessionError("missing API key")
    key_hash = hash_token(presented)
    key = repository.resolve_api_key_by_hash(session, key_hash)
    if key is None or not key.is_active(now=moment):
        raise ApiKeySessionError("invalid or inactive API key")
    if not key.user.is_active:
        raise ApiKeySessionError("user is disabled")
    key.last_used_at = moment
    _row, sess_token = repository.create_user_session(
        session,
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        idp="api_key",
        source_api_key_id=key.id,
        now=moment,
    )
    return key.user, sess_token


__all__ = ["ApiKeySessionError", "exchange_api_key_for_browser_session"]
