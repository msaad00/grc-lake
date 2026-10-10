"""Starlette session handling with an explicit SHA-256 cookie signer."""

from __future__ import annotations

import hashlib
from typing import Literal

from itsdangerous import TimestampSigner
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp

from security_lakehouse.auth.signing import validate_signing_secret


class SHA256SessionMiddleware(SessionMiddleware):
    """Preserve Starlette cookie behavior while pinning the signing digest."""

    def __init__(
        self,
        app: ASGIApp,
        secret_key: str,
        *,
        same_site: Literal["lax", "strict", "none"] = "lax",
        https_only: bool = True,
    ) -> None:
        secret = validate_signing_secret(secret_key, name="GRC_LAKE_SESSION_SECRET")
        super().__init__(app, secret_key=secret, same_site=same_site, https_only=https_only)
        self.signer = TimestampSigner(secret, digest_method=hashlib.sha256)
