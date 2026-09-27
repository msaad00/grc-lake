"""OAuth 2.0 client-credentials token source (RFC 6749 section 4.4).

Connectors that authenticate with an API client id + secret (Jamf Pro API
clients, CrowdStrike Falcon API clients) exchange them for a short-lived bearer
token. The token lives in memory only, is reused until shortly before it
expires, and is re-minted once when an API call answers 401. The exchange goes
through the same egress layers as every other connector request:
``netguard.open_public`` (public-address + redirect revalidation) and
``backoff.http_retry`` (429/5xx with ``Retry-After``).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from security_lakehouse import netguard
from security_lakehouse.ingestion import backoff

T = TypeVar("T")

DEFAULT_TIMEOUT = 20
# Re-mint this many seconds before the advertised expiry so a token never
# expires between the check and the request that uses it.
DEFAULT_SKEW_SECONDS = 60
# Used when the token response omits ``expires_in`` (it is RECOMMENDED, not
# required, by RFC 6749 section 5.1).
DEFAULT_LIFETIME_SECONDS = 300


class CredentialRejectedError(RuntimeError):
    """The token endpoint refused the configured client credentials."""


class ClientCredentialsToken:
    """Mint and cache a bearer token from client credentials."""

    def __init__(
        self,
        token_url: str,
        *,
        form: Mapping[str, str],
        label: str,
        timeout: int = DEFAULT_TIMEOUT,
        skew_seconds: int = DEFAULT_SKEW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if urllib.parse.urlparse(token_url).scheme != "https":
            raise ValueError(f"{label} token URL must use https")
        self.token_url = token_url
        self.label = label
        self.timeout = timeout
        self._form = urllib.parse.urlencode(dict(form)).encode("ascii")
        self._skew = skew_seconds
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0

    def bearer(self) -> str:
        if self._token is None or self._clock() >= self._expires_at - self._skew:
            return self._mint()
        return self._token

    def invalidate(self) -> None:
        self._token = None

    def call_with_bearer(self, call: Callable[[str], T]) -> T:
        """Run ``call(token)``; on HTTP 401 re-mint once and retry, then fail closed."""
        try:
            return call(self.bearer())
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
        self.invalidate()
        return call(self.bearer())

    def _mint(self) -> str:
        request = urllib.request.Request(
            self.token_url,
            data=self._form,
            method="POST",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "accept": "application/json",
                "user-agent": "trustops-security-data-lake",
            },
        )
        try:
            payload = backoff.http_retry(lambda: self._open(request))
        except urllib.error.HTTPError as exc:
            if exc.code in {400, 401, 403}:
                raise CredentialRejectedError(
                    f"{self.label} rejected the client credentials (HTTP {exc.code}); "
                    "check the client id, secret reference, and the client's role"
                ) from None
            raise
        token = str((payload or {}).get("access_token") or "") if isinstance(payload, dict) else ""
        if not token:
            raise CredentialRejectedError(f"{self.label} token response did not include an access_token")
        try:
            lifetime = float(payload.get("expires_in") or DEFAULT_LIFETIME_SECONDS)
        except (TypeError, ValueError):
            lifetime = DEFAULT_LIFETIME_SECONDS
        self._token = token
        self._expires_at = self._clock() + lifetime
        return token

    def _open(self, request: urllib.request.Request) -> Any:
        with netguard.open_public(request, timeout=self.timeout, label=self.label) as resp:
            return json.loads(resp.read().decode("utf-8"))
