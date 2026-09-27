"""Shared SSRF / URL-safety guard for outbound and inbound HTTP.

Both the workflow egress path and the inbound connector clients route
credentialed requests at operator-supplied hosts. This module centralizes the
defense so the check is identical on every path: only ``http``/``https`` is
allowed, and the *resolved* address(es) must be public — a public-looking name
that resolves to a private/loopback address (DNS rebinding, split-horizon) is
still blocked.

Validating the *first* URL is not enough: ``urllib``'s default opener silently
follows 3xx redirects, and paginating clients follow server-supplied ``Link``
URLs. Either lets a validated host pivot the credentialed request at an internal
address. ``open_guarded`` closes that gap — it re-runs the caller's validator on
every redirect hop and drops credential headers on any cross-origin hop, so the
guard cannot be bypassed after the first request.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse, urlsplit

ALLOWED_SCHEMES = {"http", "https"}

# Credential-bearing headers that must not ride a cross-origin redirect.
_SENSITIVE_HEADERS = ("Authorization", "Cookie", "Proxy-Authorization")


def assert_resolved_ip_is_public(host: str, *, label: str = "target") -> list[str]:
    """Resolve ``host`` and reject any address in a non-public range.

    Returns the resolved addresses on success; raises ``ValueError`` otherwise.
    Every resolved address must be globally routable unicast; the check runs on
    the resolved address(es), not just the hostname string.

    The connection re-resolves the name, so a resolver that answers differently
    between this check and the connect (DNS rebinding) is not caught here.
    """
    if host.lower() == "localhost":
        raise ValueError(f"{label} 'localhost' is not allowed")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError(f"{label} host {host!r} did not resolve: {exc}") from exc
    addresses = [str(info[4][0]) for info in infos]
    if not addresses:
        raise ValueError(f"{label} host {host!r} did not resolve to any address")
    for raw_ip in addresses:
        # Strip any IPv6 scope id (e.g. fe80::1%eth0) before parsing.
        ip = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        # is_global also excludes shared/CGNAT space (100.64.0.0/10), which
        # is_private does not flag.
        if not ip.is_global or ip.is_multicast:
            raise ValueError(f"{label} resolves to non-public address {raw_ip} (SSRF blocked)")
    return addresses


def assert_url_is_public(url: str, *, label: str = "target") -> str:
    """Validate that ``url`` is http(s) and its host resolves to a public IP.

    Returns the host on success; raises ``ValueError`` otherwise. Use at the
    boundary where an operator-configured base URL first enters a credentialed
    request path.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"{label} URL scheme must be http or https, got {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"{label} URL has no host: {url!r}")
    assert_resolved_ip_is_public(host, label=label)
    return host


def _origin(url: str) -> tuple[str, str, int]:
    """Scheme/host/port triple used to decide whether a redirect crosses origin."""
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return (scheme, (parsed.hostname or "").lower(), port)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate each redirect hop and strip credentials across origins.

    ``urllib``'s default handler follows 3xx to any host and re-sends every
    header (including ``Authorization``) unchanged. This subclass runs the
    caller's ``validate`` on the hop target first — so the allowlist / SSRF
    guard applies to the *redirected* host, not only the first one — and drops
    credential headers when the hop changes origin, so a redirect can never leak
    a token or a session cookie to a different host.
    """

    def __init__(self, validate: Callable[[str], Any]) -> None:
        super().__init__()
        self._validate = validate

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]  # noqa: ANN001, ANN201
        self._validate(newurl)  # raises ValueError on a disallowed target
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(newurl) != _origin(req.full_url):
            for name in _SENSITIVE_HEADERS:
                new.remove_header(name)
        return new


def guarded_opener(validate: Callable[[str], Any]) -> urllib.request.OpenerDirector:
    """Build an opener whose redirects are re-validated via ``validate``."""
    return urllib.request.build_opener(_GuardedRedirectHandler(validate))


def open_guarded(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
    validate: Callable[[str], Any],
):  # type: ignore[no-untyped-def]
    """Validate ``request``'s URL, then open it with redirect revalidation.

    ``validate`` runs on the initial URL and again on every redirect target; it
    must raise on any URL that should be refused. Returns the response object
    (usable as a context manager), matching ``urllib.request.urlopen``.
    """
    validate(request.full_url)
    return guarded_opener(validate).open(request, timeout=timeout)


def open_public(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
    label: str = "target",
):  # type: ignore[no-untyped-def]
    """``open_guarded`` with the public-IP validator — the connector default.

    Every request URL and every redirect hop must be http(s) and resolve to a
    public address, so a paginating client cannot be pivoted at an internal host
    via a ``Link`` header or a 3xx redirect after the boundary check passed.
    """
    return open_guarded(
        request,
        timeout=timeout,
        validate=lambda url: assert_url_is_public(url, label=label),
    )
