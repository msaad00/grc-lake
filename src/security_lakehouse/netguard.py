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

Checking a name and then connecting by that name resolves it twice, and a
resolver that answers public for the check and private for the connect (DNS
rebinding with a zero TTL) slips through. The guarded opener therefore connects
through ``PinnedHTTPConnection`` / ``PinnedHTTPSConnection``: each connection
resolves the host once, requires every answer to be public, and opens the socket
to that validated address. The Host header, TLS SNI, and certificate hostname
verification still use the original name. Each redirect hop gets its own pinned
connection.
"""

from __future__ import annotations

import functools
import http.client
import ipaddress
import socket
import ssl
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse, urlsplit

ALLOWED_SCHEMES = {"http", "https"}

# IPv6 prefixes that carry an IPv4 address in their low 32 bits. A resolver
# (or a literal) can hand back one of these to reach an internal IPv4 target
# through a NAT64 gateway or a dual-stack host, and ``ipaddress`` reports most of
# them as global, so the embedded IPv4 is checked instead.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.IPv6Network("64:ff9b:1::/48")
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")
_IPV4_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")
# 6to4 (RFC 3056) and Teredo (RFC 4380) tunnel to IPv4 hosts named inside the
# address. Some Python releases report these prefixes as global, so every
# embedded IPv4 must itself be public.
_SIXTOFOUR = ipaddress.IPv6Network("2002::/16")
_TEREDO = ipaddress.IPv6Network("2001::/32")

# Credential-bearing headers that must not ride a cross-origin redirect.
_SENSITIVE_HEADERS = ("Authorization", "Cookie", "Proxy-Authorization")


def _embedded_ipv4s(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses a 6to4 or Teredo address tunnels to (server first for Teredo)."""
    if ip in _SIXTOFOUR:
        # Bits 16-47 (RFC 3056 section 2).
        return [ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)]
    if ip in _TEREDO:
        # Server IPv4 in bits 32-63; client IPv4 bit-inverted in the last 32 (RFC 4380 section 4).
        server = ipaddress.IPv4Address((int(ip) >> 64) & 0xFFFFFFFF)
        client = ipaddress.IPv4Address(~int(ip) & 0xFFFFFFFF)
        return [server, client]
    return []


def _is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for a globally routable unicast address, judging embedded IPv4 by the IPv4 rules."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _NAT64_LOCAL_USE:
            # RFC 8215 local-use translation prefix: always an operator-internal path.
            return False
        if ip in _NAT64_WELL_KNOWN or ip in _IPV4_COMPATIBLE or ip in _IPV4_MAPPED:
            return _is_public_address(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if not all(_is_public_address(embedded) for embedded in _embedded_ipv4s(ip)):
            return False
    # is_global also excludes shared/CGNAT space (100.64.0.0/10), which
    # is_private does not flag.
    return ip.is_global and not ip.is_multicast


def assert_resolved_ip_is_public(host: str, *, label: str = "target") -> list[str]:
    """Resolve ``host`` and reject any address in a non-public range.

    Returns the resolved addresses on success; raises ``ValueError`` otherwise.
    Every resolved address must be globally routable unicast; the check runs on
    the resolved address(es), not just the hostname string.

    Checking alone does not pin the connection: connect through
    ``open_guarded`` / ``open_public`` (which connect to the validated address)
    so a resolver that answers differently on the next lookup cannot redirect it.
    """
    if host.lower() == "localhost":
        raise ValueError(f"{label} 'localhost' is not allowed")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError(f"{label} host {host!r} did not resolve: {exc}") from exc
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise ValueError(f"{label} host {host!r} did not resolve to any address")
    for raw_ip in addresses:
        # Strip any IPv6 scope id (e.g. fe80::1%eth0) before parsing.
        ip = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        if not _is_public_address(ip):
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

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        self._validate(newurl)  # raises ValueError on a disallowed target
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(newurl) != _origin(req.full_url):
            for name in _SENSITIVE_HEADERS:
                new.remove_header(name)
        return new


def _connect_pinned(host: str, port: int, timeout: Any, source_address: Any, label: str) -> socket.socket:
    """Resolve ``host`` once, require every answer to be public, and connect to one of them."""
    addresses = assert_resolved_ip_is_public(host, label=label)
    last_error: OSError | None = None
    for raw_ip in addresses:
        try:
            return socket.create_connection((raw_ip.split("%", 1)[0], port), timeout, source_address)
        except OSError as exc:
            last_error = exc
    raise last_error or OSError(f"{label} host {host!r} could not be reached")


class _PinnedConnectMixin:
    """Swap ``http.client``'s TCP connect for ``_connect_pinned``.

    When the request goes through an operator-configured proxy (plain-HTTP
    forwarding or a CONNECT tunnel), the socket goes to the proxy as configured
    and the proxy resolves the target; the target URL is still checked by the
    caller's validator.
    """

    def __init__(self, *args: Any, label: str = "target", proxied: bool = False, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._label = label
        self._proxied = proxied
        self._create_connection = self._pinned_create_connection

    def _pinned_create_connection(
        self, address: tuple[str, int], timeout: Any = None, source_address: Any = None
    ) -> socket.socket:
        if self._proxied or getattr(self, "_tunnel_host", None):
            return socket.create_connection(address, timeout, source_address)
        return _connect_pinned(address[0], address[1], timeout, source_address, self._label)


class PinnedHTTPConnection(_PinnedConnectMixin, http.client.HTTPConnection):
    """``HTTPConnection`` that connects to the address it validated, not a second lookup."""


class PinnedHTTPSConnection(_PinnedConnectMixin, http.client.HTTPSConnection):
    """``HTTPSConnection`` pinned like ``PinnedHTTPConnection``.

    ``HTTPSConnection.connect`` wraps the socket with ``server_hostname=self.host``,
    so SNI and certificate hostname checks stay on the original name.
    """


def _is_proxied(req: urllib.request.Request) -> bool:
    """True when ``ProxyHandler`` rerouted a plain-HTTP request to a proxy host."""
    return (req.host or "").lower() != (urlsplit(req.full_url).netloc or "").lower()


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, label: str) -> None:
        super().__init__()
        self._label = label

    def http_open(self, req):  # noqa: ANN001, ANN201
        return self.do_open(
            functools.partial(PinnedHTTPConnection, label=self._label, proxied=_is_proxied(req)),
            req,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, label: str) -> None:
        super().__init__(context=ssl.create_default_context())
        self._label = label

    def https_open(self, req):  # noqa: ANN001, ANN201
        return self.do_open(
            functools.partial(PinnedHTTPSConnection, label=self._label, proxied=_is_proxied(req)),
            req,
            context=self._context,
        )


def guarded_opener(validate: Callable[[str], Any], *, label: str = "target") -> urllib.request.OpenerDirector:
    """Build an opener whose redirects are re-validated and whose sockets are pinned.

    Every connection (the first request and each redirect hop) resolves its host
    once, requires every answer to be public, and connects to that address.
    """
    return urllib.request.build_opener(
        _GuardedRedirectHandler(validate),
        _PinnedHTTPHandler(label),
        _PinnedHTTPSHandler(label),
    )


def open_guarded(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
    validate: Callable[[str], Any],
    label: str = "target",
):
    """Validate ``request``'s URL, then open it with redirect revalidation.

    ``validate`` runs on the initial URL and again on every redirect target; it
    must raise on any URL that should be refused. Independently of
    ``validate``, every socket connects only to a public address resolved and
    checked for that connection. Returns the response object (usable as a
    context manager), matching ``urllib.request.urlopen``.
    """
    validate(request.full_url)
    return guarded_opener(validate, label=label).open(request, timeout=timeout)


def open_public(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
    label: str = "target",
):
    """``open_guarded`` with the public-IP validator — the connector default.

    Every request URL and every redirect hop must be http(s) and resolve to a
    public address, so a paginating client cannot be pivoted at an internal host
    via a ``Link`` header or a 3xx redirect after the boundary check passed.
    """
    return open_guarded(
        request,
        timeout=timeout,
        validate=lambda url: assert_url_is_public(url, label=label),
        label=label,
    )
