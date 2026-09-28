"""Unit tests for SSRF / URL safety guards."""

from __future__ import annotations

import socket
import ssl
import urllib.request

import pytest

from security_lakehouse import netguard
from security_lakehouse.netguard import assert_resolved_ip_is_public, assert_url_is_public


def test_assert_resolved_ip_is_public_blocks_localhost() -> None:
    with pytest.raises(ValueError, match="localhost"):
        assert_resolved_ip_is_public("localhost")


def test_assert_resolved_ip_is_public_blocks_private_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        assert host == "internal.example"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError, match="non-public"):
        assert_resolved_ip_is_public("internal.example")


def test_assert_resolved_ip_is_public_allows_public_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        assert host == "api.example.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert assert_resolved_ip_is_public("api.example.com") == ["93.184.216.34"]


def test_assert_url_is_public_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="scheme"):
        assert_url_is_public("file:///etc/passwd")


def test_assert_url_is_public_rejects_missing_host() -> None:
    with pytest.raises(ValueError, match="no host"):
        assert_url_is_public("https:///missing-host")


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",  # carrier-grade NAT (RFC 6598), not flagged by is_private
        "100.127.255.254",
        "192.0.0.8",  # IETF protocol assignments
        "198.18.0.1",  # benchmarking
        "::ffff:10.0.0.1",
        "224.0.1.1",  # globally scoped multicast is still not a unicast target
    ],
)
def test_non_global_ranges_are_blocked(monkeypatch, address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    def fake_getaddrinfo(host, port, family_=0, type=0, proto=0, flags=0):
        return [(family, socket.SOCK_STREAM, 6, "", (address, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError, match="non-public"):
        assert_resolved_ip_is_public("sneaky.example")


# --- DNS rebinding: the socket connects to the address that was validated -------

PUBLIC_IP = "93.184.216.34"
HOP_IP = "93.184.216.35"
PRIVATE_IP = "10.0.0.8"
_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
_REDIRECT = b"HTTP/1.1 302 Found\r\nLocation: http://hop.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def _sequenced_dns(monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[str]]) -> dict[str, int]:
    """Answer the n-th lookup of a host with the n-th address in its list (the last one repeats)."""
    calls: dict[str, int] = {}

    def fake_getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ARG001
        index = calls.get(host, 0)
        calls[host] = index + 1
        seq = answers[host]
        ip = seq[min(index, len(seq) - 1)]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return calls


class _UnixStream:
    """A socketpair end standing in for a TCP socket (TCP_NODELAY is a no-op here)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def setsockopt(self, *_a: object) -> None:
        return None

    def __getattr__(self, name: str) -> object:
        return getattr(self._sock, name)


def _patch_connect(monkeypatch: pytest.MonkeyPatch, responses: list[bytes]) -> list[tuple[str, int]]:
    """Replace the TCP connect: record each address and hand back a canned HTTP response."""
    addresses: list[tuple[str, int]] = []
    queue = list(responses)
    peers: list[socket.socket] = []

    def fake_create_connection(address, timeout=None, source_address=None, **kwargs):  # noqa: ANN001, ANN003, ARG001
        addresses.append((address[0], address[1]))
        ours, theirs = socket.socketpair()
        theirs.sendall(queue.pop(0))
        peers.append(theirs)
        return _UnixStream(ours)

    monkeypatch.setattr(netguard.socket, "create_connection", fake_create_connection)
    return addresses


def test_open_public_connects_to_the_validated_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _sequenced_dns(monkeypatch, {"api.example.com": [PUBLIC_IP]})
    addresses = _patch_connect(monkeypatch, [_OK])
    with netguard.open_public(urllib.request.Request("http://api.example.com/v1"), timeout=2) as resp:
        assert resp.read() == b"ok"
    # The socket is opened to the literal validated address, never by name.
    assert addresses == [(PUBLIC_IP, 80)]


def test_rebinding_between_check_and_connect_never_reaches_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    # The boundary check sees a public answer; every later lookup answers private.
    _sequenced_dns(monkeypatch, {"rebind.example": [PUBLIC_IP, PRIVATE_IP]})
    addresses = _patch_connect(monkeypatch, [_OK])
    with pytest.raises(ValueError, match="non-public"):
        netguard.open_public(urllib.request.Request("http://rebind.example/x"), timeout=2)
    assert addresses == []


def test_pinned_connection_resolves_once_and_keeps_host_header(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _sequenced_dns(monkeypatch, {"api.example.com": [PUBLIC_IP, PRIVATE_IP]})
    addresses: list[tuple[str, int]] = []
    sent: list[bytes] = []

    class _Sock:
        def setsockopt(self, *_a: object) -> None:
            return None

        def sendall(self, data: bytes) -> None:
            sent.append(bytes(data))

        def close(self) -> None:
            return None

    def fake_create_connection(address, timeout=None, source_address=None, **kwargs):  # noqa: ANN001, ANN003, ARG001
        addresses.append(address)
        return _Sock()

    monkeypatch.setattr(netguard.socket, "create_connection", fake_create_connection)
    conn = netguard.PinnedHTTPConnection("api.example.com", 8080, timeout=2)
    conn.request("GET", "/v1")
    assert calls["api.example.com"] == 1
    assert addresses == [(PUBLIC_IP, 8080)]
    assert b"Host: api.example.com:8080" in b"".join(sent)


def test_pinned_https_keeps_sni_and_cert_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    _sequenced_dns(monkeypatch, {"api.example.com": [PUBLIC_IP]})
    addresses: list[tuple[str, int]] = []
    wrapped: dict[str, object] = {}

    class _Sock:
        def setsockopt(self, *_a: object) -> None:
            return None

    class _Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, sock, server_hostname=None, **kwargs):  # noqa: ANN001, ANN003, ARG002
            wrapped["server_hostname"] = server_hostname
            return sock

    def fake_create_connection(address, timeout=None, source_address=None, **kwargs):  # noqa: ANN001, ANN003, ARG001
        addresses.append(address)
        return _Sock()

    monkeypatch.setattr(netguard.socket, "create_connection", fake_create_connection)
    conn = netguard.PinnedHTTPSConnection("api.example.com", 443, timeout=2, context=_Context())
    conn.connect()
    assert addresses == [(PUBLIC_IP, 443)]
    # SNI and certificate hostname verification stay bound to the name, not the IP.
    assert wrapped["server_hostname"] == "api.example.com"


def test_guarded_opener_https_verifies_certificates() -> None:
    opener = netguard.guarded_opener(lambda _u: None)
    handlers = [h for h in opener.handlers if isinstance(h, netguard._PinnedHTTPSHandler)]
    assert len(handlers) == 1
    context = handlers[0]._context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_redirect_hop_rebinding_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # hop.example passes the redirect validator, then rebinds for the connect.
    _sequenced_dns(monkeypatch, {"start.example": [PUBLIC_IP], "hop.example": [HOP_IP, PRIVATE_IP]})
    addresses = _patch_connect(monkeypatch, [_REDIRECT, _OK])
    with pytest.raises(ValueError, match="non-public"):
        netguard.open_public(urllib.request.Request("http://start.example/"), timeout=2)
    assert addresses == [(PUBLIC_IP, 80)]


def test_redirect_hop_connects_to_its_own_validated_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _sequenced_dns(monkeypatch, {"start.example": [PUBLIC_IP], "hop.example": [HOP_IP]})
    addresses = _patch_connect(monkeypatch, [_REDIRECT, _OK])
    with netguard.open_public(urllib.request.Request("http://start.example/"), timeout=2) as resp:
        assert resp.read() == b"ok"
    assert addresses == [(PUBLIC_IP, 80), (HOP_IP, 80)]


def test_open_guarded_pins_even_with_a_custom_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allowlist-style validators that do not resolve still cannot reach a private address."""
    _sequenced_dns(monkeypatch, {"hooks.example.com": [PRIVATE_IP]})
    addresses = _patch_connect(monkeypatch, [_OK])
    with pytest.raises(ValueError, match="non-public"):
        netguard.open_guarded(
            urllib.request.Request("http://hooks.example.com/x"),
            timeout=2,
            validate=lambda _u: None,
        )
    assert addresses == []


def test_proxied_request_connects_to_the_operator_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """With an operator egress proxy the proxy resolves the target; it is not pinned or range-checked."""
    _sequenced_dns(monkeypatch, {"api.example.com": [PUBLIC_IP]})
    addresses = _patch_connect(monkeypatch, [_OK])
    monkeypatch.setenv("http_proxy", "http://10.1.2.3:3128")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    with netguard.open_public(urllib.request.Request("http://api.example.com/v1"), timeout=2) as resp:
        assert resp.read() == b"ok"
    assert addresses == [("10.1.2.3", 3128)]


# --- IPv6 forms that embed an IPv4 address (NAT64, IPv4-compatible) -------------


def _resolve_to(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    def fake_getaddrinfo(host, port, family_=0, type=0, proto=0, flags=0):
        return [(family, socket.SOCK_STREAM, 6, "", (address, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254 (cloud metadata)
        "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
        "64:ff9b::a00:1",  # NAT64 of 10.0.0.1
        "::127.0.0.1",  # IPv4-compatible loopback
        "::a00:1",  # IPv4-compatible 10.0.0.1
        "::a9fe:a9fe",  # IPv4-compatible metadata address
        "64:ff9b:1::1",  # local-use NAT64 prefix (RFC 8215)
        "64:ff9b:1::808:808",  # local-use NAT64 even with a public-looking suffix
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
    ],
)
def test_ipv6_embedded_private_ipv4_is_blocked(monkeypatch, address: str) -> None:
    _resolve_to(monkeypatch, address)
    with pytest.raises(ValueError, match="non-public"):
        assert_resolved_ip_is_public("nat64.example")


@pytest.mark.parametrize("address", ["64:ff9b::808:808", "::808:808"])
def test_ipv6_embedded_public_ipv4_follows_ipv4_policy(monkeypatch, address: str) -> None:
    # The embedded IPv4 decides: a public v4 behind the well-known NAT64 prefix
    # or the IPv4-compatible form is as reachable as the v4 itself.
    _resolve_to(monkeypatch, address)
    assert assert_resolved_ip_is_public("nat64.example") == [address]
