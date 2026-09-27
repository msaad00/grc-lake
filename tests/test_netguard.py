"""Unit tests for SSRF / URL safety guards."""

from __future__ import annotations

import socket

import pytest

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
