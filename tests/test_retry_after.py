"""Retry-After parsing: delta-seconds (integer or decimal) and HTTP-date forms."""

from __future__ import annotations

import urllib.error
from datetime import UTC, datetime, timedelta
from email.message import Message
from email.utils import format_datetime

import pytest

from security_lakehouse.ingestion import backoff


def _http_error(retry_after: str | None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://api.example", 429, "slow down", headers, None)


@pytest.mark.parametrize(("raw", "expected"), [("5", 5.0), ("1.5", 1.5), (" 0.25 ", 0.25), ("0", 0.0)])
def test_retry_after_accepts_integer_and_decimal_seconds(raw: str, expected: float) -> None:
    assert backoff.http_retry_after(_http_error(raw)) == pytest.approx(expected)


@pytest.mark.parametrize("raw", ["-3", "nan", "inf", "soon", ""])
def test_retry_after_rejects_unusable_values(raw: str) -> None:
    assert backoff.http_retry_after(_http_error(raw)) is None


def test_retry_after_http_date_with_gmt() -> None:
    when = datetime.now(UTC) + timedelta(seconds=120)
    value = backoff.http_retry_after(_http_error(format_datetime(when, usegmt=True)))
    assert value is not None and 100 <= value <= 121


def test_retry_after_http_date_without_zone_is_treated_as_utc() -> None:
    """RFC 5322 '-0000' parses to a naive datetime; it must be read as UTC, not dropped."""
    when = datetime.now(UTC) + timedelta(seconds=120)
    raw = when.strftime("%a, %d %b %Y %H:%M:%S -0000")
    value = backoff.http_retry_after(_http_error(raw))
    assert value is not None and 100 <= value <= 121


def test_retry_after_past_date_is_zero() -> None:
    when = datetime.now(UTC) - timedelta(hours=1)
    assert backoff.http_retry_after(_http_error(format_datetime(when, usegmt=True))) == 0.0


def test_retry_after_ignores_non_http_errors() -> None:
    assert backoff.http_retry_after(ValueError("x")) is None
    assert backoff.http_retry_after(_http_error(None)) is None
