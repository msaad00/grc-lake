"""UTC clock, ISO-8601 serialization, and timestamp parsing.

Two serialization forms are used on purpose: lake files carry the ``Z`` form
(:func:`utc_iso_z`) and database rows carry Python's native offset form
(:func:`iso_offset`, ``+00:00`` for UTC values).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, overload

IsoOffsetTz = Literal["keep", "assume_utc", "utc"]


def utc_now(now: datetime | None = None) -> datetime:
    """Return ``now`` when given, else the current aware UTC time."""
    return now or datetime.now(UTC)


def utc_iso_z(value: datetime) -> str:
    """Serialize as UTC with a ``Z`` suffix (lake file form)."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def utc_now_iso_z() -> str:
    return utc_iso_z(datetime.now(UTC))


def iso_offset(value: datetime | None, *, tz: IsoOffsetTz = "keep") -> str | None:
    """Serialize with ``datetime.isoformat()`` (database row form); ``None`` passes through.

    ``keep`` serializes the value as given (a naive value stays offset-less),
    ``assume_utc`` labels naive values as UTC and keeps aware offsets, and
    ``utc`` additionally converts aware values to UTC.
    """
    if value is None:
        return None
    if tz != "keep" and value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    if tz == "utc":
        value = value.astimezone(UTC)
    return value.isoformat()


@overload
def parse_iso(value: str, *, lenient: Literal[False] = False) -> datetime: ...


@overload
def parse_iso(value: Any, *, lenient: Literal[True]) -> datetime | None: ...


def parse_iso(value: Any, *, lenient: bool = False) -> datetime | None:
    """Parse ISO-8601 text into an aware UTC datetime.

    Surrounding whitespace and a trailing ``Z``/``z`` are accepted, naive
    values are UTC, and a bare date is midnight UTC. Strict mode raises
    ``ValueError``/``OverflowError``; ``lenient`` returns ``None`` for an empty
    or unparseable value and parses any other value through ``str()``.
    """
    if lenient:
        if not value:
            return None
        try:
            return parse_iso(str(value))
        except (ValueError, OverflowError):
            return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


__all__ = ["IsoOffsetTz", "iso_offset", "parse_iso", "utc_iso_z", "utc_now", "utc_now_iso_z"]
