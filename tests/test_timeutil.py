"""Golden equivalence tests for the shared timestamp helpers.

The ``_legacy_*`` functions are verbatim copies of the private helpers that
``security_lakehouse.timeutil`` replaced. Each replacement must reproduce its
legacy helper exactly (value, type, exception class and message) for every
input below, on every supported Python version.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import HTTPException

from security_lakehouse import models, timeutil
from security_lakehouse.server_routes.deps import parse_dt

PLUS_TWO = timezone(timedelta(hours=2))
MINUS_FIVE_THIRTY = timezone(-timedelta(hours=5, minutes=30))

DATETIMES: list[datetime] = [
    datetime(2026, 5, 20, 10, 0, 0),
    datetime(2026, 5, 20, 10, 0, 0, 123456),
    datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC),
    datetime(2026, 5, 20, 10, 0, 0, 7, tzinfo=UTC),
    datetime(2026, 5, 20, 12, 0, 0, tzinfo=PLUS_TWO),
    datetime(2026, 5, 20, 4, 30, 0, 500000, tzinfo=MINUS_FIVE_THIRTY),
    datetime(2026, 1, 1, tzinfo=timezone(timedelta(0))),
]

STRINGS: list[str] = [
    "2026-05-20T10:00:00Z",
    "2026-05-20T10:00:00z",
    "2026-05-20t10:00:00Z",
    "2026-05-20T10:00:00+00:00",
    "2026-05-20T10:00:00.123456Z",
    "2026-05-20T10:00:00.123456+00:00",
    "2026-05-20T12:00:00+02:00",
    "2026-05-20T10:00:00-05:30",
    "2026-05-20T10:00:00",
    "2026-05-20T10:00",
    "2026-05-20T10:00Z",
    "2026-05-20",
    "2026-05-20Z",
    "20260520T100000Z",
    " 2026-05-20T10:00:00Z ",
    "",
    "   ",
    "garbage",
    "2026-13-01",
    "2026-05-20T25:00:00Z",
    "2026-05-20T10:00:00ZZ",
    "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00",
]

JSON_VALUES: list[Any] = [*STRINGS, None, 0, 1, 1.5, True, False, [], {}, ["2026-05-20"], {"a": 1}]


def _outcome(fn: Any, value: Any) -> tuple[str, Any]:
    try:
        result = fn(value)
    except HTTPException as exc:
        return ("http", (exc.status_code, exc.detail))
    except Exception as exc:  # noqa: BLE001
        return ("raise", (type(exc), str(exc)))
    if isinstance(result, datetime):
        return ("ok", (result.isoformat(), result.tzinfo is not None, result.utcoffset()))
    return ("ok", result)


def _legacy_db_now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _legacy_db_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _legacy_as_aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _legacy_remediation_iso(value: datetime | None) -> str | None:
    return _legacy_as_aware(value).isoformat() if value else None


def _legacy_access_reviews_iso(value: datetime | None) -> str | None:
    return _legacy_as_aware(value).astimezone(UTC).isoformat() if value else None


def _legacy_scheduler_utc_iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _legacy_parse_event_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _legacy_crowdstrike_parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return _legacy_parse_event_time(str(value))
    except Exception:  # noqa: BLE001
        return None


def _legacy_server_app_parse_dt(value: str | None) -> datetime | None:
    if value is None or value == "":
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid datetime: {value!r}") from exc


def _legacy_assessment_parse_iso(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = value.strip()
        if not text:
            raise ValueError("timestamp must not be empty")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _legacy_framework_provenance_parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        return None


@pytest.mark.parametrize("value", [None, *DATETIMES])
def test_utc_now_matches_db_now(value: datetime | None) -> None:
    if value is None:
        before = datetime.now(UTC)
        result = timeutil.utc_now(value)
        assert result.tzinfo is UTC
        assert before <= result <= datetime.now(UTC)
        assert _legacy_db_now(None).tzinfo is UTC
    else:
        assert timeutil.utc_now(value) is _legacy_db_now(value)


def test_utc_now_without_argument_is_aware_utc() -> None:
    assert timeutil.utc_now().tzinfo is UTC


@pytest.mark.parametrize("value", [None, *DATETIMES])
def test_iso_offset_matches_db_iso(value: datetime | None) -> None:
    assert timeutil.iso_offset(value) == _legacy_db_iso(value)


@pytest.mark.parametrize("value", [None, *DATETIMES])
def test_iso_offset_assume_utc_matches_remediation_iso(value: datetime | None) -> None:
    assert timeutil.iso_offset(value, tz="assume_utc") == _legacy_remediation_iso(value)


@pytest.mark.parametrize("value", [None, *DATETIMES])
def test_iso_offset_utc_matches_access_reviews_iso(value: datetime | None) -> None:
    assert timeutil.iso_offset(value, tz="utc") == _legacy_access_reviews_iso(value)


@pytest.mark.parametrize("value", [dt for dt in DATETIMES if dt.tzinfo is not None])
def test_utc_iso_z_matches_legacy_z_helpers(value: datetime) -> None:
    expected = _legacy_scheduler_utc_iso(value)
    assert timeutil.utc_iso_z(value) == expected
    assert models.utc_iso(value) == expected


def test_utc_iso_z_golden_values() -> None:
    assert timeutil.utc_iso_z(datetime(2026, 5, 20, 12, 0, tzinfo=PLUS_TWO)) == "2026-05-20T10:00:00Z"
    assert timeutil.utc_iso_z(datetime(2026, 5, 20, 10, 0, 0, 120, tzinfo=UTC)) == "2026-05-20T10:00:00.000120Z"
    assert timeutil.iso_offset(datetime(2026, 5, 20, 10, 0, tzinfo=UTC)) == "2026-05-20T10:00:00+00:00"
    assert timeutil.iso_offset(datetime(2026, 5, 20, 10, 0)) == "2026-05-20T10:00:00"
    assert timeutil.iso_offset(datetime(2026, 5, 20, 10, 0), tz="assume_utc") == "2026-05-20T10:00:00+00:00"
    assert timeutil.iso_offset(datetime(2026, 5, 20, 12, 0, tzinfo=PLUS_TWO), tz="assume_utc") == (
        "2026-05-20T12:00:00+02:00"
    )
    assert timeutil.iso_offset(datetime(2026, 5, 20, 12, 0, tzinfo=PLUS_TWO), tz="utc") == "2026-05-20T10:00:00+00:00"


def test_utc_now_iso_z_shape() -> None:
    before = datetime.now(UTC)
    text = timeutil.utc_now_iso_z()
    assert text.endswith("Z") and "+00:00" not in text
    assert before <= datetime.fromisoformat(text.replace("Z", "+00:00")) <= datetime.now(UTC)


@pytest.mark.parametrize("value", STRINGS)
def test_parse_iso_matches_parse_event_time(value: str) -> None:
    expected = _outcome(_legacy_parse_event_time, value)
    assert _outcome(timeutil.parse_iso, value) == expected
    assert _outcome(models.parse_event_time, value) == expected


@pytest.mark.parametrize("value", JSON_VALUES)
def test_lenient_parse_iso_matches_crowdstrike_parse_time(value: Any) -> None:
    expected = _outcome(_legacy_crowdstrike_parse_time, value)
    assert _outcome(lambda item: timeutil.parse_iso(item, lenient=True), value) == expected


@pytest.mark.parametrize("value", [None, *STRINGS])
def test_server_parse_dt_matches_legacy(value: str | None) -> None:
    assert _outcome(parse_dt, value) == _outcome(_legacy_server_app_parse_dt, value)


def test_parse_iso_golden_values() -> None:
    assert timeutil.parse_iso("2026-05-20T12:00:00+02:00") == datetime(2026, 5, 20, 10, tzinfo=UTC)
    assert timeutil.parse_iso("2026-05-20") == datetime(2026, 5, 20, tzinfo=UTC)
    assert timeutil.parse_iso(" 2026-05-20T10:00:00z ") == datetime(2026, 5, 20, 10, tzinfo=UTC)
    assert timeutil.parse_iso("2026-05-20T10:00:00.5Z").microsecond == 500000
    with pytest.raises(ValueError):
        timeutil.parse_iso("garbage")
    with pytest.raises(OverflowError):
        timeutil.parse_iso("0001-01-01T00:00:00+01:00")
    assert timeutil.parse_iso("garbage", lenient=True) is None
    assert timeutil.parse_iso("0001-01-01T00:00:00+01:00", lenient=True) is None
    assert timeutil.parse_iso(None, lenient=True) is None
    assert timeutil.parse_iso("", lenient=True) is None


def test_kept_parsers_have_genuinely_different_semantics() -> None:
    """These helpers stay separate because they disagree with the canonical parser."""
    canonical = timeutil.parse_iso
    assert canonical("2026-05-20T10:00:00z") == datetime(2026, 5, 20, 10, tzinfo=UTC)
    with pytest.raises(ValueError):
        _legacy_assessment_parse_iso("2026-05-20T10:00:00z")
    assert _outcome(_legacy_assessment_parse_iso, "") != _outcome(canonical, "")
    assert _legacy_framework_provenance_parse_iso(" 2026-05-20T10:00:00Z ") is None
    with pytest.raises(OverflowError):
        _legacy_framework_provenance_parse_iso("0001-01-01T00:00:00+01:00")
    assert parse_dt("2026-05-20T12:00:00+02:00").utcoffset() == timedelta(hours=2)  # type: ignore[union-attr]


def test_kept_parsers_still_match_their_golden_behavior() -> None:
    from security_lakehouse.assessment import _parse_iso as assessment_parse_iso
    from security_lakehouse.framework_provenance import _parse_iso as provenance_parse_iso

    for value in STRINGS:
        assert _outcome(assessment_parse_iso, value) == _outcome(_legacy_assessment_parse_iso, value), value
        assert _outcome(provenance_parse_iso, value) == _outcome(_legacy_framework_provenance_parse_iso, value), value
    for moment in DATETIMES:
        assert _outcome(assessment_parse_iso, moment) == _outcome(_legacy_assessment_parse_iso, moment)


def test_date_only_inputs_are_midnight_utc() -> None:
    assert timeutil.parse_iso(date(2026, 5, 20).isoformat()) == datetime(2026, 5, 20, tzinfo=UTC)
