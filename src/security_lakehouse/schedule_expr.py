"""Schedule expressions shared by the scheduler and its targets."""

from __future__ import annotations

import re
from datetime import timedelta

_INTERVAL_RE = re.compile(r"^every\s+(\d+)\s*(m|h)$", re.IGNORECASE)


def parse_schedule(schedule: str) -> timedelta | None:
    """Return the period for a schedule expression, or None if unrecognised."""
    if not schedule:
        return None
    text = schedule.strip().lower()
    if text == "@hourly":
        return timedelta(hours=1)
    if text == "@daily":
        return timedelta(days=1)
    match = _INTERVAL_RE.match(text)
    if not match:
        return None
    value, unit = int(match.group(1)), match.group(2)
    if value <= 0:
        return None
    if unit == "m":
        return timedelta(minutes=value)
    if unit == "h":
        return timedelta(hours=value)
    return None
