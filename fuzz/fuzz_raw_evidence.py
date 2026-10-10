"""Fuzz the raw evidence path behind ``grc-lake validate --raw``.

Invariants:
* ``read_jsonl`` either returns one dict per non-blank line or raises
  ``ValueError`` (strict JSON, UTF-8, and object-per-line rejections).
* ``validate_raw_events`` never raises; it returns a list of messages.
* A batch with no messages satisfies the documented contract: every record
  carries the required non-empty string fields, an entity object, a
  timezone-qualified ``event_time``, a known severity, and a unique identity.
"""

from __future__ import annotations

import atexit
import os
import tempfile
from pathlib import Path

from _input import run

from security_lakehouse.event_identity import event_identity
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import REQUIRED_FIELDS, VALID_SEVERITIES, evidence_timestamp, validate_raw_events

_FD, _NAME = tempfile.mkstemp(prefix="grc-lake-fuzz-", suffix=".jsonl")
os.close(_FD)
_PATH = Path(_NAME)
atexit.register(_PATH.unlink, missing_ok=True)


def TestOneInput(data: bytes) -> None:
    _PATH.write_bytes(data)
    try:
        rows = read_jsonl(_PATH)
    except ValueError:
        return
    assert all(isinstance(row, dict) for row in rows)

    errors = validate_raw_events(rows)
    assert isinstance(errors, list) and all(isinstance(error, str) for error in errors)
    if errors:
        return
    identities = set()
    for row in rows:
        assert set(row) >= REQUIRED_FIELDS, "valid record is missing a required field"
        for field in REQUIRED_FIELDS - {"entity"}:
            assert isinstance(row[field], str) and row[field].strip(), f"valid record has empty {field}"
        assert isinstance(row["entity"], dict)
        evidence_timestamp(row["event_time"])
        assert row.get("severity", "info") in VALID_SEVERITIES
        identity = event_identity(row)
        assert identity not in identities, "valid batch repeats an event identity"
        identities.add(identity)


if __name__ == "__main__":
    run(TestOneInput)
