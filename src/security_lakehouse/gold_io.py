"""Stream strict gold JSON through the existing atomic file boundary."""

from __future__ import annotations

import json
from itertools import chain
from pathlib import Path
from typing import Any

from security_lakehouse import strict_json
from security_lakehouse.io import _atomic_write, resolve_path


def write_gold_json(path: str | Path, payload: Any) -> None:
    """Preserve pretty JSON bytes without allocating a serialized document copy."""
    strict_json.validate(payload)
    encoder = json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False)
    _atomic_write(resolve_path(path), chain(encoder.iterencode(payload), ("\n",)))
