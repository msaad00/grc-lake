"""Shared helpers for the fuzz targets.

Targets keep their invariants in a plain ``TestOneInput(data: bytes)`` so the
unit suite can replay seeds without atheris; only ``run`` needs it.
"""

from __future__ import annotations

import sys
from collections.abc import Callable


class Input:
    """Deterministically split one fuzz input into typed fields."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take_int(self, limit: int) -> int:
        """Return an int in ``[0, limit)``; 0 once the input is exhausted."""
        if self._pos >= len(self._data) or limit <= 1:
            return 0
        width = ((limit - 1).bit_length() + 7) // 8
        chunk = self._data[self._pos : self._pos + width]
        self._pos += len(chunk)
        return int.from_bytes(chunk, "little") % limit

    def take_bytes(self, limit: int) -> bytes:
        size = self.take_int(limit + 1)
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def take_text(self, limit: int) -> str:
        """Any code points, lone surrogates included, as an HTTP header or JSON string may carry."""
        raw = self.take_bytes(limit * 2)
        return raw[: len(raw) // 2 * 2].decode("utf-16-le", errors="surrogatepass")

    def take_rest(self) -> bytes:
        chunk = self._data[self._pos :]
        self._pos = len(self._data)
        return chunk


def run(test_one_input: Callable[[bytes], None]) -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
