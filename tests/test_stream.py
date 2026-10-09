"""Continuous-eval SSE stream tests (server mode)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app, platform_event_stream, posture_event_stream
from test_api_v1 import _seed_lake


class _FakeRequest:
    """A request whose connection stays alive for ``alive_checks`` polls, then drops."""

    def __init__(self, alive_checks: int = 1) -> None:
        self._remaining = alive_checks

    async def is_disconnected(self) -> bool:
        if self._remaining <= 0:
            return True
        self._remaining -= 1
        return False


def test_posture_event_stream_emits_posture_frame(tmp_path: Path) -> None:
    _seed_lake(tmp_path)

    async def collect() -> list[str]:
        frames: list[str] = []
        async for frame in posture_event_stream(tmp_path, _FakeRequest(alive_checks=1), interval=0):
            frames.append(frame)
        return frames

    frames = asyncio.run(collect())
    assert any(frame.startswith("event: posture") for frame in frames)
    assert any('"posture"' in frame for frame in frames)


def test_platform_event_stream_emits_freshness_frame(tmp_path: Path) -> None:
    _seed_lake(tmp_path)

    async def collect() -> list[str]:
        frames: list[str] = []
        async for frame in platform_event_stream(tmp_path, _FakeRequest(alive_checks=1), interval=0):
            frames.append(frame)
        return frames

    frames = asyncio.run(collect())
    assert any(frame.startswith("event: freshness") for frame in frames)


def test_platform_event_stream_emits_ai_governance_frame(tmp_path: Path) -> None:
    _seed_lake(tmp_path)

    async def collect() -> list[str]:
        frames: list[str] = []
        async for frame in platform_event_stream(tmp_path, _FakeRequest(alive_checks=1), interval=0):
            frames.append(frame)
        return frames

    frames = asyncio.run(collect())
    assert any(frame.startswith("event: ai-governance") for frame in frames)


def test_stream_requires_auth(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))  # auth required; 401 before any streaming
    assert client.get("/api/v1/stream").status_code == 401
