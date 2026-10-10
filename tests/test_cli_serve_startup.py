"""`grc-lake serve --server` announces the URL only after startup checks pass."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("uvicorn")

from security_lakehouse import cli, server_app


def _args(tmp_path: Any, *extra: str) -> Any:
    return cli._parser().parse_args(["serve", "--server", "--lake", str(tmp_path), "--port", "8799", *extra])


def test_failed_startup_check_prints_no_serving_line(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("GRC_LAKE_COOKIE_SIGNING_KEY is required when authentication is enabled")

    ran: list[Any] = []
    monkeypatch.setattr(server_app, "create_app", refuse)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: ran.append(a))

    with pytest.raises(RuntimeError, match="GRC_LAKE_COOKIE_SIGNING_KEY"):
        cli._serve(_args(tmp_path))

    assert "serving" not in capsys.readouterr().out
    assert ran == []


@pytest.mark.parametrize(("require_auth", "label"), [(True, "server mode)"), (False, "INSECURE no-auth")])
def test_serving_line_follows_app_construction_and_reports_effective_auth(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    require_auth: bool,
    label: str,
) -> None:
    events: list[str] = []
    app = SimpleNamespace(state=SimpleNamespace(require_auth=require_auth))

    def build(lake: Any, *, require_auth: bool) -> Any:
        events.append(f"create_app(require_auth={require_auth})")
        return app

    def run(target: Any, *, host: str, port: int) -> None:
        events.append("printed" if "serving" in capsys.readouterr().out else "not-printed")
        assert target is app
        assert (host, port) == ("127.0.0.1", 8799)

    monkeypatch.setattr(server_app, "create_app", build)
    monkeypatch.setattr("uvicorn.run", run)

    assert cli._serve(_args(tmp_path)) == 0

    assert events == ["create_app(require_auth=True)", "printed"]
    capsys.readouterr()
    # The label reflects the app's effective auth (an env override can disable it).
    events.clear()
    monkeypatch.setattr("uvicorn.run", lambda *_a, **_k: None)
    cli._serve(_args(tmp_path))
    assert label in capsys.readouterr().out
