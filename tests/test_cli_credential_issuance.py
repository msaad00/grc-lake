"""A first credential must be usable once without leaking through list APIs."""

import json
from pathlib import Path

from security_lakehouse.cli import main
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import resolve_api_key


def test_cli_bootstrap_and_issue_key_reveal_once(tmp_path, capsys):
    assert main(["platform", "seed-dev", "--lake", str(tmp_path)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert "token" not in first
    first_token = Path(first["token_file"]).read_text().strip()
    assert (
        main(["auth", "issue-key", "--lake", str(tmp_path), "--tenant-slug", "dev", "--email", "admin@localhost"]) == 0
    )
    second = json.loads(capsys.readouterr().out)
    assert "token" not in second
    second_token = Path(second["token_file"]).read_text().strip()
    with session_scope(session_factory(create_engine_for(tmp_path))) as session:
        assert resolve_api_key(session, first_token) is not None
        assert resolve_api_key(session, second_token) is not None
    assert first_token != second_token
    assert main(["auth", "list-keys", "--lake", str(tmp_path), "--tenant-slug", "dev"]) == 0
    listing = capsys.readouterr().out
    assert first_token not in listing
    assert second_token not in listing


def test_cli_delivers_secret_to_new_owner_only_file_not_stdout(tmp_path, capsys):
    import stat
    from pathlib import Path

    assert main(["platform", "seed-dev", "--lake", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    metadata = json.loads(output)
    assert "token" not in metadata
    path = Path(metadata["token_file"])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    token = path.read_text().strip()
    assert token not in output
    with session_scope(session_factory(create_engine_for(tmp_path))) as session:
        assert resolve_api_key(session, token) is not None


def test_delivery_never_overwrites_existing_secret_and_cleans_failed_commit(tmp_path):
    import pytest

    from security_lakehouse.cli import _store_new_api_key

    class Session:
        def commit(self):
            raise RuntimeError("database unavailable")

    path = tmp_path / "server/credentials/key.token"
    path.parent.mkdir(parents=True)
    path.write_text("existing")
    with pytest.raises(FileExistsError):
        _store_new_api_key(Session(), str(tmp_path), "key", "new-secret")
    assert path.read_text() == "existing"
    with pytest.raises(RuntimeError, match="database unavailable"):
        _store_new_api_key(Session(), str(tmp_path), "new-key", "new-secret")
    assert not (path.parent / "new-key.token").exists()
