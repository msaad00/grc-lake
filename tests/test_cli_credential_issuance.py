"""A first credential must be usable once without leaking through list APIs."""

import json

from security_lakehouse.cli import main
from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
from security_lakehouse.db.repository import resolve_api_key


def test_cli_bootstrap_and_issue_key_reveal_once(tmp_path, capsys):
    assert main(["platform", "seed-dev", "--lake", str(tmp_path)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first.get("token_revealed") is True
    assert isinstance(first.get("token"), str)
    assert (
        main(["auth", "issue-key", "--lake", str(tmp_path), "--tenant-slug", "dev", "--email", "admin@localhost"]) == 0
    )
    second = json.loads(capsys.readouterr().out)
    assert second.get("token_revealed") is True
    with session_scope(session_factory(create_engine_for(tmp_path))) as session:
        assert resolve_api_key(session, first["token"]) is not None
        assert resolve_api_key(session, second["token"]) is not None
    assert first["token"] != second["token"]
    assert main(["auth", "list-keys", "--lake", str(tmp_path), "--tenant-slug", "dev"]) == 0
    listing = capsys.readouterr().out
    assert first["token"] not in listing
    assert second["token"] not in listing
