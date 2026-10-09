"""Connector state files must not be world-readable.

`gold/connector_config.jsonl` holds the access path for every configured
connector. Secret-shaped values are redacted before the write, but what remains
still identifies how GRC Lake reaches a customer account -- role ARNs, account
ids, hosts, usernames, and the AWS External ID, which `connector_runner` reads
back from this file at sync time. At the default 0644 any local account on the
host can read all of it.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from security_lakehouse.connector_state import CONFIG_FILE, RUNS_FILE, append_config_event, append_run_event


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_config_events_are_written_owner_only(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="github-security",
        state="disabled",
        actor="tester",
        credentials={"token": "ghp_secret", "external_id": "ext-123"},
        options={"repo": "acme/widgets"},
    )
    path = tmp_path / "gold" / CONFIG_FILE
    assert _mode(path) == 0o600, f"connector config is {oct(_mode(path))}, expected 0600"


def test_run_events_are_written_owner_only(tmp_path: Path) -> None:
    append_run_event(tmp_path, connector_id="github-security", kind="probe", result="ok", actor="tester")
    path = tmp_path / "gold" / RUNS_FILE
    assert _mode(path) == 0o600


def test_a_file_left_world_readable_is_tightened_on_next_write(tmp_path: Path) -> None:
    """Existing installs already have 0644 files; the next write must fix them."""
    gold = tmp_path / "gold"
    gold.mkdir(parents=True)
    path = gold / CONFIG_FILE
    path.write_text("", encoding="utf-8")
    path.chmod(0o644)
    assert _mode(path) == 0o644

    append_config_event(tmp_path, connector_id="github-security", state="disabled", actor="tester")
    assert _mode(path) == 0o600


def test_append_refuses_to_follow_a_symlink(tmp_path: Path) -> None:
    """A symlink where the state file belongs must not redirect the write."""
    gold = tmp_path / "gold"
    gold.mkdir(parents=True)
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("", encoding="utf-8")
    (gold / CONFIG_FILE).symlink_to(target)

    with pytest.raises(OSError):
        append_config_event(tmp_path, connector_id="github-security", state="disabled", actor="tester")
    assert target.read_text(encoding="utf-8") == ""


def test_the_fingerprint_salt_is_per_install_and_owner_only(tmp_path: Path) -> None:
    """The salt used to be a compile-time constant, identical on every install.

    `credential_fingerprint` is readable at `read` scope, so one rainbow table
    over likely credential values worked against every GRC Lake deployment at
    once. A per-install salt makes that table worth nothing anywhere else.
    """
    from security_lakehouse.connector_state import _access_fingerprint, _fingerprint_salt

    one, two = tmp_path / "lake-a", tmp_path / "lake-b"

    salt_a = _fingerprint_salt(one)
    assert len(salt_a) >= 32
    assert _fingerprint_salt(one) == salt_a, "salt must be stable, or every probe invalidates"

    salt_b = _fingerprint_salt(two)
    assert salt_a != salt_b, "two installs must not share a salt"

    assert _mode(one / "gold" / ".access_salt") == 0o600

    payload = ({"token": "abc"}, {"org": "x"})
    assert _access_fingerprint(*payload, lake_dir=one) == _access_fingerprint(*payload, lake_dir=one)
    assert _access_fingerprint(*payload, lake_dir=one) != _access_fingerprint(*payload, lake_dir=two)


def test_secret_markers_also_differ_between_installs(tmp_path: Path) -> None:
    """The ``***<hex>`` marker is a hash of the secret and carries the same exposure."""
    one, two = tmp_path / "lake-a", tmp_path / "lake-b"
    for lake in (one, two):
        append_config_event(
            lake,
            connector_id="github-security",
            state="disabled",
            actor="tester",
            credentials={"token": "the-same-secret"},
        )

    def marker(lake: Path) -> str:
        line = (lake / "gold" / CONFIG_FILE).read_text(encoding="utf-8").strip().splitlines()[-1]
        import json

        return json.loads(line)["credentials"]["token"]

    assert marker(one).startswith("***")
    assert marker(one) != marker(two)


def test_probe_before_enable_still_matches_within_one_install(tmp_path: Path) -> None:
    """Rotating the salt must not break the probe-before-enable check it feeds."""
    from security_lakehouse.connector_state import _access_fingerprint

    credentials, options = {"token": "abc"}, {"org": "x"}
    first = _access_fingerprint(credentials, options, lake_dir=tmp_path)
    again = _access_fingerprint(credentials, options, lake_dir=tmp_path)
    rotated = _access_fingerprint({"token": "rotated"}, options, lake_dir=tmp_path)

    assert first == again
    assert first != rotated
