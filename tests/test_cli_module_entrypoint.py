"""Exercise Python module execution, which differs from importing main()."""

import subprocess
import sys


def test_module_entrypoint_can_build_all_command_parsers():
    result = subprocess.run(
        [sys.executable, "-m", "security_lakehouse.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "assessment" in result.stdout
