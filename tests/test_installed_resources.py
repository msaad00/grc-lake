"""Runtime resources must resolve without a repository or working-directory fallback."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def test_cloud_templates_and_schemas_without_checkout(tmp_path):
    import security_lakehouse

    package = tmp_path / "security_lakehouse"
    shutil.copytree(
        Path(security_lakehouse.__file__).parent, package, ignore=shutil.ignore_patterns("__pycache__", "web")
    )
    code = """
import json
from importlib.resources import files
from security_lakehouse.cloud_linking import aws_template_bytes, aws_terraform_bytes, gcp_template_bytes
assert b'AWSTemplateFormatVersion' in aws_template_bytes()
assert b'resource' in aws_terraform_bytes()
assert b'resource' in gcp_template_bytes()
schema = json.loads(files('security_lakehouse').joinpath('resources/schemas/raw-security-event.schema.json').read_text())
assert schema['type'] == 'object'
print(json.dumps({'resources': 'ok'}))
"""
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"resources": "ok"}
