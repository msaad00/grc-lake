import copy

from security_lakehouse import api_v1
from security_lakehouse.server_app import create_app


def test_json_v1_success_responses_declare_the_envelope(tmp_path):
    spec = create_app(tmp_path, require_auth=False).openapi()
    missing = []
    for path, item in spec["paths"].items():
        if not path.startswith("/api/v1/"):
            continue
        for method, operation in item.items():
            if not isinstance(operation, dict):
                continue
            for code, response in operation.get("responses", {}).items():
                content = response.get("content", {}).get("application/json")
                if code.startswith("2") and content is not None and not content.get("schema"):
                    missing.append((path, method, code))
    assert not missing, missing


def test_openapi_merge_is_idempotent_and_does_not_mutate_input(tmp_path):
    spec = create_app(tmp_path, require_auth=False).openapi()
    original = copy.deepcopy(spec)
    once = api_v1.merge_openapi(spec)
    assert spec == original
    assert api_v1.merge_openapi(once) == once
