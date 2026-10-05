from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from security_lakehouse import strict_json
from security_lakehouse.validation import evidence_timestamp

FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time", raises=(ValueError, TypeError))
def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return True  # The schema type validator handles non-string values.
    evidence_timestamp(value)
    return True


ROOT = Path(__file__).resolve().parents[1]
JSON_FILES = [
    "data/schemas/raw-security-event.schema.json",
    "data/schemas/normalized-event.schema.json",
    "data/schemas/current-posture.schema.json",
    "data/schemas/evidence-freshness.schema.json",
    "data/schemas/violation.schema.json",
    "controls/catalog.json",
    "frameworks/registry.json",
    "mappings/control_map.json",
    "connectors/catalog.json",
    "programs/catalog.json",
    "programs/vendor_questionnaires.json",
    "policy_templates/catalog.json",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate TrustOps JSON, JSONL, schemas, and generated artifacts.")
    parser.add_argument("--generated", action="store_true", help="Also validate generated lake artifacts.")
    args = parser.parse_args()

    for relative in JSON_FILES:
        _read_json(ROOT / relative)

    schemas = {path.name: _read_json(path) for path in (ROOT / "data" / "schemas").glob("*.schema.json")}
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)

    raw_events = _read_jsonl(ROOT / "data" / "raw" / "security_events.jsonl")
    _validate_rows(schemas["raw-security-event.schema.json"], raw_events)

    if args.generated:
        lake = ROOT / "build" / "lakehouse"
        _validate_rows(
            schemas["normalized-event.schema.json"], _read_jsonl(lake / "silver" / "normalized_events.jsonl")
        )
        _validate_rows(
            schemas["evidence-freshness.schema.json"], _read_jsonl(lake / "gold" / "evidence_freshness.jsonl")
        )
        current_posture_schema = copy.deepcopy(schemas["current-posture.schema.json"])
        current_posture_schema["properties"]["violations"] = {
            "type": "array",
            "items": schemas["violation.schema.json"],
        }
        Draft202012Validator(current_posture_schema, format_checker=FORMAT_CHECKER).validate(
            _read_json(lake / "gold" / "current_posture.json")
        )

    return 0


def _read_json(path: Path) -> dict[str, Any] | list[Any]:
    with path.open(encoding="utf-8") as handle:
        return strict_json.loads(handle.read())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():
                value = strict_json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{line_number}: expected JSON object")
                rows.append(value)
    return rows


def _validate_rows(schema: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
    for row in rows:
        validator.validate(row)


if __name__ == "__main__":
    raise SystemExit(main())
