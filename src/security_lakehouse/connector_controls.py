"""Strict explicit mappings for warehouse and object-store observations."""

import re
from typing import Any


def mapped_controls(
    row: dict[str, Any], default: list[str], *, fields: tuple[str, ...] = ("controls", "control_ids", "control_id")
) -> list[str]:
    for field in fields:
        if field not in row:
            continue
        raw = row[field]
        values = re.split(r"[,|]", raw) if isinstance(raw, str) else raw
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value.strip() for value in values)
        ):
            raise ValueError("explicit control mapping must contain nonempty control identifiers")
        return list(dict.fromkeys(value.strip() for value in values))
    return list(dict.fromkeys(default))
