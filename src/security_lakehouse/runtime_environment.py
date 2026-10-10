"""Read GRC Lake configuration while accepting the previous environment prefix."""

from __future__ import annotations

import os
from collections.abc import Mapping


def runtime_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an isolated view where a non-empty GRC_LAKE_ value wins.

    Existing TRUSTOPS_ deployments continue to work. Both spellings resolve to
    the same value, including tenant-scoped secrets. An empty GRC_LAKE_ value
    counts as unset when the TRUSTOPS_ spelling is non-empty: otherwise
    ``GRC_LAKE_ENV=`` would silently erase ``TRUSTOPS_ENV=production`` and
    unlock development-only behaviour. Caller dictionaries and the process
    environment are never mutated, so independent app instances cannot leak
    configuration through a cached alias.
    """
    original = dict(os.environ if env is None else env)
    result = dict(original)
    for key, value in original.items():
        if key.startswith("TRUSTOPS_"):
            new_key = "GRC_LAKE_" + key[len("TRUSTOPS_") :]
            if not result.get(new_key):
                result[new_key] = value
    for key, value in list(result.items()):
        if key.startswith("GRC_LAKE_"):
            result["TRUSTOPS_" + key[len("GRC_LAKE_") :]] = value
    return result
