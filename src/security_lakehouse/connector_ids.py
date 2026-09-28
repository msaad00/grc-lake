"""Deterministic connector-local event id slugs."""

from __future__ import annotations

import hashlib
import re

_UNSAFE = re.compile(r"[^a-z0-9_.:-]+")
_DIGEST_CHARS = 12


def stable_id_slug(
    seed: str,
    *,
    fallback: str,
    limit: int = 96,
    keep: str = "head",
    unsafe: re.Pattern[str] = _UNSAFE,
) -> str:
    """Slug ``seed`` into a stable id that stays unique when it must be shortened.

    Cloud resource names share long common prefixes, so plain truncation maps
    distinct resources onto one id and the later row silently replaces the
    earlier one. A slug over ``limit`` keeps its readable head (or tail, with
    ``keep="tail"``) and appends a digest of the full seed. Seeds that already
    fit keep their historical id.
    """
    raw = str(seed).lower()
    slug = unsafe.sub("-", raw).strip("-")
    if not slug:
        return fallback
    if len(slug) <= limit:
        return slug
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_DIGEST_CHARS]
    room = limit - _DIGEST_CHARS - 1
    kept = slug[-room:].strip("-") if keep == "tail" else slug[:room].rstrip("-")
    return f"{kept}-{digest}"


__all__ = ["stable_id_slug"]
