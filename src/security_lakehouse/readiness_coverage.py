"""Catalog-denominated coverage gate shared by assessment read projections."""

from __future__ import annotations

FRAMEWORK_READY_MIN_COVERAGE_PCT = 50.0


def readiness_coverage(evaluated: object, catalog_total: object) -> tuple[float | None, bool]:
    """Return displayed coverage and its gate; invalid/missing counts fail closed.

    Callers supply their explicitly evaluated population, not mapping counts.
    Compare the original counts before rounding the displayed percentage.
    """
    if (
        type(evaluated) is not int
        or type(catalog_total) is not int
        or catalog_total <= 0
        or evaluated < 0
        or evaluated > catalog_total
    ):
        return None, False
    return round(
        100 * evaluated / catalog_total, 1
    ), 100 * evaluated >= catalog_total * FRAMEWORK_READY_MIN_COVERAGE_PCT
