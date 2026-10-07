"""Coverage gates use evaluated/catalog counts, never rounded percentages."""

import pytest

from security_lakehouse.readiness_coverage import readiness_coverage


@pytest.mark.parametrize(
    "evaluated,total,percentage,sufficient",
    [
        (0, 100, 0.0, False),
        (49, 100, 49.0, False),
        (50, 100, 50.0, True),
        (51, 100, 51.0, True),
        (4999, 10000, 50.0, False),
        (0, 0, None, False),
        (1, None, None, False),
        (None, 10, None, False),
        (True, 2, None, False),
        (1, True, None, False),
        (-1, 10, None, False),
        (11, 10, None, False),
        (float("nan"), 10, None, False),
        (1, float("inf"), None, False),
    ],
)
def test_valid_count_boundaries(evaluated, total, percentage, sufficient):
    assert readiness_coverage(evaluated, total) == (percentage, sufficient)
