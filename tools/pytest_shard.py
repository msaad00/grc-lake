"""Opt-in, deterministic module sharding: pytest -p tools.pytest_shard --ci-shard=1/4.

Balance by collected test count, including parametrization, without splitting
module fixtures across runners. New tests participate automatically. Ordinary
pytest runs are unchanged; empty shards retain pytest's nonzero exit status.
"""

from __future__ import annotations

from collections import defaultdict

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--ci-shard", help="One-based shard index/count, for example 1/4")


def _shard(config: pytest.Config) -> tuple[int, int] | None:
    value = config.getoption("--ci-shard")
    if value is None:
        return None
    try:
        index, count = map(int, value.split("/"))
        if not 1 <= index <= count:
            raise ValueError
    except ValueError as exc:
        raise pytest.UsageError("--ci-shard must be index/count with 1 <= index <= count") from exc
    return index - 1, count


def pytest_configure(config: pytest.Config) -> None:
    _shard(config)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    shard = _shard(config)
    if shard is None:
        return
    index, count = shard
    modules: dict[str, list[pytest.Item]] = defaultdict(list)
    for item in items:
        modules[item.nodeid.split("::", 1)[0]].append(item)
    loads = [0] * count
    owners: dict[str, int] = {}
    for module in sorted(modules, key=lambda name: (-len(modules[name]), name)):
        owner = min(range(count), key=lambda candidate: (loads[candidate], candidate))
        owners[module] = owner
        loads[owner] += len(modules[module])
    selected, deselected = [], []
    for item in items:
        target = selected if owners[item.nodeid.split("::", 1)[0]] == index else deselected
        target.append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
