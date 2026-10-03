# Bounded CCF pipeline measurements

Measured October 3, 2026 on clean source commit `a73a9b53d7d5dcca0584a79c5e52b3e72dbcce7d`.
These are synthetic local measurements, not production capacity or live-control
accuracy claims. [Raw corrected results](ccf-pipeline-2026-10-03.json) retain all
nine attempts, input hashes, source fingerprint, environment, and guardrails.

| Events / observed assets | Median pipeline seconds |   Seconds range | Peak process RSS MiB | Retained generation MiB | Counts, labels, integrity |
| -----------------------: | ----------------------: | --------------: | -------------------: | ----------------------: | ------------------------- |
|                    1,000 |                   3.668 |     3.627–3.745 |          269.8–276.7 |               30.0–30.0 | 3/3                       |
|                   10,000 |                  16.300 |   16.165–16.803 |          634.4–687.8 |             159.7–160.0 | 3/3                       |
|                  100,000 |                 166.911 | 141.607–267.414 |        2765.2–3002.3 |           1416.7–1417.2 | 3/3                       |

## Workload and method

One platform tenant, one explicit identity safeguard, three framework tags per
event, seed 42. Two source tenants deliberately reuse asset IDs. Each of five
cases contains 20% of events: pass, fail, unknown, stale, and absent safeguard
binding. Thus 100k events produce 80k asset/safeguard outcomes (20k each of pass,
fail, not evaluated, and stale); the remaining 20k assets lack a binding. Each
asset verdict and event ID is compared with the predefined label set. This does
not establish complete inventory or exhaustive safeguard/rule coverage.

The pipeline evaluation clock is pinned to `2026-10-03T16:41:01.796885+00:00`
so freshness labels remain stable between repeats. Real wall time and resource
watchdogs remain unmodified. Each attempt starts a fresh process and temporary
lake. Pipeline seconds exclude fixture generation and post-run verification;
peak RSS covers the worker, including those operations. Retained bytes include
all generation artifacts, including SQLite and DuckDB marts, and exclude raw
fixture intake outside the lake.

Host: macOS 27.0.1 ARM64, Python 3.13.5, 10 logical CPUs, 16 GiB physical memory.
No other task-owned test/build workload ran during these measurements; OS page
cache and other system applications were not controlled. Runs are sequential,
not cold-cache or concurrent-tenant capacity tests. Watchdog thresholds: 600 s,
4 GiB sampled RSS, and 5 GiB free disk, sampled every 250 ms. Temporary storage is
removed after each attempt. These thresholds are not hard OS allocation limits.

## Reproduce

```bash
uv sync --frozen --all-extras
uv run python tools/benchmark_assessment_pipeline.py --workload ccf --sizes 1000 10000 100000 --repeats 3 --base-time 2026-10-03T16:41:01.796885+00:00
```

Use the recorded source revision for exact fixture hashes. Preserve every failed
or bounded-out attempt. Stop before increasing load if a smaller size fails.
The pipeline remains memory-bound local Python evaluation; a configured warehouse
sink does not change that. Million-event, authenticated-provider, HTTP concurrency,
and cross-host HA behavior were not tested by this harness.

## Retained failed experiment

The [initial clock-dependent run](ccf-pipeline-initial-clock-2026-10-03.json) at
`2075679b1d8f7e40b9c36a15db461dd70d3b0ddb` passed eight attempts but failed the
third 100k label check. The elapsed experiment crossed a connector freshness
threshold: 2,857 expected passes correctly became stale. Counts and integrity
still passed. The harness had fixed labels but used a moving evaluation time.
A regression using an old fixture date reproduced this defect; the corrected
harness pins only the synthetic pipeline clock. The failed run is retained and
is not counted as a successful qualification or a before/after speedup baseline.

See the broader [validation protocol](../BENCHMARKS.md) for live-provider,
isolation, availability, and accuracy requirements.
