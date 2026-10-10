# Artifact hashing memory benchmark

This experiment compares the former `sha256(path.read_bytes())` operation with
GRC Lake `file_sha256`, which reuses a 1 MiB buffer. Generation sealing and
verification, evidence integrity creation and verification, and Parquet export
use this helper. Hash formats and publication semantics are unchanged.

## Reproduce

From a checkout with Python 3.11 and the project installed:

```bash
uv sync --python 3.11 --frozen --all-extras
uv run python tools/benchmark_artifact_hashing.py > artifact-hashing.json
```

The default run creates synthetic 8, 64, and 256 MiB files, with three repetitions
per method and size. It retains at most one 256 MiB fixture on local temporary
storage. Each worker has a 60-second timeout; the 18 workers run serially. No
network, cloud resources, credentials, or account evidence are used. Failed or
timed-out attempts remain in the result, and any failed attempt makes the command
exit nonzero. Keep such results alongside successful runs.

Each file repeats the bytes 0 through 255. Both methods must match the SHA-256
computed while generating the fixture. A parent process reads the file before
each worker; these are warm-cache measurements. Method order alternates between
repetitions. Process startup/import time is excluded from hash duration.

Each measurement uses a fresh child process. `peak_python_bytes` is the
`tracemalloc` peak during hashing; `peak_rss_bytes` is the process-lifetime high
water mark, including Python and imports. RSS is normalized to bytes on macOS
and Linux. Timing includes tracing overhead. The JSON records every attempt,
Python/OS/architecture, logical CPU count, revision, tracked diff hash, and hashes
of the measured helper source and benchmark script. A nonempty diff means the
revision alone does not identify the measured implementation; compare the source
hashes too. Hostnames, user paths, and account identifiers are excluded.

## Recorded synthetic run

Measured 2026-09-14 on macOS arm64, Python 3.11.15,
with 10 logical CPUs. All 18 attempts matched their fixture hashes. The table
shows the maximum memory across three attempts per row, plus median and range
of hash duration. [Raw attempts and source hashes](artifact-hashing.json) are
included so the measurements can be checked and repeated.

| File    | Method     | Peak Python MiB | Peak RSS MiB | Median ms |      Range ms |
| ------- | ---------- | --------------: | -----------: | --------: | ------------: |
| 8 MiB   | Whole file |            8.00 |        32.67 |      6.78 |     6.61–6.84 |
| 8 MiB   | Streaming  |            1.01 |        25.66 |      6.21 |     6.10–6.25 |
| 64 MiB  | Whole file |           64.00 |        88.67 |     53.26 |   53.00–55.54 |
| 64 MiB  | Streaming  |            1.01 |        25.59 |     47.11 |   46.94–47.81 |
| 256 MiB | Whole file |          256.00 |       280.83 |    223.63 | 214.19–225.52 |
| 256 MiB | Streaming  |            1.01 |        25.59 |    193.82 | 193.82–199.79 |

The measured streaming Python allocation peak stayed near 1 MiB across these
file sizes. Total process RSS includes the interpreter and was higher. These
results establish the hashing allocation improvement on this host; the warm-cache
durations do not establish a general throughput or speedup guarantee.

## Scope and limitations

This is a file-hashing microbenchmark. It measures neither pipeline throughput nor
API latency. Full normalization and evidence verification still materialize rows,
sets, and sorted collections; manifests are parsed in memory. Source-record size,
concurrent workload memory, disk throughput, cold-cache behavior, distributed
storage, and production capacity are unverified. Disk type and physical RAM are
not recorded by this small harness, so timing comparisons across hosts are not
supported. No live precision/recall or vendor cost-savings claim follows from this
result. Use the broader [validation protocol](../BENCHMARKS.md) for those questions.
