# TrustOps validation and benchmark plan

**Status: validation protocol.** This document defines reproducible
methods for evaluating TrustOps. Existing unit tests,
synthetic fixtures, connector availability, and configured warehouse sinks do
not establish live accuracy, production capacity, or certification readiness.

The [bounded CCF pipeline measurements](benchmarks/CCF_PIPELINE.md) record repeated
1k, 10k, and 100k synthetic runs, including a retained failed experiment.

The [artifact hashing microbenchmark](benchmarks/ARTIFACT_HASHING.md) measures one
specific memory improvement using synthetic files. It does not establish
end-to-end capacity, detection accuracy, or cost savings.

The bounded full-pipeline harness records row counts, integrity checks, wall time,
process peak RSS, retained-generation bytes, input hashes, commit and working-tree
fingerprints. It uses one platform tenant. Each attempt stops after 600 seconds,
when sampled worker RSS exceeds 4 GiB, or when free disk drops below 5 GiB.
RSS and disk are sampled every 250 ms; these are watchdog thresholds, not hard
allocation limits. The parent removes temporary lakes even after killing a worker.
A failed attempt stops progression to larger sizes and remains in the report.

```bash
uv run python tools/benchmark_assessment_pipeline.py --sizes 1000 10000 --repeats 3
uv run python tools/benchmark_assessment_pipeline.py --workload ccf --sizes 1000 10000 100000 --repeats 3
```

Run without concurrent tests or other workload and report the actual environment.
The default fixture tests framework-control fan-out without explicit safeguard
bindings. The `ccf` fixture uses one explicit identity safeguard and five cases:
pass, fail, unknown, stale, and missing binding. It checks independently assigned
asset verdicts and event IDs at an explicit pipeline evaluation time pinned to
`--base-time`; real elapsed time cannot change the freshness labels between
repeats. Resource watchdogs and wall-time measurements use the real clock.
The same asset IDs are deliberately reused across
two source tenants within one platform tenant. Twenty percent of assets have no
binding; that missing population must not become a pass. These fixtures do not
establish multi-tenant API capacity or exhaustive safeguard/rule accuracy.

Choose larger sizes only after smaller ones pass with resource headroom. The
harness intentionally stops at 100k events; no result establishes million-event
capacity. Preserve failed and bounded-out measurements alongside successes.

## 1. Record the experiment

Every run must identify the exact commit, dirty-tree diff hash if applicable,
rule/catalog versions, dataset and label-set hashes, random seed, timestamp,
commands, configuration, and raw result artifacts. Record hardware, CPU, memory,
disk, OS, worker count, region, network conditions, backend versions, and costs.
Retain failures and timeouts alongside successful runs. Redact account identifiers
and sensitive evidence from publishable artifacts without changing measurements.

Separate three evidence levels: controlled labeled tests, synthetic load tests,
and authenticated live trials. Never combine them into a single accuracy or
scale claim. Use an independent holdout label set after rules are tuned.

## 2. Correctness and detection quality

Use one applicable **asset × control × observation time** as the evaluation unit.
A positive means a verified control failure. Label expected outcomes independently
of TrustOps results using source configurations and reviewer adjudication; record
uncertain labels separately. Do not derive ground truth from generated findings.

| Measure                 | Definition and reporting requirement                                                                                                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Precision               | `TP / (TP + FP)`: how often a reported failure is correct.                                                                                                                                                 |
| Recall                  | `TP / (TP + FN)`: how many known failures are detected.                                                                                                                                                    |
| False-positive rate     | `FP / (FP + TN)`, distinct from the share of alerts that are false, `FP / (TP + FP)`.                                                                                                                      |
| F1                      | Harmonic mean of precision and recall when both are defined.                                                                                                                                               |
| Decision coverage       | Evaluated applicable units / all labeled applicable units. Report unknown, stale, unsupported, error, and not-evaluated counts separately.                                                                 |
| Collection completeness | Collected unique eligible assets / independently enumerated eligible assets within the declared account, region, service, permissions, and time window. An unknown denominator means unknown completeness. |
| Verdict consistency     | Compare the same pinned evidence and rule versions across CLI, API, MCP, and UI, including exports.                                                                                                        |

Publish TP, FP, TN, FN, sample sizes, class balance, and uncertainty intervals;
report undefined denominators as N/A. Break results down by source, asset type,
control family, and severity. Report both pooled and per-control results so common
checks do not conceal weak coverage. Abstentions must remain visible; also report
an end-to-end failure-detection rate that includes known failures left unevaluated.

Exercise invalid rules, empty evidence, missing permissions, expired credentials,
pagination caps, rate limits, retries, duplicate/out-of-order events, deleted assets,
stale evidence, interrupted publication, and corrupt generations. Partial evidence
must not become a complete or passing assessment. Framework mapping coverage is
separate from executable test coverage and from compliant outcomes.

## 3. Live account trials

Run AWS, Azure, GCP, and Snowflake independently. For each, record accessible scope,
permissions, supported and unsupported asset types, an independent source inventory,
known-good and known-failing configurations, collected counts, source timestamps,
and assessment results. Use existing read-only access for observation. Any deliberate
configuration changes for test cases need an isolated test scope and authorization.

Follow one complete journey: connect → collect → evaluate → assign → review → export.
Record evidence freshness, detection delay, failure recovery, and ownership history.
Do not infer coverage of unqueried services or other accounts from one successful trial.

## 4. Volume, scale, and performance

Start with bounded synthetic workloads and increase only after each stage passes.
Proposed event counts are 1k, 10k, 100k, and 1M; these are test targets, not capacity
claims. Declare the stopping limits for disk, memory, duration, and cloud spend
before each run. Use [existing synthesis and pipeline commands](AUDIT_SCALE.md).

Record tenants, assets, events, controls per event, findings, event size distribution,
uncompressed and stored bytes, index size, and retained-generation disk usage.
Vary full vs incremental collection, change ratio, tenant skew, and concurrent
collection/evaluation/read traffic. Measure:

- Wall time, events/s, assets/s, MB/s, and end-to-end evidence-to-verdict delay.
- API and job p50/p95/p99 latency, with sample counts and enough observations for the reported percentile.
- Queue depth, retry/error/timeout rates, duplicate or dropped records, and recovery time.
- Peak RSS, CPU, disk I/O, network bytes, storage growth, and cost per run or million events.

Separate cold and warm runs; publish repeated-run variation and total attempts.
Verify counts, hashes, verdicts, and tenant boundaries under load. A fast run with
lost evidence is a failed run. A configured external sink alone does not prove
warehouse execution or that local memory bottlenecks have been removed.

## 5. Security and interoperability

| Area                        | Required evidence                                                                                                                                                                                                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Tenant isolation            | Negative access tests across inventory, evidence, jobs, caches, exports, and every supported interface, including concurrent workloads.                                                                                                                                              |
| Permissions and agents      | Least-privilege collection, role enforcement, approval boundaries, audit trails, and no unauthorized mutation from suggested remediation or untrusted evidence.                                                                                                                      |
| Data handling               | Secret redaction, configured egress behavior, retention/deletion behavior, and integrity checks under interrupted writes.                                                                                                                                                            |
| Portability                 | Read an exported artifact with an independent implementation; compare schema, types, row counts, stable identifiers, provenance, and representative values.                                                                                                                          |
| Optional open-table adapter | [Parquet](PARQUET_EXPORT.md) has fixture-based DuckDB parity tests. [Iceberg REST](ICEBERG_REST.md) has local Polaris publication and DuckDB historical-read checks. Injected commit failures and concurrency are unit-tested. Cloud storage and production scale remain unverified. |

Record the versions and commands of independent readers. Reading an export back
through TrustOps alone is insufficient evidence of interoperability. A dependency
vulnerability audit is one security check, not a complete security assessment.

## 6. Cost comparison and break-even

Compare equivalent scope and service levels: accounts, assets, framework programs,
users, evidence retention, collection frequency, support, availability, and required
integrations. Record any capability or service gap rather than assigning it zero cost.
Compare deployment scenarios separately; self-hosted software and a managed service
carry different operating responsibilities.

Use dated quotes, invoices, measured resource usage, and documented loaded labor
rates. Keep confidential vendor terms and customer identifiers out of public artifacts.
Public prices alone may omit negotiated discounts, minimum commitments, and add-ons.
Do not publish a vendor-specific savings claim without a comparable, supportable baseline.

| Cost bucket             | Include                                                                                                                             |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Subscription            | Platform fees, seats, account/asset tiers, framework and integration add-ons, and support.                                          |
| Infrastructure and data | Compute, databases, workers, backups, retained generations, object storage, logs, egress, warehouse credits, and cloud API charges. |
| People                  | Setup, integration, maintenance, upgrades, monitoring, incident response, control tuning, reviewer effort, and support.             |
| Transition              | Migration, parallel operation, training, and exit/export effort.                                                                    |
| Assessment              | External assessor and certification expenses where applicable; identify costs common to both options.                               |

For a declared comparison horizon:

```text
Total cost = one-time costs + recurring service/resource costs + labor costs
Savings = comparable alternative total cost - TrustOps total cost
Savings % = savings / comparable alternative total cost × 100
```

Report currency, duration, price date, utilization, labor assumptions, and included
costs. A zero baseline makes the percentage undefined. Separate cash reductions,
capacity freed, and hypothetical avoided costs; reduced task time is not automatically
a reduced cash expense. Do not double count time savings already included in labor.

Publish low/base/high scenarios for volume, retention, labor, and negotiated prices.
For approximately constant monthly costs, break-even months equal incremental
one-time migration/setup cost divided by monthly recurring savings. If recurring
savings are zero or negative, report no break-even under those assumptions. For
variable costs, use cumulative monthly cash flows and show the first crossing.
Report negative savings and gaps as clearly as positive results. A short pilot
provides a projection with assumptions, not a proven annual saving.

## 7. Human and agent workflow quality

Evaluate the same scoped tasks through the console and through API, CLI, and MCP.
Measure task completion against independently verified outcomes, time, manual
interventions, tool calls, model tokens/cost where applicable, and recovery after
an interrupted or failed task. Record agent/model version, permissions, prompts,
allowed tools, and repeated-run variation. Keep agent task success separate from
deterministic control precision and recall.

Check tool discovery, schema validity, pagination, job polling, stale-result
handling, retry/idempotency behavior, and evidence links. Inject misleading
instructions into test evidence and verify they cannot authorize tool actions or
cross tenant boundaries. For human reviews, measure whether users can identify
missing evidence, explain a verdict, assign an owner, and verify an export.

## 8. Workflow value and publication

Compare the same scoped task manually and with TrustOps: time to first evidence,
time to investigate a finding, reviewer effort per finding, time to prepare an
assessment export, and repeated work avoided. Record participants, task definitions,
sample counts, and the baseline. Assess remediation suggestions for correctness,
actionability, and unsafe advice separately from deterministic rule accuracy.

Certification support means evidence preparation and readiness tracking for external
assessors. Do not claim certification issuance, guaranteed audit outcomes, universal
AI safety, or a universal trust score from these benchmarks.

Publish a result table with **measured / failed / blocked / not tested** for every
area, linked to reproducible artifacts and known limitations. Public reports
should show a verified workflow, actual measurements, supported scope, and gaps.
Do not publish headline accuracy, performance, or cost numbers from projections.
