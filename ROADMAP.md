# GRC Lake Roadmap

Status as of v0.3.1 source preparation; publication is verified separately. Remaining gaps come first. Track work in GitHub issues.

## Remaining gaps

The linked epics are closed on GitHub; each row names what is still left.

| Epic                                                   | Area           | What remains                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------ | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [#611](https://github.com/msaad00/grc-lake/issues/611) | Frameworks     | ISO 27701:2025 is a limited pack (10 of 78 Annex A controls); SOC 1 stays planned (no official catalog); NIST 800-171 Rev 3, NIS2, and DORA are new and proposed-only                                                                                                          |
| [#608](https://github.com/msaad00/grc-lake/issues/608) | Connectors     | CIS Azure/GCP benchmarks, ISO 27001 clauses 4–10; live-tenant runs for the Jamf, CrowdStrike, Kubernetes, KnowBe4 previews                                                                                                                                                     |
| [#609](https://github.com/msaad00/grc-lake/issues/609) | Existing lakes | Databricks, Iceberg/Parquet, and BigQuery readers are preview and lake mappings are experimental; live verification pending                                                                                                                                                    |
| [#610](https://github.com/msaad00/grc-lake/issues/610) | Platform       | Billing and SCIM shipped (gated commercial features); live Stripe + IdP verification pending                                                                                                                                                                                   |
| —                                                      | Mapping review | 1,361 of 1,702 safeguard-to-requirement mapping rows are proposed, so 1,075 of the 1,415 mapped requirements have no reviewed mapping yet (including all NIST RMF, ISO 27701, NIST 800-171 Rev 3, NIS2, and DORA mappings). Proposed mappings are evaluated but not attestable |

Mapping counts are effective review states: a mapping marked reviewed against an
older control version counts as proposed until it is re-reviewed.

## Published in v0.3.0

- GRC Lake branding, commands and registry targets, with legacy command aliases.
- Opt-in PostgreSQL/S3 distributed mode with independent API/reader replicas.
- Stable virtual worker shards, tenant/source/date Parquet partitions and 32
  physical PostgreSQL history partitions within one database cluster.
- Parallel tenant admission, database-clock recovery and real S3 qualification.
- Console/demo improvements and the security fixes in the changelog.

Cross-database sharding, automated shard placement, provider HA/failover testing,
and production capacity qualification remain future work. Storage replication,
erasure coding and RAID belong to the selected infrastructure.

## Prepared for v0.3.1

- Generation-aware read caches and seek-based JSONL collection pages.
- Bulk DuckDB mart loading and faster strict JSON decoding, preserving validation.
- Refreshed README visuals and deployment guidance.

Cache reuse across distributed request scratch directories remains limited.
These changes do not establish a production capacity claim.

## Recently shipped

v0.2.24:

- Opt-in scheduled retention through the existing scheduler and Helm CronJob.
- Bounded, per-tenant-fair background job workers.
- Capped MCP tool output, accurate tool annotations, and an untrusted-content envelope.
- Cursor paging for graph and coverage routes and streamed evidence pages.
- Copied trust-share revocation and catalog control-ID collision checks.

The [changelog](CHANGELOG.md) has every release, and the
[release gates](docs/RELEASE_READINESS.md) explain how a release is qualified
and published.
