# Bring your own lake

Connect TrustOps to the security lake you already run, read-only, without
creating TrustOps-shaped views first. A **lake mapping** says which columns of an
existing table become TrustOps evidence; the lake readers apply it with a
parameterized, read-only query and feed the rows into the normal pipeline
(raw → bronze/silver/gold → posture).

> **Status.** The mapping spec is **experimental (v1)**: its shape may change
> before it is declared stable. The `iceberg-parquet-lake` and
> `bigquery-evidence-lake` readers are **preview**: they are tested against local
> Iceberg tables, local Parquet datasets, and recorded query shapes, but have not
> been verified against a live AWS Glue catalog, Amazon Security Lake account,
> Iceberg REST catalog, S3 bucket, or BigQuery project. Mapping mode on the
> Snowflake, Databricks, and ClickHouse readers is tested with fixtures and fake
> drivers only.

## Modes

| Mode                               | Readers                           | What you provide                                                                                  |
| ---------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------- |
| TrustOps views (unchanged default) | Snowflake, Databricks, ClickHouse | The TrustOps evidence views or table ([HERO_DATA_LAKES.md](HERO_DATA_LAKES.md))                   |
| Mapped tables                      | Snowflake, Databricks, ClickHouse | `options.mapping` (one spec or preset reference) or `options.mappings` (a list)                   |
| Iceberg / Parquet (preview)        | `iceberg-parquet-lake`            | A Glue or Iceberg REST catalog, or a Parquet location, plus mappings (optional for Security Lake) |
| BigQuery (preview)                 | `bigquery-evidence-lake`          | A query project, plus mappings                                                                    |

Without `mapping`/`mappings`, the Snowflake, Databricks, and ClickHouse readers
behave exactly as before. With a mapping, they read only the mapped tables, and
**Test connection** reads one row from each mapped table instead of the TrustOps
views.

## Quick start

Preview a built-in preset against sample rows. Nothing is written:

```bash
security-lakehouse lake presets
security-lakehouse lake map --dry-run \
  --preset ocsf/compliance_finding --table security_lake.sh_findings \
  --input sample_rows.jsonl --dialect snowflake
```

The report shows the compiled SQL and its parameters, how many rows were read,
mapped, and filtered out, per-row errors, and the first `--limit` mapped events.
Exit codes: `0` clean, `1` invalid spec, `2` some rows could not be mapped.
`--input` accepts a `.json` list, `.jsonl`, or `.parquet` (needs the `parquet`
extra). `lake map` only previews in this version and always needs `--dry-run`.

Once a mapping is configured on a connector, preview it through that connector's
reader, live or with `--fixture-dir`, again without writing evidence or moving the
watermark:

```bash
security-lakehouse lake map --dry-run --lake build/lakehouse --connector-id snowflake-evidence-lake
```

Configure a reader with a mapping (API and console configure calls take the same
`options` object):

```bash
security-lakehouse connectors configure --lake build/lakehouse \
  --connector-id snowflake-evidence-lake --state enabled \
  --credentials-json '{"account":"acme-prod","user":"TRUSTOPS_READER_SVC","private_key_ref":"SNOWFLAKE_PRIVATE_KEY_FILE"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"SECURITY","schema":"OCSF",
                   "mappings":[{"preset":"ocsf/api_activity","source":{"table":"CLOUDTRAIL_OCSF"}},
                               {"preset":"ocsf/authentication","source":{"table":"CLOUDTRAIL_OCSF"}}]}'
security-lakehouse connectors sync --lake build/lakehouse --connector-id snowflake-evidence-lake
```

Invalid mappings are rejected when the connector is configured, with every
problem listed by path. Connector options accept only inline specs and preset
references, never file paths. The console forms cover the Amazon Security Lake
defaults; custom mappings are set through the API or CLI.

## Mapping spec reference (v1)

```json
{
  "spec_version": 1,
  "name": "okta_signins",
  "description": "Okta System Log sign-ins exported to the warehouse",
  "source": {
    "table": "security.okta_system_log",
    "incremental": true,
    "lookback_minutes": 60
  },
  "filters": [
    {
      "column": "event_type",
      "op": "in",
      "value": ["user.session.start", "user.authentication.sso"]
    }
  ],
  "fields": {
    "id": { "column": "uuid" },
    "observed_at": { "column": "published", "format": "timestamp" },
    "source": { "const": "okta" },
    "event_type": { "column": "event_type", "prefix": "okta." },
    "asset_id": {
      "coalesce": [{ "column": "actor.id" }, { "const": "okta:org" }]
    },
    "asset_type": { "const": "identity" },
    "owner": { "column": "actor.alternate_id" },
    "severity": {
      "column": "outcome.result",
      "map": { "FAILURE": "medium" },
      "default": "info"
    },
    "status": { "const": "observed" },
    "controls": { "const": ["SOC2-CC6.1", "ISO27001-A.8.5"] }
  },
  "attributes": {
    "ip": { "column": "client.ip_address" },
    "outcome": { "column": "outcome.result" }
  }
}
```

JSON is always accepted; `lake map --mapping` also reads `.yaml`/`.yml` when
PyYAML is installed. Specs are limited to 64 KiB.

### Top-level keys

| Key            | Required | Meaning                                                                                                                                                                                         |
| -------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec_version` | yes      | Must be `1`.                                                                                                                                                                                    |
| `name`         | yes      | 1-64 lowercase letters, digits, `_`, `-`. Part of every event id, so keep it stable. Unique per connector.                                                                                      |
| `description`  | no       | Up to 500 characters.                                                                                                                                                                           |
| `source`       | yes      | `table` (1-3 dot-separated identifiers), `incremental` (default `true`), `lookback_minutes` (0-10080).                                                                                          |
| `filters`      | no       | Up to 20 filters, all of which must match.                                                                                                                                                      |
| `fields`       | yes      | The evidence fields below.                                                                                                                                                                      |
| `attributes`   | no       | Up to 64 extra values kept in `attributes` (keys are identifiers; names containing `secret`, `token`, `password`, `private_key`, or `api_key` are rejected because stored options redact them). |

### Fields

| Field          | Required | Becomes                        | Notes                                                                                          |
| -------------- | -------- | ------------------------------ | ---------------------------------------------------------------------------------------------- |
| `id`           | yes      | stable `event_id`              | `{"column": ...}` or `{"columns": [...]}` (1-8). A row with every id column empty is an error. |
| `observed_at`  | yes      | `event_time` and the watermark | One **top-level** column; `format` is `timestamp` (default), `epoch_ms`, or `epoch_s`.         |
| `asset_id`     | yes      | `entity.asset_id`              | A row with no value is an error.                                                               |
| `source`       | no       | `source`, `entity.org`         | Defaults to the reader (`snowflake`, `databricks`, `clickhouse`, `iceberg`, `bigquery`).       |
| `event_type`   | no       | `event_type`                   | Defaults to `<source>.<name>`.                                                                 |
| `asset_type`   | no       | `entity.asset_type`            | Defaults to `lake_record`.                                                                     |
| `owner`        | no       | `entity.asset_owner`           | Defaults to `unassigned`.                                                                      |
| `environment`  | no       | `entity.environment`           | Defaults to `unknown`.                                                                         |
| `severity`     | no       | `severity`                     | Must resolve to `critical`, `high`, `medium`, `low`, `info`, or `none`; else `info`.           |
| `status`       | no       | `status`                       | Must resolve to `pass`, `open`, or `observed`; else `observed`.                                |
| `controls`     | no       | `controls` (control hints)     | A list constant, a list column, or a delimited string column with `split`.                     |
| `evidence_ref` | no       | `evidence.evidence_ref`        | Defaults to `lake://<table>/<id digest>`.                                                      |

Constants and map values for `severity` and `status` are checked against those
vocabularies when the spec loads.

Every event also carries `attributes.source_id` (the id value), `raw_sha256` (a
SHA-256 of the canonical JSON of the whole source row), `mapping`,
`mapping_spec_version`, `source_table`, and `mapping_preset` when a preset was
used. `event_id` is `<source>-<name>-<hash of the id values>`, so re-reading a
row, or a newer version of the same finding, replaces the earlier event instead
of duplicating it.

### Value expressions

Each field or attribute is an object with exactly one of:

- `column`: a column path. Identifiers are joined by `.`, with optional `[n]`
  array indexes, for example `actor.user.name` or `resources[0].uid`. Top-level
  column names match case-insensitively; JSON text (Snowflake `VARIANT`,
  Databricks `STRUCT` in `JSON_ARRAY` results) is decoded while resolving nested
  segments.
- `const`: a string, number, boolean, or list of strings.
- `coalesce`: a list of up to 8 `column`/`const` objects. The first non-empty
  value wins. Coalesce lists cannot be nested.

Optional modifiers: `map` (source value → output; numeric source values match
their integer text, so `severity_id` 4 matches `"4"`; without a `default`, an
unmapped value passes through unchanged), `default` (used when the value is
empty or not in `map`), `prefix`, and `split` (for `controls` only).
There is no expression language: no functions, casts, or SQL fragments.

### Filters

`{"column": <top-level column>, "op": <op>, "value": <value>}` where `op` is
`eq`, `ne`, `in`, `not_in`, `is_null`, or `is_not_null`. Values are strings,
integers, or booleans (`in`/`not_in` take a list of up to 100). Filters are
pushed into the backend query as bound parameters and re-applied in Python to
every fetched row.

## How a mapping becomes a query

For SQL backends the spec compiles to one statement:

```sql
SELECT <every top-level column the mapping reads>
FROM <table>
WHERE <filters> AND <observed_at column> >= <watermark bound>
ORDER BY <observed_at column>
LIMIT <max_rows_per_sync>
```

- Only validated identifiers reach the SQL text. Snowflake and ClickHouse use
  strictly validated bare identifiers (Snowflake resolves them
  case-insensitively); Databricks and BigQuery quote them with backticks.
- Values are bound by the driver: Snowflake `%(name)s` (pyformat, bound
  client-side by the connector), Databricks `:name` in the Statement Execution API
  `parameters` list, ClickHouse `{name:Type}` HTTP parameters on a `readonly=1`
  query, BigQuery `@name` query parameters (the watermark is a typed `TIMESTAMP`).
- Nested paths are never sent to the backend; the top-level column is fetched
  and the path is resolved in Python.
- A one-part table is qualified with the Databricks `catalog`.`schema`, the
  ClickHouse `database`, or the BigQuery `dataset` from the connector settings.
  Snowflake resolves it against the connection's database and schema.

Iceberg and Parquet readers generate no SQL: filters and the bound become
pyiceberg row filters or pyarrow dataset expressions, so scans prune files and
partitions, and rows are then ordered by `observed_at` and cut to the per-sync
bound.

## Incremental reads and write mode

- An **incremental** mapping (`incremental: true`, the default) syncs in
  append mode: rows are upserted by `event_id` and history is kept. The
  connector's watermark is the newest `event_time` synced; the next sync reads
  rows with `observed_at >= watermark - lookback_minutes`. The bound is
  inclusive and ids are stable, so the overlap is re-read without duplicates.
- A **full re-read** mapping (`incremental: false`) syncs in snapshot mode: each
  sync replaces that connector's previous rows. All mappings on one connector
  must use the same mode.
- Each sync reads at most `options.max_rows_per_sync` rows per mapping (default
  50,000, oldest first). A large backfill therefore advances over several syncs.
- `iceberg-parquet-lake` reads only the last `options.initial_window_days` days
  (default 30) on the first incremental sync, instead of the full history. Set it
  to `0` to read everything.
- All mappings on a connector share one watermark. Rows that arrive later than
  `lookback_minutes` behind the newest synced row, in any mapped table, are
  skipped. Raise `lookback_minutes` for sources with long delivery lag.
- A mapping whose every fetched row fails to map fails the sync (the spec almost
  certainly does not match the table). Otherwise unmappable rows are skipped and
  logged with their count. `lake map --dry-run` lists each one.

## OCSF presets

Presets are complete specs you reference as
`{"preset": "<name>", "source": {"table": "<table>"}}`. Any other keys you add
are merged on top (lists such as `filters` are replaced). All presets filter on
`class_uid`, so one table holding several OCSF classes splits cleanly. They use a
60-minute lookback.

| Preset                       | OCSF class                      | OCSF version | Watermark         | Status                                              | Control hints                                                                     |
| ---------------------------- | ------------------------------- | ------------ | ----------------- | --------------------------------------------------- | --------------------------------------------------------------------------------- |
| `ocsf/authentication`        | Authentication (3002)           | 1.1.0        | `time_dt`         | `observed` (outcome kept in `attributes.outcome`)   | SOC2-CC6.1, ISO27001-A.8.5, ISO27001-A.8.15, NIST-800-53-IA-2, NIST-800-53-AU-2   |
| `ocsf/account_change`        | Account Change (3001)           | 1.1.0        | `time_dt`         | `observed`                                          | SOC2-CC6.2, SOC2-CC6.3, ISO27001-A.5.16, ISO27001-A.5.18, NIST-800-53-AC-2        |
| `ocsf/api_activity`          | API Activity (6003)             | 1.1.0        | `time_dt`         | `observed`                                          | SOC2-CC7.2, ISO27001-A.8.15, ISO27001-A.8.16, NIST-800-53-AU-2, NIST-800-53-AU-12 |
| `ocsf/detection_finding`     | Detection Finding (2004)        | 1.1.0        | `time_dt`         | `status_id` New/In Progress → open, Resolved → pass | SOC2-CC7.2, SOC2-CC7.3, ISO27001-A.8.16, NIST-800-53-SI-4                         |
| `ocsf/vulnerability_finding` | Vulnerability Finding (2002)    | 1.1.0        | `time_dt`         | `status_id` as above                                | SOC2-CC7.1, ISO27001-A.8.8, NIST-800-53-RA-5, NIST-800-53-SI-2                    |
| `ocsf/compliance_finding`    | Compliance Finding (2003)       | 1.1.0        | `time_dt`         | `compliance.status_id` Pass → pass, Fail → open     | SOC2-CC7.1, ISO27001-A.8.9, NIST-800-53-CM-6, NIST-800-53-CA-7                    |
| `ocsf/security_finding`      | Security Finding (2001, legacy) | 1.0.0-rc.2   | `time` (epoch ms) | `state_id` New/In Progress → open, Resolved → pass  | SOC2-CC7.2, ISO27001-A.8.16, NIST-800-53-SI-4                                     |

Severity comes from OCSF `severity_id` (1 Informational → info, 2 → low,
3 → medium, 4 → high, 5 Critical and 6 Fatal → critical; 0 and 99 → info). Sign-in,
account-change, and API events are activity evidence, so they are `observed`
rather than control failures; a failed sign-in is not a failed control. Control
hints are ids from `controls/catalog.json`. Security Hub `compliance.control`
values (for example `IAM.6`) are kept in `attributes`, not treated as TrustOps
controls.

Amazon Security Lake source version 2 writes OCSF 1.1.0 and source version 1
writes OCSF 1.0.0-rc.2
([AWS: OCSF in Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)).
The 1.1.0 presets use 1.1.0 paths such as `cloud.account.uid` and
`finding_info.uid`. For OCSF 1.0.0-rc.2 tables other than Security Hub findings,
override the paths that changed: `cloud.account_uid`, API Activity `class_uid`
3005 instead of 6003, and `time`/`epoch_ms` if `time_dt` is absent. For example:

```json
{
  "preset": "ocsf/api_activity",
  "source": { "table": "ocsf.cloudtrail_v1" },
  "filters": [{ "column": "class_uid", "op": "eq", "value": 3005 }],
  "fields": { "observed_at": { "column": "time", "format": "epoch_ms" } },
  "attributes": { "cloud_account": { "column": "cloud.account_uid" } }
}
```

Class and attribute names follow the OCSF schema browser for
[1.1.0](https://schema.ocsf.io/1.1.0/) and
[1.0.0-rc.2](https://schema.ocsf.io/1.0.0-rc.2/).

## Per-backend setup (least privilege)

Every reader only issues reads. Nothing is created, altered, or deleted in the
customer lake. Credentials are references (environment variable names or the
runtime's cloud identity) and are never stored.

### Snowflake

Grant a dedicated role `USAGE` on the warehouse, database, and schema, and
`SELECT` on each mapped table or view. Nothing else is needed; the TrustOps views
are not required in mapping mode. Authentication is unchanged: key-pair or OAuth
service user, see [CONNECTORS.md](CONNECTORS.md#connector-runner) and
[LIVE_CLOUD_POC.md](LIVE_CLOUD_POC.md).

### Databricks

`CAN USE` on one SQL warehouse, plus `USE CATALOG`, `USE SCHEMA`, and `SELECT` on
each mapped table. The service principal, OAuth M2M flow, and required
connection fields (`host`, `warehouse_id`, `catalog`, `schema`, `client_id`,
`client_secret_ref`) are the same as for the views
([CONNECTORS.md](CONNECTORS.md#databricks-evidence-lake-preview)).

### ClickHouse

A user with `SELECT` on each mapped table. Every query is sent with `readonly=1`,
and the host must resolve to a public address.

### Iceberg with AWS Glue, including Amazon Security Lake (`iceberg-parquet-lake`, preview)

Credentials: `catalog_type: "glue"`, `region`, and optionally `role_arn`,
`external_id`, and `catalog_id` (the 12-digit account that owns the catalog).
Without `role_arn`, the runtime's AWS identity is used through the standard
provider chain.

The role needs `glue:GetDatabase` and `glue:GetTable` on the lake database and
tables, `s3:GetObject` and `s3:ListBucket` on the table data and metadata
prefixes, and `kms:Decrypt` when the data uses a customer-managed key. If Lake
Formation governs the database, grant the role `DESCRIBE` and `SELECT` there as
well. For Amazon Security Lake, a subscriber with **data access** fits.

pyiceberg reads Iceberg metadata and data files straight from S3; it does not
use Lake Formation credential vending. This has not been verified against a
Lake Formation-governed Security Lake account.

Without a mapping, a Glue catalog defaults to the Security Lake source version 2
tables for the region, `amazon_security_lake_glue_db_<region>.amazon_security_lake_table_<region>_<source>_2_0`:

- `cloud_trail_mgmt` → `ocsf/authentication`, `ocsf/account_change`, `ocsf/api_activity`
- `sh_findings` → `ocsf/detection_finding`, `ocsf/vulnerability_finding`, `ocsf/compliance_finding`

`options.security_lake_sources` narrows the set (a list, or a comma-separated
string from the console). Security Lake source version 1 tables are Hive-style
Parquet rather than Iceberg; read them with `catalog_type: "parquet"` and the
`ocsf/security_finding` preset.

Glue and S3 calls go to the AWS regional endpoints; no endpoint override is
accepted, and the reader ignores storage settings (endpoint, proxy, signer,
FileIO class) carried in table metadata. Every metadata, manifest, and data
location must be an `s3://` (or `s3a://`, `s3n://`) URI: a table whose metadata
points at `file:`, a bare path, or an HTTP URL is refused. In hosted server mode
`role_arn` and `external_id` are required (see
[Hosted connector credentials](SERVER_AUTH.md#hosted-connector-credentials)).

### Iceberg REST catalog

Credentials: `catalog_type: "rest"`, `uri` (HTTPS, resolving to a public
address), `warehouse`, and `credential_ref`, the name of an environment variable
holding a short-lived bearer token (default `TRUSTOPS_ICEBERG_TOKEN`). The client
is the hardened one used by [Iceberg publication](ICEBERG_REST.md): no redirects,
no endpoint relocation, no refresh credentials. The token needs read access
(load table and scan) to the mapped namespaces only. From the catalog's config
and table responses the reader keeps only vended storage credentials, their
expiry, and the region (`s3.access-key-id`, `s3.secret-access-key`,
`s3.session-token`, `s3.region`, their `client.*` forms, and
`gcs.oauth2.token`/`gcs.oauth2.token-expires-at`); endpoint, proxy, signer,
role, retry, and FileIO settings are dropped. Storage locations must be `s3://`,
or `gs://` when `warehouse` itself is a `gs://` location; `file:`, bare paths,
and HTTP are refused. The catalog must still scope vended credentials to read.
In hosted server mode `credential_ref` is required and must pass the
[secret-reference policy](SERVER_AUTH.md#hosted-connector-credentials).

### Parquet on S3 or local disk

Credentials: `catalog_type: "parquet"`, `path` (`s3://bucket/prefix`) or
`options.parquet_paths` (`{"<table>": "s3://..."}` for several tables), and
optionally `region`, `role_arn`, and `external_id`. The role needs `s3:ListBucket`
on the prefix and `s3:GetObject` on its objects. Hive-style partition
directories (`region=us-east-1/...`) become filterable columns.

Local paths are refused unless `TRUSTOPS_LAKE_LOCAL_ROOT` names the directory
they may read, and resolved paths cannot escape it. In hosted server mode each
tenant may read only `$TRUSTOPS_LAKE_LOCAL_ROOT/<tenant_id>`, and S3 paths need
`role_arn` plus `external_id`. Anything other than `s3://` or an absolute local
path is rejected.

### BigQuery (`bigquery-evidence-lake`, preview)

Install the `bigquery` extra (`pip install 'trustops-security-data-lake[bigquery]'`).
Credentials: `project_id` (the project that runs the queries), and optionally
`dataset` (qualifies one-part table names) and `location`. Authentication is
Application Default Credentials: workload identity, an attached service
account, or `gcloud auth application-default login` for a trial. No key file is
configured in TrustOps. Set `impersonate_service_account` to have that identity
impersonate a service account in your project; hosted server mode requires it,
and there a fully qualified table in another project than `project_id` needs
`options.allow_cross_project: true`.

Grant `roles/bigquery.jobUser` on the query project and
`roles/bigquery.dataViewer` on the source dataset or tables. Views also need
read access to their underlying tables unless they are authorized views. Each
query sets `maximum_bytes_billed` (`options.maximum_bytes_billed`, default
10 GiB), so a scan above the cap fails instead of running.

## Limits and follow-ups

- Mapping mode is not yet verified against live Snowflake, Databricks, or
  ClickHouse accounts, and the two new readers are preview until they are
  verified against live Glue/Security Lake, REST, S3, and BigQuery sources.
- One watermark per connector (see [Incremental reads](#incremental-reads-and-write-mode)).
- The Iceberg, Parquet, and BigQuery probes validate configuration only. The
  Snowflake and ClickHouse probes read one row per mapped table.
- There is no console editor for custom mapping JSON yet. Use `lake map --dry-run`
  and the API/CLI `options`.
