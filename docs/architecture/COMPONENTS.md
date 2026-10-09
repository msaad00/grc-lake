# Components

## Connectors

Connectors adapt external systems into evidence records. Examples:

- cloud posture export
- vulnerability scanner export
- identity provider access review
- SIEM detection alert
- runtime policy violation
- ticketing/remediation state
- AI/model registry metadata

Connectors should be replaceable and independently testable.

## Evidence Model

The evidence model provides:

- stable `evidence_id`
- source and event type
- asset reference
- collection time
- evidence URI
- raw SHA-256 hash
- freshness metadata

## Control Catalog

The control catalog provides:

- framework
- control identifier
- title
- risk domain
- owner
- evidence requirement
- evaluation frequency

## Evaluation Engine

The evaluation engine consumes evidence and controls. It emits:

- framework score
- control status
- stale evidence
- missing evidence
- violation records
- current posture

## Snapshot Service

The snapshot service freezes current posture into an immutable export with an
assessment hash. Snapshots are for audits, vendor reviews, incidents, releases,
and board reporting.

## Lake Adapters

Storage is an adapter boundary:

- local evidence files with SQLite or PostgreSQL for one writable replica
- PostgreSQL coordination and S3-compatible evidence objects for distributed mode
- Snowflake for governed evidence
- ClickHouse for telemetry analytics

No product logic should depend on one warehouse.
