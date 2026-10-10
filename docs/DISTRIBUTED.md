# Distributed PostgreSQL and S3 mode

GRC Lake can run multiple API replicas and workers with independent local disks.
PostgreSQL coordinates ownership, application records, job claims and publication;
S3-compatible storage holds immutable evidence objects. This mode is part of OSS
and works for self-hosted or operator-hosted installations. Hosted billing and
signup features do not enable distribution by themselves.

## Deployment modes

| Mode                      | Durable state                        | Application topology                                            |
| ------------------------- | ------------------------------------ | --------------------------------------------------------------- |
| Local / small self-hosted | Local lake plus SQLite or PostgreSQL | One writable application replica; `Recreate` rollout            |
| Distributed API           | PostgreSQL primary endpoint plus S3  | Multiple API replicas with private scratch volumes              |
| Distributed worker        | Same PostgreSQL/S3 cluster           | Multiple worker processes, optionally assigned virtual shards   |
| Distributed reader        | Same PostgreSQL/S3 cluster           | Read traffic on a separate Service; tenant mutations return 405 |

A reader still writes authentication and request-audit records to PostgreSQL.
It is not a connection to a read-only PostgreSQL standby. Authentication callbacks
remain available. Local CLI commands do not implicitly publish to a distributed
cluster; use `cluster` commands or the authenticated API. MCP uses remote API mode.

## Shards, partitions and replicas

- **Virtual shards:** tenant IDs hash into 64 stable buckets by default, configurable
  from 1 to 4096 at cluster creation. PostgreSQL registers the shard count and object
  location; changing them on an existing cluster fails closed. Replica count does
  not change a tenant's shard or object keys. Shards route work, not PostgreSQL rows
  across multiple database servers. A tenant remains one consistency boundary.
- **PostgreSQL history partitions:** retained publication manifests use 32 physical
  hash partitions by tenant. A tenant/version lookup prunes to one partition.
  These database partitions are separate from the configurable virtual worker
  shards; they stay within one PostgreSQL cluster and do not add database servers.
- **Worker placement:** workers may claim all shards or an explicit comma-separated
  list using `cluster worker --shards 0,1,2`. Overlapping assignments are safe;
  database claims admit at most one running job per tenant. Claims use nonblocking
  per-tenant locks, so a busy tenant does not serialize unrelated workers. Reassign shard ranges
  by changing worker configuration. There is no automatic shard placement service.
- **Evidence partitions:** each published assessment also produces typed Parquet
  partitions by owning tenant, source and UTC event date. Original source-account
  IDs remain in the evidence rows. Paths encode the source with a digest; the
  manifest retains its original name, row count, size and SHA-256. Conversion uses
  bounded row batches. `cluster partitions` prunes source/date partitions before
  downloading objects. Existing JSONL and assessment APIs retain their contracts.
- **Application replicas:** API and worker pods may run on different machines and
  write different tenants concurrently. Same-tenant lake publication uses an
  expiring lease and a monotonically increasing fence; conflicting immediate
  mutations return 409. Workers wait up to 95 seconds for a busy tenant, covering the 90-second
  lease of a failed owner. A single tenant's
  evaluation is not split across workers.
- **Storage replicas:** PostgreSQL normally has one primary and operator-managed
  standbys; use its primary service endpoint. Object-store replication or erasure
  coding belongs to the S3 service. GRC Lake does not configure either system's
  failover, quorum or durability policy.
- **RAID:** configure it at the host/NAS/storage layer if appropriate. It neither
  coordinates application writers nor substitutes for backups.

## Publication and failure behavior

A worker restores the last committed tenant manifest into private scratch space.
It writes locally, uploads new content-addressed objects with conditional S3
writes, then atomically commits the new manifest pointer and domain SQL changes.
Unchanged verified objects reuse their existing references. Readers discover the
head through PostgreSQL, never an S3 listing or a pod-local pointer.

PostgreSQL checks lease expiry using its own clock. An expired or superseded fence
cannot publish. Upload failures and rejected HTTP mutations roll back domain SQL
and leave the old publication visible. Denied requests remain in the shared audit
sink. Scheduler attempt cadence is committed independently before execution, so
an abandoned publication does not erase an attempted workflow or connector run.
An interrupted job is not automatically replayed: external effects may already
have occurred. Review domain history before submitting a new idempotency key.

This is atomic publication of database state and object references, not a
transaction spanning external email, webhooks or warehouse providers. A network
failure after commit can make the response uncertain; retain the idempotency key
for supported asynchronous operations and inspect their status before retrying.

## Configure a cluster

Install `grc-lake[server,cloud,parquet]` or build the repository's Docker image.
Provision a dedicated PostgreSQL application database and an S3 bucket. One
database belongs to one cluster; sharing it between distinct cluster IDs is rejected. All replicas must share the same cluster
identity, database, bucket, endpoint, region, signing keys and connector secrets.
Credentials use the normal AWS SDK credential chain, including workload identity.

```bash
export GRC_LAKE_DEPLOYMENT_MODE=distributed
export GRC_LAKE_CLUSTER_ID=grc-primary
export GRC_LAKE_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@PRIMARY/grc_lake'
export GRC_LAKE_OBJECT_BUCKET=grc-lake-evidence
export GRC_LAKE_OBJECT_REGION=us-east-1
# For a self-hosted S3 service:
# export GRC_LAKE_OBJECT_ENDPOINT=https://objects.example.com
export GRC_LAKE_COOKIE_SIGNING_KEY='REPLACE_WITH_A_SHARED_RANDOM_SECRET'

grc-lake cluster init --lake /private/scratch
grc-lake serve --server --lake /private/scratch --host 0.0.0.0 --port 8787
# On worker nodes, with the same shared configuration:
grc-lake cluster worker --lake /private/scratch --concurrency 2 --shards all
```

`cluster init` migrates PostgreSQL and checks the bucket's conditional-write
behavior. Startup migrations are serialized by a PostgreSQL transaction lock.
The preflight needs Get/Put/Delete on `clusters/<id>/preflight/`; runtime data needs
Get/Put and multipart-upload permissions under `clusters/<id>/shard=*/`.
S3-compatible services must implement `If-None-Match: *` for PutObject and
CompleteMultipartUpload. Validate the specific provider before production use.
HTTPS is required for configured endpoints; only local testing should set
`GRC_LAKE_OBJECT_ALLOW_HTTP=1`.

Create users and tenant records using the existing authenticated onboarding or
`grc-lake db` commands. To migrate an existing tenant, first quiesce its old writer
and retain a backup of its application database and lake. The source must have a
verified sealed generation matching the existing target tenant ID:

```bash
grc-lake cluster import --lake /private/scratch --tenant-id TENANT_ID --source /old/tenant-lake
grc-lake cluster status --lake /private/scratch --tenant-id TENANT_ID
```

Import refuses a nonempty target publication and server/multi-tenant roots. It
preserves the source. Application identity records are not copied from SQLite by
this command; migrate those to PostgreSQL separately before switching traffic.

## Kubernetes profiles

The chart defaults to local mode. The distributed profiles require customer
Secrets: `grc-lake-database` containing `database-url`, and `grc-lake-signing`
containing `cookie-key`. Override the example cluster ID, bucket and endpoint.
Configure workload identity or supply S3 credential Secret references in `env`.

```bash
helm upgrade --install grc-api deploy/helm/grc-lake \
  -f deploy/examples/distributed/api-values.yaml
helm upgrade --install grc-workers deploy/helm/grc-lake \
  -f deploy/examples/distributed/api-values.yaml \
  -f deploy/examples/distributed/worker-values.yaml
helm upgrade --install grc-readers deploy/helm/grc-lake \
  -f deploy/examples/distributed/api-values.yaml \
  -f deploy/examples/distributed/reader-values.yaml
```

The profiles render two replicas, rolling updates, and bounded private `emptyDir`
volumes. No shared lake PVC is used. Worker deployments have no HTTP Service or
HTTP probes. Route browser/API mutations to the API Service; use the reader
Service for read traffic. Enable `scheduler.enabled` on one release; overlapping
scheduler pods are fenced per tenant. Deploy additional scheduler processes with
`grc-lake scheduler tick --all-tenants` when required. Tenant failures are isolated.
Readiness checks PostgreSQL, writable scratch and S3 bucket reachability. These
checks do not prove provider replication, multipart semantics or failover readiness.

## Query a partition subset

```bash
grc-lake cluster partitions --lake /private/scratch --tenant-id TENANT_ID \
  --source cloud-cspm --start-date 2026-05-01 --end-date 2026-05-31 \
  --out /exports/cspm-may
# For a local verified lake:
grc-lake pipeline export-parquet --lake /local/lake --tenant-id TENANT_ID \
  --partitioned --out /exports/all-evidence
```

Date bounds are inclusive UTC dates. Each downloaded file is checked against the
committed manifest; unavailable or corrupt objects fail closed. An empty match
produces a manifest with zero selected rows. Use the manifest's explicit file list
with an analytical engine; its source field is the original source name, whereas
the directory's `source_hash` component is a digest. Distinct column names prevent
Hive partition discovery from replacing the original evidence `source` values.

## Performance and capacity boundaries

The example resource requests are starting configurations, not certified capacity.
Measure cold reads, warm reads, concurrent writes, queue wait and failover against
your provider and tenant data before selecting production limits.

- Default runtime workspace limit: 20 GiB and 100,000 filesystem entries per tenant.
  The Helm profiles lower the byte limit to 512 MiB. Exceeding a limit fails before
  publication; it does not truncate evidence. Old retained generations count too.
- Each replica admits four workspace requests by default, configurable with
  `GRC_LAKE_WORKSPACE_CONCURRENCY` (1–64). Excess requests receive 503/Retry-After.
  Queue admission, polling and cancellation avoid downloading the tenant lake.
- Compatibility API reads materialize a tenant revision and make a private local
  copy. Each replica caches up to four tenant revisions with least-recently-used
  eviction; a new publication replaces only that tenant's cached revision.
  `GRC_LAKE_READ_CACHE_ENTRIES` sets the entry bound (1–64), and
  `GRC_LAKE_READ_CACHE_BYTES` sets the total cached payload-byte bound (defaults
  to `GRC_LAKE_WORKSPACE_BYTES` and cannot be smaller). Active readers retain
  private copies across eviction. This avoids repeated downloads when tenants
  alternate, but does not eliminate private-copy cost or reuse derived in-memory
  caches across requests. Cold reads and large tenants remain expensive.
  Partition downloads bypass full-lake hydration and prune objects by source/date.
- Evaluation still materializes rows in memory. More tenant shards increase
  concurrency across tenants; they do not make one evaluation distributed or
  bounded in memory. Worker concurrency is 1–16; isolated jobs have deadlines.
- Reserve scratch for the cache, active readers/writers, temporary Parquet export
  and free-space headroom. Keep the filesystem's capacity limit above that working
  set and monitor disk pressure. Node-local scratch is disposable.
- Request-rate limits are per replica unless the existing Redis limiter is
  configured. PostgreSQL/S3 alone do not turn them into cluster-wide quotas.
- Historical manifests and immutable objects are retained. Do not apply bucket
  lifecycle deletion to referenced objects. Automatic object garbage collection
  and automatic time-based partition rotation are not implemented.

## Recovery and validation

Back up PostgreSQL with PITR and retain the referenced object versions together.
Losing only local scratch is recoverable by rehydration. Losing the authoritative
catalog cannot be repaired by guessing object order. Test restore with the same
cluster identity, storage location and signing keys before switching traffic.
Never let two independent PostgreSQL primaries govern the same cluster after a
split-brain event. Operator-managed fencing and failover are required.

The regression suite covers independent API roots, concurrent publication,
expired fences, database connection loss, failed SQL/file mutations, shared audit,
shard-restricted jobs, scheduler-attempt durability, reader isolation, concurrent
startup migrations, partition pruning and spawned-worker publication. Real
PostgreSQL and an S3 HTTP emulator run in the PostgreSQL CI gate. Emulator success
is not qualification of AWS S3, MinIO, Ceph or another production provider.

For a bounded, reproducible local measurement (requires a disposable PostgreSQL
URL in `TEST_POSTGRES_URL` with permission to create test databases):

```bash
uv run --all-extras --with 'moto[server,s3]==5.2.3' \
  python tools/benchmark_distributed.py --tenants 4 --rows 1000 \
  --out /tmp/grc-distributed-benchmark.json
```

This creates and removes its own test database and S3 emulator. The report
separates publication, cold/warm materialization and selected partition download,
and records process peak RSS and workload bounds. It does not measure networked
storage replicas or database failover.

## Container deployment qualification

Build the application image, then run the disposable qualification stack:

```bash
docker build -t grc-lake:qualification .
python3 tools/qualify_distributed.py --image grc-lake:qualification \
  --out /tmp/grc-qualification
```

The output directory must be new. The driver requires Docker Compose and Python
on the host; application dependencies run inside the built image. PostgreSQL 16
and SeaweedFS 4.48 images are pinned by digest. This is a real S3 implementation,
not the Moto emulator used by the smaller protocol tests. All services use a
private Docker network without published host ports, synthetic identities and
fresh disposable volumes. The driver generates temporary credentials and removes
them during cleanup; do not supply production credentials or data.

The run verifies conditional-create races, conditional multipart writes, two
shard-assigned workers, concurrent tenant jobs submitted through two API replicas,
a separate reader, cross-tenant job isolation and verified partition downloads.
It deletes one API replica's scratch volume, restarts dependencies, and kills a
writer before publication. It checks that SQL rolls back, unpublished files stay
invisible, an unexpired lease rejects a competing writer, and a new owner can
publish after the normal 90-second lease expires. It then restarts a worker and
runs another batch. Successful reads must agree on evidence hashes.

The required Docker CI job runs this qualification against its built image and
retains a sanitized report. The report identifies the application image digest.
This single-host stack qualifies application processes and the tested S3 protocol
behavior. It does not certify PostgreSQL primary failover, replicated SeaweedFS
storage, network partitions between physical machines, backup restoration or
production capacity. Operators must exercise those properties in their target
infrastructure before rollout.

The driver removes only its uniquely named project and volumes, including after
an assertion fails. If the driver is forcibly killed, use its recorded project
marker for bounded cleanup:

```bash
python3 tools/qualify_distributed.py --cleanup --out /tmp/grc-qualification
```

## Scaling and upgrade operations

Workers select at most 64 eligible tenant candidates per claim, using a persisted
last-start time rather than aggregating all historical jobs. Claims, fairness,
heartbeat renewal and lease recovery use PostgreSQL time, avoiding host clock
skew. Conditional updates preserve concurrent cancellation, and a
per-tenant lock still prevents overlapping execution. Recovery inspects at most
128 stale claims per poll; subsequent polls continue through the backlog. Audit
reads and tenant queue lookups use compound indexes aligned with their filters.

Migration `0029_distributed_scaling` converts retained PostgreSQL publication
history into 32 tenant hash partitions and adds the dispatch/audit indexes. SQLite
keeps ordinary tables. The conversion preserves rows, table ownership and effective
table/column grants; replacement child tables receive no default public grants.
Downgrading copies retained history back into an ordinary table without discarding
rows. This is physical partitioning within one PostgreSQL cluster, not routing
across independent databases.

Schedule a maintenance window, quiesce writers, back up PostgreSQL, and reserve
space for a second copy of retained history before this migration. It holds an
exclusive history-table lock while copying. Nonstandard row-security policies,
triggers, indexes or foreign-key/unique constraints on that table or its partitions cause a
transactional refusal so they are not silently discarded; reconcile those custom
schema extensions with the partition layout before retrying. Application-role
grants should be verified after an operator-managed schema upgrade.
