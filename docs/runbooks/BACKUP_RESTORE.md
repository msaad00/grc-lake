# Backup and restore

Back up the **whole lake root** and the application-state database together.
The lake includes bronze/silver/gold, published generations and their `current`
pointer, snapshots, integrity/review ledgers and operational history. Copying
only selected JSONL files can lose the generation or audit chain they reference.
SQLite defaults to `server/app.db` inside the lake. When `GRC_LAKE_DATABASE_URL`
selects PostgreSQL, that database requires a separate backup.

Keep runtime signing keys, OIDC settings, connector secrets and encryption keys
in an independently backed-up secret manager. Record the deployed image digest,
chart revision, Helm values and database revision with each backup. API-key
plaintext cannot be recovered from its stored hash.

## Quiesce Kubernetes writers

Local mode supports one writable application replica and one scheduler owner.
For PostgreSQL/S3 deployments, also follow the coordinated catalog/object recovery
requirements in [distributed mode](../DISTRIBUTED.md).
Pause external CLI/automation writers too. First prevent new scheduled jobs:

```bash
NS=grc-lake
RELEASE=grc-lake
kubectl -n "$NS" patch cronjob/"$RELEASE"-scheduler --type=merge \
  -p '{"spec":{"suspend":true}}'
kubectl -n "$NS" get jobs
```

If the scheduler is disabled, skip the CronJob command. Suspending a CronJob
**does not stop an already-running Job**. Identify its active Jobs by their
CronJob owner reference and wait for them to complete before proceeding. Do not
ignore failures or assume an empty label selector proves that no jobs are active.

Then stop the API and verify that its pod has terminated and no other process
is writing this lake:

```bash
kubectl -n "$NS" scale deployment/"$RELEASE" --replicas=0
kubectl -n "$NS" get pods,jobs
```

Keep the writers stopped until both lake and database backups finish. A live
PostgreSQL dump can be internally consistent yet still disagree with a lake
snapshot taken at a different point in the workflow.

## Capture storage

For Kubernetes, use your CSI driver's VolumeSnapshot procedure and wait for
`readyToUse` before considering the snapshot complete. The chart's default PVC
is `grc-lake-lake`; resolve the actual claim from the Deployment volume when
using a different release name or name overrides:

```bash
kubectl -n "$NS" get deployment "$RELEASE" \
  -o jsonpath='{.spec.template.spec.volumes[?(@.name=="lake")].persistentVolumeClaim.claimName}'
```

Snapshot classes, retention and encryption are cluster-specific prerequisites;
the application chart does not provision them. Follow the
[Kubernetes volume snapshot procedure](https://kubernetes.io/docs/concepts/storage/volume-snapshots/)
and the cloud provider's restore instructions. A temporary pod's `emptyDir` is
not a durable backup destination, and deleting that pod deletes the output.

For local files, after stopping all writers:

```bash
LAKE="${GRC_LAKE_LAKE:-build/lakehouse}"
BACKUP="$PWD/grc-lake-lake-$(date +%F).tar.gz"
tar czf "$BACKUP" -C "$LAKE" .
tar tzf "$BACKUP" >/dev/null
```

For Compose, stop `grc-lake-server` first and identify its actual mounted volume
with `docker inspect`; Compose may prefix the logical volume name with its
project name. Archive that volume to durable external storage. A bind-mount
installation can use the local command above. Do not use `docker compose down
-v`, which removes named volumes.

When using PostgreSQL, capture `pg_dump` or a managed database snapshot at the
same quiesced boundary. Store backups encrypted outside the source lake and
apply an explicit retention policy. Test recovery, not just archive creation.

## Restore into an isolated target

Keep production writers stopped. Restore a CSI snapshot into a replacement PVC
or staging namespace according to your driver; do not overwrite the only copy
of the current volume. Preserve permissions needed by the container's UID/GID 1100. Mount the restored PVC at `/lake` with the same application image and
Secret references used by the recorded deployment.

For a local drill, extract into a new empty directory rather than merging into
an existing lake:

```bash
RESTORED_LAKE=$(mktemp -d)
tar xzf "$BACKUP" -C "$RESTORED_LAKE"
grc-lake db upgrade --lake "$RESTORED_LAKE"
grc-lake db current --lake "$RESTORED_LAKE"
```

For PostgreSQL, restore the matching database to a separate target and set the
restored application's `GRC_LAKE_DATABASE_URL` accordingly. SQLite comes with
the full lake backup. Run migrations with the intended release version and
keep the pre-migration backup. In Kubernetes the normal application startup
runs migrations on its mounted lake/database; a standalone migration pod must
mount that same restored PVC and receive the same database Secret references.
An unmounted `kubectl run` pod does not migrate the restored application state.

## Verify, then resume

Start one application replica while the scheduler remains suspended:

```bash
kubectl -n "$NS" scale deployment/"$RELEASE" --replicas=1
kubectl -n "$NS" rollout status deployment/"$RELEASE"
curl -fsS "$GRC_LAKE_URL/api/healthz"
curl -fsS "$GRC_LAKE_URL/api/readyz"
curl -fsS -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  "$GRC_LAKE_URL/api/v1/snapshots/integrity"
curl -fsS -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  "$GRC_LAKE_URL/api/v1/tracking/integrity"
```

Check human login, tenant scope, retained snapshot/workpaper retrieval, posture,
connector history and review-ledger integrity. Only after those checks pass,
resume the scheduler if it was previously enabled:

```bash
kubectl -n "$NS" patch cronjob/"$RELEASE"-scheduler --type=merge \
  -p '{"spec":{"suspend":false}}'
```

Verify a scheduled run completes, then re-enable other writers and traffic.
Record the recovery point and time actually observed in a staging restore
drill. Configuration checks do not establish an RPO, RTO or production backup.

See [deployment topology](HA_READ_REPLICAS.md),
[shareable hosting](../SHAREABLE_POC_HOSTING.md), and
[release readiness](../RELEASE_READINESS.md).
