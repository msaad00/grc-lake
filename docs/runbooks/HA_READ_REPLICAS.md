# Deployment topology and high-availability boundary

The default local-mode Helm topology is **one application replica with a writable lake**.
Startup writes the console and runs operational database migrations; requests
can append audit records. Setting `lake.readOnly: true` does not produce a
working read-only service. The chart rejects it, and rejects every replica count
other than one regardless of PVC access mode. A ReadWriteMany volume does not
provide distributed writer fencing.

The chart uses `Recreate` so a Deployment update terminates old pods before
starting replacements. Updates therefore have downtime. This prevents the default
rolling-update surge from overlapping application writers; it does not fence a
partitioned node or guarantee exclusive execution after manual pod deletion.
See the [Kubernetes deployment strategy documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#recreate-deployment).

```yaml
replicaCount: 1
lake:
  readOnly: false
```

Run one scheduler owner per lake. Local file locks serialize writers on the same
host; they are not a cross-host coordination protocol. PostgreSQL can hold
operational state, but it does not move the JSONL assessment pipeline into the
database or make multiple application replicas safe.

## Publication and recovery

Evaluation builds a private generation, hashes its artifacts, then atomically
switches the `current` pointer. Readers pin one generation per request. Retained
generations support historical exports; deleting one makes dependent exports
unavailable rather than silently substituting current results. Tests kill a
publisher process before the pointer switch, verify the previous generation
remains readable, and verify a replacement writer can acquire the lock and
publish. This is local crash recovery evidence, not cross-host failover.

Back up the lake,
review ledger, and operational database together and test restore before use.

## Distributed replicas

Opt-in [distributed PostgreSQL/S3 mode](../DISTRIBUTED.md) provides multiple API,
worker and reader replicas, stable tenant shards, partitioned Parquet, shared
request audit and fenced publication. Each replica has private scratch storage.
The chart permits rolling updates and multiple replicas only in that mode.

A distributed reader still needs the PostgreSQL primary for authentication and
request audit. It rejects tenant mutations and uses committed object manifests;
it is not a read-only mount of another pod's local lake. The runbook describes
resource bounds, migration, backup, failover responsibilities and limitations.
