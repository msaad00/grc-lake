# Deployment topology and high-availability boundary

The supported Helm topology is **one application replica with a writable lake**.
Startup writes the console and runs operational database migrations; requests
can append audit records. Setting `lake.readOnly: true` does not produce a
working read-only service. The chart rejects it, and rejects every replica count
other than one regardless of PVC access mode. A ReadWriteMany volume does not
provide distributed writer fencing.

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
unavailable rather than silently substituting current results. Back up the lake,
review ledger, and operational database together and test restore before use.

## Work required before read replicas

- Separate immutable assessment reads from startup, migration, and audit writes.
- Route audit and workflow writes through a supported shared store.
- Add durable writer leases with fencing and single-owner scheduling.
- Qualify cross-host publication, failover, retries, and recovery under load.
- Measure availability and latency with concurrent tenants and realistic evidence.

Read replicas, automated failover, and horizontal evaluation are design work,
not supported deployment modes. See [architecture](../ARCHITECTURE.md) and
[benchmark boundaries](../BENCHMARKS.md).
