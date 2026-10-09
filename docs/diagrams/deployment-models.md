# Deployment models

GRC Lake is self-hosted software. Local and distributed modes use the same
assessment engine; operators own credentials, storage, backups, and availability.

```mermaid
flowchart TB
  subgraph Local["Local mode · one writable replica"]
    App["Console, API and worker"]
    Lake["Local lake / persistent volume"]
    DB["SQLite or PostgreSQL · operational records"]
    App --> Lake
    App --> DB
  end
  subgraph Distributed["Distributed mode · multiple replicas and tenant workers"]
    API["API replicas · private scratch"]
    Workers["Workers · private scratch"]
    PG["PostgreSQL primary · jobs, fences, committed manifests"]
    S3["S3-compatible storage · evidence objects"]
    API --> PG
    Workers --> PG
    API --> S3
    Workers --> S3
  end
  Sources["Read-only evidence sources"] --> App
  Sources --> Workers
  Lake --> Exports["Optional warehouse exports"]
  Workers --> Exports
```

The loopback demo uses synthetic fixtures and disables authentication. Production
installations require authentication and explicit tenant routing. Distributed
mode must be configured explicitly; adding replicas to a local deployment does
not make its publication safe. One tenant evaluation runs on one worker.

PostgreSQL failover and object-store replication belong to the operator's
infrastructure. Synthetic CI qualification does not establish production
capacity or provider availability.

See [deployment](../DEPLOYMENT.md), [distributed mode](../DISTRIBUTED.md), and
[architecture](../ARCHITECTURE.md).
