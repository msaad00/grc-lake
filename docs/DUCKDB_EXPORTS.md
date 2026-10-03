# DuckDB projection recovery

The optional DuckDB sink is a current projection of one operator-owned lake.
It replaces normalized events, control posture, asset risk, and their views in a
single transaction. Removed rows disappear after a successful refresh; readers
on another connection keep seeing the prior committed projection until commit.
A parse, constraint, or write failure rolls back the entire refresh. Retry the
latest assessment to recover. This does not provide an automatic retry queue or
coordinate transactions with Snowflake or ClickHouse.

Every source artifact must exist, including an explicitly empty file when there
are no rows. Missing artifacts fail instead of clearing previously valid data.
Generation reads are pinned for the full export. Gold rows inherit platform
ownership from the assessment manifest when available; observation tenant IDs
continue to identify source accounts.

The destination stores a hash of the canonical source lake path. Different
assessment generations from that lake share the same owner. Another lake cannot
overwrite it, even when event and control IDs coincide. Moving the source lake
requires a new destination. This is ownership protection against accidental
cross-lake reuse, not a database authorization boundary against an administrator.

Existing destinations without ownership metadata are rejected without changing
their tables. For upgrade, keep the old database, configure a new
`TRUSTOPS_DUCKDB_PATH`, export the current assessment, verify row counts and gold
views, then switch consumers. No destructive schema migration runs automatically.
An injected DuckDB connection must be idle; nested transactions are unsupported
and DuckDB requires the caller to roll back after a nested-BEGIN error.

These guarantees apply to DuckDB. Remote warehouse exports retain their individual
backend contracts and require separate qualification. Hosted tenant requests
cannot use process-wide warehouse destinations.
