# Adding a connector adapter (code registry)

Most connectors are **in-repo adapters** registered in
`connector_runner.REGISTRY` and `connectors/catalog.json` — that path is
below. A connector can also ship as a **separate installable package** that
registers itself at runtime via a Python entry point, without editing this
repo's source tree — see [Shipping a connector as a package](#shipping-a-connector-as-a-package)
further down.

## Quick start

```bash
security-lakehouse connectors scaffold my-vendor-evidence --title "My Vendor Evidence"
```

This writes starter files under `./connector-scaffold/` (module, test, and next
steps). Move them into the tree, implement the collector, then run:

```bash
security-lakehouse connectors validate
uv run pytest tests/test_my_vendor_evidence_connector.py
```

## Contributor checklist

1. **Collector** — `src/security_lakehouse/connectors_<slug>.py` with live +
   fixture clients and `collect_<slug>_evidence(...)`. HTTP requests go through
   `netguard.open_public`, `ingestion.backoff.http_retry`, and
   `ingestion.paginate.paginate`; OAuth client-credentials APIs use
   `ingestion.oauth.ClientCredentialsToken` (in-memory token, one re-mint on 401).
   Every control ID an event carries must exist in `controls/catalog.json`.
2. **Registry** — `_build_<slug>` builder + one line in `REGISTRY`.
3. **Catalog** — row in `connectors/catalog.json` with `is_implemented: true`, and
   `"release_stage": "preview"` until the connector has run against a live tenant.
4. **Tests** — fixture-backed sync under `tests/test_<slug>_connector.py`.
5. **Docs** — permissions and setup in `docs/CONNECTORS.md`.

## Event-log vs snapshot

| `data_shape` in catalog | Write mode | Watermark |
| ----------------------- | ---------- | --------- |
| `event_log`             | append     | yes       |
| `current_state`         | snapshot   | no        |

Append connectors receive `SyncInputs.since` from `gold/watermarks.jsonl`.

## Workflow automation

Registered connectors can be synced from workflows via `action.connector_sync`
(see `security_lakehouse/workflows.py` action catalog).

## Shipping a connector as a package

The registration mechanism the in-repo registry uses is also open to
third-party packages, so a connector does not have to live in this repo's
source tree. On first access, `connector_runner.effective_registry()` scans
installed packages for connectors registered under the `trustops.connectors`
[entry-point group](https://packaging.python.org/en/latest/specifications/entry-points/)
and merges them with the in-repo `REGISTRY`.

An entry point's name is the `connector_id`; it must resolve to a callable
implementing the same `ConnectorBuilder` contract an in-repo adapter uses —
`Callable[[SyncInputs], list[dict[str, Any]]]`. A minimal package looks like:

```
my-trustops-connector/
├── pyproject.toml
└── my_trustops_connector.py
```

```python
# my_trustops_connector.py
from security_lakehouse.connector_runner import SyncInputs


def build(inputs: SyncInputs) -> list[dict]:
    # Branch on inputs.fixture_dir for a fixture client, inputs.env /
    # inputs.credentials for a live one — exactly like an in-repo adapter.
    ...
    return rows  # raw evidence rows; see validate_raw_events for the schema
```

```toml
# pyproject.toml
[project]
name = "my-trustops-connector"
version = "0.1.0"
dependencies = ["trustops-security-data-lake"]

[project.entry-points."trustops.connectors"]
my-vendor-evidence = "my_trustops_connector:build"
```

Once the package is installed (`pip install my-trustops-connector`), its
`my-vendor-evidence` builder is dispatched through the same sync path as any
in-repo connector.

**Collision resolution.** An in-repo adapter always wins on a `connector_id`
collision — an installed package can never override or shadow a built-in
connector. A colliding entry point is logged as a warning and dropped, never
raised and never silently applied.

**Failure isolation.** An entry point that fails to import, or that does not
resolve to a callable, is logged and excluded. A bug in one third-party
package never breaks the rest of the registry or the app.

### Catalog metadata

A builder alone wires sync _dispatch_. To make the connector configurable,
enable-able, and visible in the console and `/api/v1/connectors`, the package
also registers its catalog row under `trustops.connector_catalog`, using the
same entry-point name:

```python
# my_trustops_connector.py
CATALOG_ENTRY = {
    "connector_id": "my-vendor-evidence",
    "name": "My Vendor Evidence",
    "category": "evidence",
    "collection_mode": "direct_api_read",
    "access_boundary": "scoped_token",
    "credential_type": "my_vendor_api_token",
    "minimum_permissions": ["evidence.read"],
    "evidence_types": ["policy"],
    "default_route": "local",
    "freshness_slo_minutes": 1440,
    "production_status": "supported_connector",
    "data_shape": "current_state",
}
```

```toml
[project.entry-points."trustops.connector_catalog"]
my-vendor-evidence = "my_trustops_connector:CATALOG_ENTRY"
```

The value may be the row itself or a zero-argument callable returning it.
`load_connector_catalog()` merges the row after the in-repo catalog only if:

- it passes the same validation as an in-repo row (`validate_connector_row`:
  required fields, collection mode ↔ access boundary pairing, no over-broad
  permissions, no secret-like fields or values);
- its `connector_id` matches the entry-point name and does not collide with a
  built-in connector;
- a callable builder with the same name is registered under
  `trustops.connectors` — the catalog never lists a connector that cannot sync;
- it does not claim `production_status: primary_lake`.

A rejected row is logged and excluded, never raised. Admitted rows get
`is_implemented: true` and a `provenance` field naming the entry point; the
console marks them **Installed package**. Credential fields in the console come
from the generic `credential_type` fallback (a `*token*` type asks for a
`credential_ref`), and there are no connector-specific scope fields.
`make validate` checks the in-repo catalog file only.

## Related docs

- [INGESTION_CONNECTORS_IDEMPOTENCY.md](INGESTION_CONNECTORS_IDEMPOTENCY.md)
- [CONNECTORS.md](CONNECTORS.md)
