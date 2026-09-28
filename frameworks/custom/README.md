# Custom frameworks

Drop customer-specific or internal frameworks here, then merge into your
deployment catalog or point `TRUSTOPS_DATA_DIR` at a directory that includes
them.

## Files

| File                    | Purpose                                                  |
| ----------------------- | -------------------------------------------------------- |
| `example.registry.json` | Framework metadata (source URL, version, guardrails)     |
| `example.controls.json` | Control definitions with provenance and evaluation rules |

See [Framework Packs](../../docs/FRAMEWORK_PACKS.md) for the full workflow and
`security-lakehouse frameworks sync-packs` for built-in SOC 2, NIST AI RMF,
FedRAMP, CIS AWS, and ISO full packs.

## Merge custom controls

1. Append framework rows to `frameworks/registry.json` (or load from this directory in your fork).
2. Append controls to `controls/catalog.json` — every control needs provenance fields.
3. Add reviewed mappings to `mappings/control_articles.json`.
4. Run:

```bash
security-lakehouse controls provenance
security-lakehouse catalog verify
make smoke
```

Custom frameworks use `implementation_status: "custom"` in the registry.
