# AI bill of materials

GRC Lake imports machine-readable AI inventory into the customer-controlled
lake and exports it without a hosted service.

```bash
grc-lake aibom import \
  --input model-bom.json \
  --lake build/lakehouse

grc-lake aibom export \
  --lake build/lakehouse \
  --format cyclonedx-1.7 \
  --out build/model-bom.cdx.json
```

The first command accepts CycloneDX 1.5–1.7 JSON or SPDX 3 JSON-LD and writes a
bounded canonical inventory to `aibom/inventory.json` under the lake. AI
governance inventory, API, CLI, and MCP reads then include those items.

Exports are deterministic inventory projections:

- `cyclonedx-1.7` — components, model-card presence, package URLs, and licenses
- `spdx-3.0.1` — AI/dataset package identity and descriptive metadata

Input is limited to 10 MiB. Unknown formats and documents without supported AI
model, dataset, application, or library components fail closed. GRC Lake stores
the source SHA-256 for provenance but does not upload the source document.

CycloneDX and SPDX remain the authorities for full schema/profile conformance:

- <https://cyclonedx.org/docs/1.7/json/>
- <https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/>
