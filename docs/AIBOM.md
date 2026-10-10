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

Exports are inventory projections. Component content is derived only from the
stored inventory; each export gets a fresh document identifier and creation time.

- `cyclonedx-1.7` — `serialNumber` (`urn:uuid`), `metadata.timestamp` and
  `metadata.tools`, components, model cards (including `modelParameters` when
  the source supplied them, up to 64 KiB per model), package URLs, and licenses
- `spdx-3.0.1` — JSON-LD `@graph` with one `CreationInfo`, an `SpdxDocument`,
  `ai_AIPackage` for models, `dataset_DatasetPackage` for datasets (dataset type
  `noAssertion`), `software_Package` for applications and libraries, and declared
  licenses as `simplelicensing_LicenseExpression` elements linked by
  `hasDeclaredLicense` relationships

Inventory identifiers that are not `urn:` or `http(s)` IRIs become
document-scoped `urn:grc-lake:aibom:` identifiers in SPDX output. Both exports
validate against the official CycloneDX 1.7 and SPDX 3.0.1 JSON schemas; the
SPDX export does not carry model hyperparameters or training details.

Input is limited to 10 MiB. Unknown formats and documents without supported AI
model, dataset, application, or library components fail closed. GRC Lake stores
the source SHA-256 for provenance but does not upload the source document.

CycloneDX and SPDX remain the authorities for full schema/profile conformance:

- <https://cyclonedx.org/docs/1.7/json/>
- <https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/>
