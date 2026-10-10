# Upgrade from TrustOps to GRC Lake

GRC Lake is the new product name for the same open-source, self-hosted evidence
platform. The repository, console, CLI, Python distribution, MCP server, chart,
images, and documentation use `grc-lake`. This change does not add a hosted
service or change the evidence boundary.

[GRC Lake 0.3.0](https://github.com/msaad00/grc-lake/releases/tag/v0.3.0)
is the first release published as `grc-lake` on PyPI and
`ghcr.io/msaad00/grc-lake` for containers. Existing TrustOps releases retain
their old package and image names; historical versions are not republished
under the new registry name. A later branch merge does not publish a release.

## Compatibility

| Surface           | GRC Lake name                                                    | Existing integrations                                                                             |
| ----------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| CLI               | `grc-lake`                                                       | `security-lakehouse` remains an alias                                                             |
| MCP command       | `grc-lake-mcp`                                                   | `trustops-mcp` remains an alias                                                                   |
| Python SDK        | `grc_lake.sdk.GrcLakeClient`                                     | `security_lakehouse.sdk.TrustOpsClient` remains an alias                                          |
| Environment       | `GRC_LAKE_*`                                                     | `TRUSTOPS_*` remains accepted by the Python runtime                                               |
| Mark URL          | `/brand/grc-lake-mark.svg`                                       | `/brand/trustops-mark.svg` still serves the current mark                                          |
| Connector plugins | `grc_lake.connectors`, `grc_lake.connector_catalog` entry points | `trustops.connectors`, `trustops.connector_catalog` still load; `grc_lake.*` wins on a name clash |

When both environment names exist, `GRC_LAKE_*` wins, including an explicitly
empty value. Existing secret values and tenant suffixes remain valid. Rename
variables without rotating or printing their values. Helper scripts and new
infrastructure examples document the new names; update their invocation too.

The internal `security_lakehouse` package, evidence schemas, canonical hashes,
token formats, cryptographic salts, session cookie names, and browser preference
keys remain compatible. Historical release notes retain their original names.
No lake rewrite or database migration is required just for branding.

## Preserve deployment identity and data

Back up the lake and operational database together before an upgrade. Stop the
old application writer before starting the replacement against the same lake.

- **Python:** install the new distribution into a fresh environment, then point
  it at the existing lake and configuration. Avoid installing both distributions
  into one environment: they own the same `security_lakehouse` files.
- **Docker Compose:** services are now `grc-lake` and `grc-lake-server`. The default
  volume names preserve the old `trustops_trustops-demo-lake` and
  `trustops_trustops-lake` volumes. For a custom previous Compose project, set
  `GRC_LAKE_DEMO_VOLUME` and `GRC_LAKE_VOLUME` to its actual existing volume names.
  Inspect the rendered Compose configuration before starting. Stop the previous
  Compose project first; do not use `down -v` on data you want to keep. An existing
  `.trustops-demo-seeded` marker prevents reseeding the sample lake.
- **Helm:** keep the existing release name and namespace. Set `nameOverride` and
  `fullnameOverride` to the previous chart name and resource fullname, and retain
  the old service account and Secret names in your values. Compare a rendered
  upgrade with the live Deployment, PVC, Service and selectors before applying.
  Renaming Kubernetes resources is a separate migration; changing the chart
  directory does not migrate a PVC. Select a published GRC Lake image explicitly.
- **Terraform:** internal resource addresses retain their legacy names to avoid
  a branding-only state rename. Preserve existing input values for namespaces,
  release names, buckets, IAM roles, and service accounts. New default names are
  for new installations. Review `terraform plan` for replacements before applying.
- **Git:** GitHub redirects the previous repository URL after the rename. Update
  your remote to `https://github.com/msaad00/grc-lake.git` when convenient. Existing
  clones and worktree directories need not be moved.

See [deployment](DEPLOYMENT.md) and the
[supported topology](runbooks/HA_READ_REPLICAS.md). Replicas, sharding, storage
redundancy, and backup guarantees do not change with the name.
