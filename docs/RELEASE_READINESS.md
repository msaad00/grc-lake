# Release readiness

GRC Lake **0.3.1** prepares generation-aware read caching, seek-based collection
pages, bulk mart loading, and refreshed documentation listed in the
[changelog](../CHANGELOG.md). The rebrand and opt-in PostgreSQL/S3 runtime shipped
in 0.3.0. Local deployment remains supported. Distributed mode requires explicit
configuration and the [migration and recovery procedures](DISTRIBUTED.md); it is
not enabled by a package upgrade. Cache reuse across distributed request scratch
directories remains limited; local timings do not establish distributed capacity.

Version 0.3.1 is published. Changes merged after its release commit are not
in those artifacts; qualify them as a subsequent version before tagging. A new
source version remains a candidate until the publication gates below succeed. Existing `trustops-security-data-lake` releases remain available under
their original PyPI name. New releases target `grc-lake`; use a fresh Python
environment when moving between distributions because they own overlapping
module files. Legacy CLI aliases and Python imports remain supported.

Source and CI qualification do not establish publication, live-provider accuracy,
or a working customer deployment. The pinned build-tool replacement and its
verification limits are documented in [dependency security scope](DEPENDENCY_SECURITY.md).

## Release gates

A source test, successful CI run, published artifact, and authenticated deployment
are separate evidence. Run the checks below on the final revision; publish only
when its required CI checks pass.

| Gate                  | Verification                                                                                            | Required outcome                                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Version alignment     | `uv run pytest -q tests/test_release_version_consistency.py`                                            | Python package, lockfiles, console, chart, and changelog agree; workflow actions are SHA-pinned and every job has a timeout |
| Core contracts        | `uv run pytest -q`                                                                                      | Correctness, collection failure, generation integrity, auth, and tenant-boundary tests pass                                 |
| Public artifacts      | `uv run pre-commit run --all-files` and `make validate validate-doc-images validate-brand`              | Valid catalogs, references, branding, and secret checks                                                                     |
| Console               | `npm --prefix app/web run lint`, `npm --prefix app/web run typecheck`, `npm --prefix app/web run build` | A bundled static console with no lint or type errors                                                                        |
| Browser interactions  | `bash tools/run_e2e_console.sh`                                                                         | Dashboard, links, disclosures, accessible interactions, and responsive layouts pass against synthetic fixtures              |
| Dependency security   | `make pip-audit npm-audit`                                                                              | No audit-blocking vulnerabilities in the resolved dependencies                                                              |
| Image vulnerabilities | CI `docker-build` job (Trivy)                                                                           | No fixable HIGH or CRITICAL vulnerability in the built image                                                                |
| Packaging             | `make release-build`                                                                                    | A clean `dist/`; wheel verification confirms that the console and required runtime assets are included                      |
| Deployment templates  | `make deploy-check`                                                                                     | Helm rendering and Terraform validation pass; no resources are provisioned                                                  |
| Changelog             | A `## <version> - <date>` section in `CHANGELOG.md`                                                     | The section exists and becomes the GitHub release notes                                                                     |
| Publication           | Version tag on a main commit whose `ci` run passed                                                      | GitHub, PyPI, and container publication jobs succeed                                                                        |
| Published artifacts   | Fresh install and container smoke checks; `gh attestation verify`                                       | Version, bundled console, health, authenticated authorization, persistence, and integrity checks pass; provenance verifies  |

A branch merge alone does not publish a release. On a `v*` tag, the release
workflow enforces these gates before anything is published:

1. **Tested commit.** The tagged commit must be on `main`, and the `ci`
   workflow must have concluded `success` for that exact SHA. A tag pushed while
   CI is still running waits for it (up to 40 minutes); a tag on an unmerged or
   failing commit stops the release.
2. **Version.** The tag must equal the version in `pyproject.toml`,
   `Chart.yaml` (`version` and `appVersion`), `app/web/src/lib/brand.ts`, and
   `app/web/package.json`, and `CHANGELOG.md` must have a `## <version>` section.
3. **Build.** The console is built, then the wheel and sdist with `uv build`
   (uv pinned to the same version as the Dockerfile) and a bounded setuptools.
   `tools/verify_wheel.py` checks the wheel.
4. **Image scan.** The image is built and scanned with Trivy before it is
   pushed; a fixable HIGH or CRITICAL vulnerability blocks the release.

What each release publishes:

| Artifact                      | Where                      | Supply-chain evidence                                                                                                |
| ----------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Wheel and sdist               | PyPI (trusted publishing)  | SLSA build provenance attestation; PyPI publish attestations                                                         |
| Container image               | `ghcr.io/<owner>/grc-lake` | BuildKit provenance (`mode=max`) and SBOM attestations; a GitHub build provenance attestation pushed to the registry |
| CycloneDX SBOM (`*.cdx.json`) | GitHub release             | The locked Python runtime dependencies (base plus the extras the image installs), generated by `uv export`           |
| Release notes                 | GitHub release             | This version's `CHANGELOG.md` section, followed by GitHub's generated PR list                                        |

Image tags are the exact version, `<major>.<minor>`, and `sha-<short>`. `latest`
moves only for a stable tag; a prerelease such as `v1.0.0-rc.1` never updates it.

Verify artifacts against the identity that signed that release. Releases through
0.3.1 were published from `msaad00/grc-lake`; a repository redirect does not
rewrite their signing certificates or move their GHCR package. For the next
release from `koda-ai-studio/grc-lake`, use that repository and its published image
digest after publication succeeds.

```bash
# Historical 0.3.1 image: fetch the signed bundle directly from the registry.
gh attestation verify \
  oci://ghcr.io/msaad00/grc-lake@sha256:d8cd294bbe5b761ab98f38931657711b1aa94edc08d7687b757d4973a89d7625 \
  --repo msaad00/grc-lake --bundle-from-oci \
  --signer-workflow msaad00/grc-lake/.github/workflows/release.yml \
  --source-digest 62360213113726240b89c8e00769311768bcd3a8

# For a future release published from the current repository:
gh attestation verify grc_lake-<version>-py3-none-any.whl --repo koda-ai-studio/grc-lake

# Releases using bundle retention also attach python-provenance.sigstore.json.
# Download it from the same release as the wheel/sdist, then verify each file:
gh attestation verify grc_lake-<version>-py3-none-any.whl \
  --bundle python-provenance.sigstore.json --repo koda-ai-studio/grc-lake \
  --signer-workflow koda-ai-studio/grc-lake/.github/workflows/release.yml \
  --source-digest <release-commit> --source-ref refs/tags/v<version>
```

The workflow retains the original signed Python bundle as a `python-provenance`
Actions artifact before publishing to PyPI, then attaches it to the GitHub
release. Missing or empty bundle output stops publication. The bundle stays
outside `dist/` and is not uploaded to PyPI as a distribution. It covers both the
wheel and sdist; run verification for each. This provides an independent retrieval
path for future releases, but does not restore missing bundles for older releases.
The staging tests check byte preservation and missing-file failures; actual
signature verification requires the signed release bundle.

If the GitHub attestation API returns 404, retain the retrieval failure separately
from artifact-integrity checks. For containers, `--bundle-from-oci` provides an
independent retrieval path for the signed GitHub bundle. It is not the same as
merely inspecting unsigned BuildKit metadata. PyPI publishing attestations also
provide distinct evidence for Python artifacts; they do not establish that a
GitHub SLSA bundle is retrievable. Never change the expected signer just to make
verification pass. See [GitHub attestation verification](https://cli.github.com/manual/gh_attestation_verify).

All workflow actions are pinned to a full commit SHA with the release tag in a
comment, and the Dockerfile pins its base images by digest. Dependabot's
`github-actions` and `docker` ecosystems propose updates to both.

## Next publication after the repository transfer

The `grc-lake` PyPI project already exists. A project owner must configure an
[ordinary trusted publisher on that project](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
not a pending publisher intended to create a new project:

| Field             | Value            |
| ----------------- | ---------------- |
| PyPI project      | `grc-lake`       |
| GitHub owner      | `koda-ai-studio` |
| Repository        | `grc-lake`       |
| Workflow filename | `release.yml`    |
| Environment       | `release`        |

Verify the `release` GitHub environment and its intended reviewer/tag restrictions
as well. A successful dry run exercises builds, not PyPI authorization or registry
write permissions. Historical provenance proves the earlier upload's identity;
it does not show the project's current trusted-publisher settings.

The release workflow derives its image destination from `github.repository_owner`,
so the next release targets `ghcr.io/koda-ai-studio/grc-lake`. Before tagging:

1. Confirm the organization permits package creation and that this repository's
   Actions token has access to the intended package. The workflow already requests
   `packages: write`; existing package grants and organization policy are separate.
2. Preserve `ghcr.io/msaad00/grc-lake` for historical releases. GHCR uses granular
   permissions: a [repository transfer does not transfer package ownership](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages#about-repository-transfers)
   and can remove repository linkage and Actions access.
3. Align the next candidate's Compose, Helm, Terraform, and example image settings
   with its intended namespace and version. Current 0.3.1 defaults deliberately
   retain the working historical image. Do not replace those defaults with an
   unpublished destination or assume an old version tag exists in the new namespace.
4. After user-authorized publication, verify anonymous pulls (if public delivery
   is intended), both architecture digests, signed provenance, and runtime smoke
   checks against the newly published bytes. Registry visibility may need explicit
   configuration; a successful workflow alone is not anonymous-pull evidence.

Keep the old distribution and its releases intact. Do not delete or replace a
publisher until its replacement is confirmed and remaining workflows are accounted
for. Merge, tag, publication, and deployment remain separate operator decisions.

## Authenticated image qualification

Use an already-pulled image and an explicit platform. The probe starts the
Compose server profile with authentication required, creates two synthetic tenants
and expiring admin/reader API keys, and checks authorization, evidence isolation,
snapshot reads/exports, revocation, integrity, and persistence after container
recreation. It reuses the image's installed application and never mounts source
code into the server. It removes its containers, volume, and temporary signing key.
Choose a fresh output directory for each run:

```bash
IMAGE=ghcr.io/msaad00/grc-lake@sha256:d8cd294bbe5b761ab98f38931657711b1aa94edc08d7687b757d4973a89d7625
docker pull --platform linux/amd64 "$IMAGE"
python tools/authenticated_smoke.py --image "$IMAGE" --platform linux/amd64 \
  --output /tmp/grc-lake-auth-amd64
```

Repeat with `linux/arm64` and another output directory. Record native versus
emulated execution. These are bounded local API-key checks; they do not establish
OIDC/SAML, TLS, live-provider behavior, production deployment, or capacity.
Use `tools/compose_smoke.py` separately when qualifying the unauthenticated demo.

Scan each published architecture against a fresh vulnerability database. Retain
all severities in the report, then separately evaluate the release policy of no
fixable HIGH/CRITICAL findings. A policy pass is not a vulnerability-free image.

## What the overview means

- **Assessment score** is the percentage of observed controls with fresh passing evidence; catalog coverage is reported separately.
- **Control pass rate** is passing test rows divided by total test rows. The chart
  separates pass, fail, warning, and remaining **Other** results. Unevaluated
  controls are not displayed as a zero-percent result.
- **Open findings** and severity counts describe the current assessment. Other
  findings are those outside the critical and high groups.
- **Frameworks assessed** describes assessed coverage, not certification or a
  complete assessment of every requirement in a framework.
- **Evidence freshness** and **assessment export** are separate from the score.
  A connected update stream does not establish that evidence is current.

## Evidence boundaries

Synthetic fixture tests demonstrate reproducible application behavior, including
failure and authorization paths. They do not establish live collection accuracy,
precision, recall, customer capacity, vendor cost savings, or production readiness.

Local Polaris/Iceberg and independent-reader tests establish only the catalog,
snapshot, schema, and data-parity behaviors covered by those tests. They do not
establish interoperability with every hosted warehouse or object store.

A Docker build or Helm render is not an authenticated cloud deployment. Private
cloud-account experiments must be documented separately with sanitized results;
never commit credentials, account identifiers, raw customer evidence, or private
commercial information to this public repository.

## Deployment probes

`GET /api/healthz` reports process liveness. `GET /api/readyz` returns 200 only
when local mode has the tenant table and its lake root accepts a temporary write
and fsync. Distributed mode additionally checks access to its S3 bucket while
using PostgreSQL for the tenant-table check and private scratch for the write
probe; otherwise it returns a sanitized 503. Both
are unauthenticated. Readiness is excluded from request audit and rate limiting,
returns `Cache-Control: no-store`, and never enumerates tenants or hashes all
assessment artifacts. An empty, initialized deployment can be ready.

SQLite is checked with a fresh existing-file connection, so removal or corruption
is detected even if the application pool still holds an earlier connection.
Restoring the database makes the next probe succeed. Remote database connection
timeouts follow the configured SQLAlchemy driver. The Helm chart uses readiness
to route traffic and keeps liveness separate to avoid restarting on dependency
outages. These probes do not certify assessment freshness, per-tenant artifact
integrity, backup recovery, or remote provider health.

## Deployment acceptance

Before sharing a hosted pilot, validate the target environment directly:

1. HTTPS, external authentication, tenant isolation, and role-based access.
2. Required read-only connector grants and complete collection with failure
   reporting, freshness, and provenance.
3. Integrity verification, durable evidence and snapshots, backup and restore.
4. Scheduler behavior, resource limits, logs, monitoring, and incident ownership.
5. Scoped export/share creation, expiry, revocation, and audit records.
6. Workload-specific throughput, data volume, latency, and operating cost.

Certification decisions require the applicable independent assessment process.
Framework mappings and executable checks support evidence review; they do not
replace that process.
