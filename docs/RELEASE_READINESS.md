# Release readiness

GRC Lake **0.3.1** prepares generation-aware read caching, seek-based collection
pages, bulk mart loading, and refreshed documentation listed in the
[changelog](../CHANGELOG.md). The rebrand and opt-in PostgreSQL/S3 runtime shipped
in 0.3.0. Local deployment remains supported. Distributed mode requires explicit
configuration and the [migration and recovery procedures](DISTRIBUTED.md); it is
not enabled by a package upgrade. Cache reuse across distributed request scratch
directories remains limited; local timings do not establish distributed capacity.

The source version is a release candidate until the publication gates below
succeed. Existing `trustops-security-data-lake` releases remain available under
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

Verify a published artifact:

```bash
gh attestation verify grc_lake-<version>-py3-none-any.whl --repo msaad00/grc-lake
gh attestation verify oci://ghcr.io/msaad00/grc-lake:<version> --repo msaad00/grc-lake
```

All workflow actions are pinned to a full commit SHA with the release tag in a
comment, and the Dockerfile pins its base images by digest. Dependabot's
`github-actions` and `docker` ecosystems propose updates to both.

## First publication under the GRC Lake name

Before tagging the first `grc-lake` release, configure a GitHub Actions pending
publisher under [PyPI account publishing](https://pypi.org/manage/account/publishing/):

| Field             | Value         |
| ----------------- | ------------- |
| PyPI project name | `grc-lake`    |
| GitHub owner      | `msaad00`     |
| Repository        | `grc-lake`    |
| Workflow filename | `release.yml` |
| Environment       | `release`     |

A [pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
creates the project on its first successful upload; it does not reserve the name.
Keep the old project's releases intact. The old project's publisher does not
authorize publication of the new distribution. Do not treat a repository rename
or a successful dry run as proof that PyPI publishing authorization is configured.

## What the overview means

- **Assessment score** is the percentage of observed controls with fresh passing evidence; catalog coverage is reported separately.
- **Assessed coverage** is the share of catalogued requirements with an assessment
  result. It describes assessment scope, not the percentage passing. Requirements
  still needing evidence remain visible separately.
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
