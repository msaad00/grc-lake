# Release readiness

TrustOps **0.2.16** adds production SCIM 2.0 and Stripe billing for commercial
hosted tenants, a Databricks evidence-lake reader (preview), inherited NIST SP
800-53 reviews, and official NIST AI RMF titles. See [the
changelog](../CHANGELOG.md) for release scope.

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
| Container image               | `ghcr.io/<owner>/trustops` | BuildKit provenance (`mode=max`) and SBOM attestations; a GitHub build provenance attestation pushed to the registry |
| CycloneDX SBOM (`*.cdx.json`) | GitHub release             | The locked Python runtime dependencies (base plus the extras the image installs), generated by `uv export`           |
| Release notes                 | GitHub release             | This version's `CHANGELOG.md` section, followed by GitHub's generated PR list                                        |

Image tags are the exact version, `<major>.<minor>`, and `sha-<short>`. `latest`
moves only for a stable tag; a prerelease such as `v1.0.0-rc.1` never updates it.

Verify a published artifact:

```bash
gh attestation verify trustops_security_data_lake-<version>-py3-none-any.whl --repo msaad00/trustops-security-data-lake
gh attestation verify oci://ghcr.io/msaad00/trustops:<version> --repo msaad00/trustops-security-data-lake
```

All workflow actions are pinned to a full commit SHA with the release tag in a
comment, and the Dockerfile pins its base images by digest. Dependabot's
`github-actions` and `docker` ecosystems propose updates to both.

## What the overview means

- **Assessment score** is the control-count-weighted framework score out of 100.
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
