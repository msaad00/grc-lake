# Security policy

## Report a vulnerability

Please report security vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/msaad00/trustops-security-data-lake/security/advisories/new)**
(the repository's **Security** tab, then **Report a vulnerability**).

Do not open a public issue, pull request, or discussion for a vulnerability.

Include what you can of:

- the affected version (`pip show trustops-security-data-lake`, or the image tag);
- the component: API, console, CLI, MCP server, a connector, the Helm chart,
  the container image, or the posture-gate action;
- steps to reproduce, and the impact you expect;
- whether the issue needs authentication, and which role.

Do not include real credentials or customer evidence. We will acknowledge the
report, work on a fix in the private advisory, and credit you when the advisory
is published unless you ask us not to.

## Supported versions

Security fixes go into the latest release of the current minor line and ship
as a new patch release. Upgrade to the newest patch to receive them.

| Version                      | Supported |
| ---------------------------- | --------- |
| Latest `0.2.x` patch release | Yes       |
| Earlier releases             | No        |

## Scope

In scope:

- the `trustops-security-data-lake` Python package and its CLI, API, console,
  and MCP server;
- the `ghcr.io/msaad00/trustops` container image and the Helm chart in
  [`deploy/helm/trustops`](deploy/helm/trustops/);
- the posture-gate GitHub Action in [`.github/actions/posture-gate`](.github/actions/posture-gate/);
- deployment templates in [`deploy/`](deploy/) and [`compose.yaml`](compose.yaml).

Examples of issues we want to hear about: authentication or tenant-isolation
bypass, privilege escalation between roles, credential or secret disclosure,
server-side request forgery through connectors, injection, and tampering with
evidence or review logs that goes undetected.

Out of scope:

- running with authentication disabled (`--allow-insecure-no-auth`, or the
  default `trustops` service in `compose.yaml`). That mode is unauthenticated
  by design, for local demos only;
- vulnerabilities in third-party dependencies with no TrustOps-specific impact;
  report those upstream. Dependabot opens weekly version-update PRs;
- findings in the bundled sample data under `mockup_companies/`;
- results that need an already compromised host, or physical access.

For how authentication, tenancy, and credentials are designed, see
[server auth](docs/SERVER_AUTH.md) and [architecture](docs/ARCHITECTURE.md).

The current dependency audit scope and the build-tool advisory mitigations are documented in
[dependency security](docs/DEPENDENCY_SECURITY.md).
