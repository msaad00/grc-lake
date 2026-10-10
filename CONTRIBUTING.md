# Contributing to GRC Lake

Thanks for helping. Bug reports, docs fixes, connectors, framework packs, and
console polish are all welcome. Issues labeled
[`good first issue`](https://github.com/msaad00/grc-lake/labels/good%20first%20issue)
are scoped to be finished in one pull request.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Report
security problems privately, as described in [SECURITY.md](SECURITY.md), not in
a public issue.

## Set up

You need Python 3.11 or later, [uv](https://docs.astral.sh/uv/), Node 22 or
later, and `make`.

```bash
git clone https://github.com/msaad00/grc-lake.git
cd grc-lake
make uv-sync               # uv sync --frozen --all-extras, same as CI
make pre-commit-install    # pre-commit and commit-message hooks
make web-install           # console dependencies (npm ci)
```

Run `make help` (or just `make`) to list commands and their descriptions. This
does not require Python or Node dependencies and does not start builds or tests.
Python targets run through `uv run --frozen python`, so Ruff, mypy and pytest
come from the lockfile rather than whatever is first on `PATH`. Set
`PYTHON=python` to use an already-activated interpreter instead.

Run the console against the sample company:

```bash
make demo-local            # builds the console, loads the golden fixture, serves :8787
```

Then open <http://127.0.0.1:8787/console/dashboard/>. Authentication is off in
this mode; it is for your machine only. After a console change, run
`make web-build` and restart the server to see it.

`make web-dev` starts the Next.js UI development server at
<http://localhost:5173/console/dashboard/>. It has no API proxy: relative `/api`
requests go to port 5173. Use `make demo-local` above when you need the working
console and Python API together.

If you only need the pre-built console, `docker compose up` runs the published
image with the same sample data; see the [5-minute tutorial](docs/TUTORIAL_5_MIN.md).

## Check your change

Run the checks that match what you touched before you push. CI runs all of them.

| Change                  | Command                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------- |
| Any Python              | `make lint format-check test`                                                         |
| One test file           | `python -m pytest -q tests/test_<name>.py`                                            |
| Catalogs, fixtures, API | `make smoke` (validation, pipeline, generated artifacts, API smoke, tests)            |
| Console (`app/web/`)    | `make web-ci` (install, typecheck, production build), `npm --prefix app/web run lint` |
| Docs images, brand      | `make validate-doc-images validate-brand`                                             |
| Helm, Terraform         | `make deploy-check` (needs `helm` and `terraform`)                                    |
| Everything, as CI does  | `make ci`, then `make pre-commit-run`                                                 |

CI partitions the complete collected Python suite into four groups, balancing
by test count while keeping each module's fixtures on one runner. To reproduce
a group locally, run `uv run python -m pytest -q -p tools.pytest_shard --ci-shard=1/4`
(replace `1` with the failing group). Ordinary `make test` still runs everything.
The required `smoke` check passes only when every group, the pipeline smoke, hooks,
and security scans pass; failures, cancellations, and skipped dependencies block it. Each group
retains a JUnit report and prints its slowest tests for diagnosing imbalance.

Ruff runs in `quality` and the history secret scan runs in `security`; CI skips
those duplicate pre-commit hooks and caches the remaining hook environments.
Local pre-commit still runs every hook. The security and Docker jobs start
without waiting for the web job; Python, pipeline, and browser tests consume
its bundle. Docker separately verifies the standalone image build and Compose
quickstart. CodeQL cancels superseded runs for the same branch or pull request.

Write the test first when you fix a bug or add behavior, and check that it
fails without your change. Tests assert on real output, not on "it ran".

For Compose or image changes, build locally with `docker build -t grc-lake:ci .`,
then run `python3 tools/compose_smoke.py --image grc-lake:ci`. Docker Compose
2.24.4 or newer is required. The check uses a fresh project and a dynamic loopback
port, recreates the demo container on the same volume, and removes its containers
and volumes afterward. It also validates the authenticated server profile with
synthetic configuration; it does not start that profile or contact cloud providers.
Diagnostics are saved in `build/compose-smoke/`; use `--output` with a new path
for each repeat so earlier failure evidence remains available. CI runs this check
inside the required `docker-build` job and retains its JSON result and container
log for 14 days, including when the check fails.

## Commits and pull requests

- Branch from `main`. One logical change per pull request.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  enforced by the commitizen hook: `feat(connectors): add Jamf device evidence`,
  `fix(console): keep filters on reload`, `docs: explain mapping review`.
  Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, and `chore`.
- Fill in the [pull request template](.github/pull_request_template.md): what
  changed, why, and the commands you ran.
- Keep claims honest. Do not describe a framework, connector, or control as
  covered or live-verified unless the catalog, tests, and docs back it.
- The repository does not require a DCO sign-off.

## Add a connector

Connectors are read-only evidence collectors. Start with
[Adding connectors](docs/ADDING_CONNECTORS.md): the scaffold command, the
contributor checklist, event-log versus snapshot collection, and how to ship a
connector as a separate Python package. The [connector catalog](docs/CONNECTORS.md)
shows the contract every existing connector follows. Every connector needs a
fixture client, so its tests run offline.

## Add or extend a framework pack

Framework packs are JSON manifests. [Framework packs](docs/FRAMEWORK_PACKS.md)
covers the manifest schema, `make framework-packs`, and how to add a framework;
the [Common Control Framework](docs/COMMON_CONTROL_FRAMEWORK.md) explains how
safeguards map to requirements. New mappings start as `proposed`; only a
person who has checked the requirement text marks one `reviewed`
(see [mapping review](docs/MAPPING_REVIEW.md)).

## Repository layout

| Path                                    | Contents                                                      |
| --------------------------------------- | ------------------------------------------------------------- |
| `src/security_lakehouse/`               | Engine, API, auth, connectors, MCP server, CLI.               |
| `app/web/`                              | Next.js console.                                              |
| `controls/`, `frameworks/`, `mappings/` | Rules, framework catalogs, and mappings.                      |
| `mockup_companies/`                     | Sample companies used as fixtures.                            |
| `tests/`                                | Python tests.                                                 |
| `deploy/`, `compose.yaml`               | Deployment examples.                                          |
| `docs/`                                 | Guides; [architecture](docs/ARCHITECTURE.md) is a good start. |

## License

Contributions are accepted under the [Apache License 2.0](LICENSE), the
project's license.
