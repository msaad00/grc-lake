# CI posture gate

The posture gate is a GitHub Action that asks a TrustOps deployment for its
current posture and failing control tests, and fails the job when they cross
the thresholds you set. Use it to stop a merge or a deploy when compliance
posture gets worse.

It lives in this repository at
[`.github/actions/posture-gate`](../.github/actions/posture-gate/action.yml),
so any repository can call it. It reads only; it never changes TrustOps state.
Operational details (running the script outside GitHub, snapshots on a green
deploy, troubleshooting) are in the [CI posture gate playbook](playbooks/CI_POSTURE_GATE.md).

## Try it on sample data

[`examples/github-actions/trustops-golden-gate.yml`](../examples/github-actions/trustops-golden-gate.yml)
needs no deployment and no secrets. Copy it into `.github/workflows/` of any
repository. It installs TrustOps on the runner, loads the bundled sample
company, serves it on loopback, and runs the gate twice: a ratchet gate that
passes at the sample's current numbers, and a strict gate that the last step
asserts has failed.

To run the same thing on your machine:

```bash
pip install "trustops-security-data-lake[server]"
security-lakehouse fixtures load --company golden --out ./lake --rebase-times
security-lakehouse serve --server --allow-insecure-no-auth --lake ./lake --port 8787 &

# From a checkout of this repository (needs curl and jq):
TRUSTOPS_URL=http://127.0.0.1:8787 MIN_SCORE=70 ./tools/ci/posture-gate.sh
# exits 1: the sample company has a low score and failing control tests
```

## Gate a real deployment

Create an API key for a user with the `read_only` role (console
**Access → API keys**; see [server auth](SERVER_AUTH.md#api-keys)), then add two repository
secrets: `TRUSTOPS_URL` (for example `https://trustops.example.com`) and
`TRUSTOPS_API_TOKEN`. Copy this workflow into `.github/workflows/`:

```yaml
name: TrustOps posture gate

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  posture:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Evaluate TrustOps posture
        id: gate
        uses: msaad00/trustops-security-data-lake/.github/actions/posture-gate@v0.2.24
        with:
          trustops-url: ${{ secrets.TRUSTOPS_URL }}
          api-token: ${{ secrets.TRUSTOPS_API_TOKEN }}
          min-score: "70"
          max-critical-violations: "0"
          max-failing-control-tests: "0"
      - name: Report
        if: always()
        env:
          SCORE: ${{ steps.gate.outputs.posture_score }}
          STATE: ${{ steps.gate.outputs.posture_state }}
        run: echo "TrustOps posture ${SCORE} (${STATE})" >> "$GITHUB_STEP_SUMMARY"
```

The same file is checked in as
[`examples/github-actions/trustops-posture-gate.yml`](../examples/github-actions/trustops-posture-gate.yml).
The runner must reach `TRUSTOPS_URL`; for a private deployment, use a
self-hosted runner inside that network. For supply-chain safety, pin the
`uses:` line to the commit SHA of the release tag instead of the tag name.

## Inputs

| Input                       | Default         | Meaning                                                                      |
| --------------------------- | --------------- | ---------------------------------------------------------------------------- |
| `trustops-url`              | required        | Base URL of the deployment, no trailing slash.                               |
| `api-token`                 | empty           | Bearer API key with read scope. Empty only for a local no-auth server.       |
| `correlation-id`            | `github.run_id` | Sent as `X-Correlation-ID`, so the run appears in the TrustOps audit trail.  |
| `min-score`                 | `0`             | Minimum posture score, 0 to 100.                                             |
| `max-critical-violations`   | `0`             | Maximum open critical violations.                                            |
| `max-open-violations`       | `-1`            | Maximum open violations of any severity; `-1` skips the check.               |
| `max-failing-control-tests` | `0`             | Maximum failing control tests after the allowlist; `-1` skips the check.     |
| `allowed-failing-controls`  | empty           | Comma-separated control IDs that may fail without failing the gate.          |
| `framework`                 | empty           | Only count failing control tests for this framework ID (for example `soc2`). |
| `fail-on-stale-evidence`    | `false`         | `true` also fails the gate when any control has stale or expired evidence.   |

## Outputs

| Output                      | Meaning                                                   |
| --------------------------- | --------------------------------------------------------- |
| `posture_score`             | Posture score returned by TrustOps.                       |
| `posture_state`             | Posture state label, for example `healthy` or `critical`. |
| `open_violation_count`      | Open violations at evaluation time.                       |
| `critical_violation_count`  | Open critical violations at evaluation time.              |
| `failed_control_test_count` | Failing control tests after the allowlist.                |

## Choosing thresholds

- **Ratchet.** Set each maximum to today's number and lower it as you fix
  things. The gate then fails only on regressions.
- **Known exceptions.** List a control in `allowed-failing-controls` while an
  approved exception is open, and remove it when the exception closes.
- **Per framework.** Use `framework` to gate one program, for example a SOC 2
  audit window, without blocking on the others.

The gate needs `curl` and `jq` on the runner; GitHub-hosted Ubuntu runners
have both. It calls `GET /api/v1/posture/current` and, unless
`max-failing-control-tests` is `-1` and there is no allowlist,
`GET /api/v1/control-tests?result=fail`.
