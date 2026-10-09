# GRC Lake in five minutes

From nothing to evaluated controls on sample data, then your own cloud, a
mapping review, and an auditor export. Steps 1 to 3 need no account and no
credentials.

## 1. Start GRC Lake with sample data

Pick one.

**Docker Compose** (Docker with Compose v2):

```bash
git clone https://github.com/msaad00/grc-lake.git
cd grc-lake
docker compose up
```

**pip** (Python 3.11 or later):

```bash
python -m venv .venv && source .venv/bin/activate
pip install "grc-lake[server]"
grc-lake fixtures load --company golden --out ./lake --rebase-times
grc-lake serve --server --allow-insecure-no-auth --lake ./lake --port 8787
```

Either way you get the bundled **golden** sample company (38 controls and 41
evidence records across AWS, GitHub, identity, and AI-governance sources),
served at <http://127.0.0.1:8787/console/dashboard/>.

> **Authentication is off.** Both commands are for your own machine and sample
> data only. Compose publishes the port on `127.0.0.1` only. For a shared or
> real deployment, use the Compose `grc-lake-server` service (below) or the
> [deployment guide](../deploy/README.md).

Check it is up:

```bash
curl -s http://127.0.0.1:8787/api/healthz
# {"ok":true,"service":"grc-lake-assessment"}
```

## 2. Read the first findings

In the console, **Overview** shows the posture score and the open violations;
**Controls** lists each control with its result and the evidence behind it.

The same numbers from the API and the CLI:

```bash
curl -s http://127.0.0.1:8787/api/v1/posture/current | jq '.data.posture'
grc-lake assessment status --lake ./lake | jq '.posture'
grc-lake assessment violations --lake ./lake
```

For a concise terminal summary and the installed package version:

```bash
grc-lake --version
grc-lake assessment status --lake ./lake --format summary
```

The summary shows the posture, total and unevaluated controls, failing and warning
tests, open violations, and stale/expired/missing evidence. JSON remains the
default; `--format json` selects it explicitly. Summary counts use the same
assessment totals as JSON, including when detailed violation lists are capped.

The sample company is deliberately unhealthy. Counts and scores depend on the
evaluation policy and evidence freshness at run time; use the summary above for
current values. Every failure links to the evidence record that caused it.

With Compose, run CLI commands inside the container and use `/lake`:

```bash
docker compose exec grc-lake grc-lake assessment status --lake /lake
```

## 3. Gate a pipeline on it

The [CI posture gate](CI_GATE.md) turns those numbers into a pass or fail for a
pull request. From a checkout of this repository, with the server still running:

```bash
GRC_LAKE_URL=http://127.0.0.1:8787 MIN_SCORE=70 ./tools/ci/posture-gate.sh
# exits 1: posture score is below 70, with 4 critical violations and 19 failing control tests
```

## 4. Connect one real cloud account, read-only

Use a **new lake** for real evidence so it never mixes with the sample data.
Install the cloud SDKs, then follow [Live cloud POC](LIVE_CLOUD_POC.md) for your
provider. For AWS with an SSO profile, the local flow is:

```bash
pip install "grc-lake[server,cloud]"
aws sso login --profile grc-lake-poc
export AWS_PROFILE=grc-lake-poc
creds='{"account_id":"<account-id>"}'

grc-lake connectors probe --lake ./my-lake --connector-id aws-posture --credentials-json "$creds"
grc-lake connectors configure --lake ./my-lake --connector-id aws-posture --credentials-json "$creds" --state enabled
grc-lake connectors sync --lake ./my-lake --connector-id aws-posture
```

The connector calls only read-only IAM APIs, listed in
[Live cloud POC](LIVE_CLOUD_POC.md#aws-trial-account). For a server, use the
assume-role variant and the templates in [`deploy/aws`](../deploy/aws/),
[`deploy/azure`](../deploy/azure/), or [`deploy/gcp`](../deploy/gcp/); the
console path is **Connections → choose a source → Test → Enable → Sync**.

## 5. Review a mapping

A mapping says "this safeguard's evidence satisfies that framework
requirement". Proposed mappings have not been confirmed by a person. List the
SOC 2 queue, then approve one with a rationale:

```bash
grc-lake frameworks review-queue --lake ./lake --framework soc2 \
  | jq -r '.items[:5][] | "\(.safeguard_id) \(.control_id) \(.review_state)"'

grc-lake frameworks review approve --lake ./lake \
  --safeguard SG-IDENTITY-001 --framework soc2 --control SOC2-CC6.3 \
  --rationale "Access-review evidence covers removal of logical access" \
  --reviewer you@example.com

grc-lake frameworks safeguards --lake ./lake --format table | head -3
# Counts reflect the current catalog and your organization review decisions.
```

The decision is appended to a hash-chained log in the lake. In server mode
only a signed-in `admin` or `compliance_reviewer` can decide, in the console
under **Evaluate → Mapping review**. [Mapping review](MAPPING_REVIEW.md) has
the full model.

## 6. Export for an auditor

```bash
# Freeze the current posture as a hash-chained snapshot.
grc-lake assessment snapshot --lake ./lake --reason "Q3 readiness review"

# OSCAL component definition, including your org-reviewed mappings.
grc-lake oscal export --component-definition --lake ./lake --out component-definition.json

# OSCAL assessment results: one finding per evaluated control.
grc-lake oscal export --assessment-results ./lake --out assessment-results.json
```

[OSCAL export](OSCAL_EXPORT.md) explains both documents and the matching API
routes. In the console, **Audit room** collects frozen assessments for review.

## Next steps

- Run it for real with the Compose `grc-lake-server` service. It requires
  authentication, has no sample data, and listens on `127.0.0.1:8788`; put a
  TLS proxy in front. Create the first tenant and admin, whose email must
  match their SSO login ([server auth](SERVER_AUTH.md) covers OIDC and SAML):

  ```bash
  cp deploy/compose/grc-lake.env.example grc-lake.env   # then fill in the secrets
  docker compose run --rm grc-lake-server grc-lake auth create-tenant --lake /lake --slug acme --name "Acme"
  docker compose run --rm grc-lake-server grc-lake auth create-user --lake /lake --tenant-slug acme --email admin@acme.example --role admin
  docker compose up -d grc-lake-server
  ```

- Reset the Compose demo with `docker compose down -v`.
- [Product walkthrough](PRODUCT_WALKTHROUGH.md) · [connectors](CONNECTORS.md) ·
  [framework coverage](FRAMEWORK_COVERAGE.md) · [contributing](../CONTRIBUTING.md)
