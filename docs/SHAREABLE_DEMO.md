# Shareable Demo

Use this guide when you want a **hosted link** evaluators can open, sign into, **link real accounts**, see **live ingestion**, and receive a **scoped trust share** — without exposing raw evidence or credentials.

## What you publish

| Link                                                   | Audience           | Purpose                                                |
| ------------------------------------------------------ | ------------------ | ------------------------------------------------------ |
| `{PUBLIC_URL}/console/demo/`                           | Evaluators         | Demo landing — sign in, connect accounts, view posture |
| `{PUBLIC_URL}/console/poc/`                            | Operators          | Launch checklist + copyable invite URLs                |
| `{PUBLIC_URL}/api/v1/auth/login`                       | Evaluators         | Browser SSO entry                                      |
| `{PUBLIC_URL}/console/connectors/?connect=aws-posture` | Operators          | Deep-link account linking                              |
| `{PUBLIC_URL}/console/trust-center/`                   | Operators          | Issue auditor/customer trust links                     |
| `{PUBLIC_URL}/console/trust/{token}`                   | External reviewers | Redacted posture (token shown once at create)          |

Set `GRC_LAKE_PUBLIC_URL` on the server (Helm `env` or process environment). The console **Launch** and **Demo** pages surface copyable links when this variable is set.

## Operator flow (15 minutes)

1. Deploy from [Shareable POC Hosting](SHAREABLE_POC_HOSTING.md) or `deploy/examples/aws-snowflake-poc-values.yaml`.
2. Configure OIDC/SAML — **do not** use `--allow-insecure-no-auth` for external shares.
3. Open `/console/poc/` as admin — confirm gates turn green.
4. Copy **Shareable demo links** (workspace, sign-in, connect accounts).
5. Send evaluators the **Demo landing** or **Sign-in** URL.
6. Link at least one source on **Connectors** (discover → probe → enable → sync).
7. Confirm dashboard shows non-empty posture from live sync.
8. Create a trust-center share for external reviewers.

## Account linking (true ingestion)

GRC Lake uses **read-only** connectors. The console walks:

```text
Connect → Discover scope → Probe (Test) → Enable → Sync → Posture updates
```

Recommended first links (deep-link from Launch page):

| Connector                 | What it proves                  |
| ------------------------- | ------------------------------- |
| `aws-posture`             | Cloud IAM + config evidence     |
| `azure-posture`           | Azure subscription posture      |
| `gcp-posture`             | GCP org/project posture         |
| `snowflake-evidence-lake` | Existing governed evidence lake |
| `github-security`         | Repo and supply-chain signals   |
| `okta-identity`           | Identity directory evidence     |

Status on the Launch page:

- **not linked** — connector disabled
- **connected** — probe succeeded
- **live ingestion** — enabled with successful sync and evidence rows

## API: demo kit

`GET /api/v1/platform/poc-readiness` (admin) returns `demo_kit`:

```json
{
  "share_links": [
    { "kind": "workspace", "url": "https://...", "label": "..." }
  ],
  "account_linking": [
    {
      "connector_id": "aws-posture",
      "status": "ingesting",
      "connect_url": "..."
    }
  ],
  "account_linking_summary": { "live_ingestion": 1 }
}
```

No raw tokens or secrets are included in this response.

## Evaluator experience

1. Open the demo or sign-in link from your host.
2. Authenticate with company SSO.
3. Open **Connectors** (or use a deep link your host sent).
4. Complete account linking with read-only grants your security team approved.
5. Review **Dashboard**, **Evidence**, and **Controls**.
6. If shared a trust link, open `/console/trust/{token}` for redacted external view.

## Related docs

- [Shareable POC Hosting](SHAREABLE_POC_HOSTING.md) — Helm, secrets, scheduler
- [AWS + Snowflake Demo](AWS_SNOWFLAKE_DEMO.md) — reference deployment
- [Release Readiness](RELEASE_READINESS.md) — go/no-go gates
- [Connectors](CONNECTORS.md) — access boundaries
