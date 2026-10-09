# Product Walkthrough

GRC Lake runs on infrastructure you operate: your laptop, a single host, or your
Kubernetes cluster. There is no managed service. This page gets the demo running
and maps each console page to the job it does. What is shipped versus planned
lives in the [roadmap](../ROADMAP.md).

## First run

| Step            | Command                                                                               | Result                                                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Install         | `uv sync --frozen --extra dev --extra server`                                         | The `grc-lake` CLI and server dependencies.                                                                                               |
| Load the demo   | `uv run grc-lake fixtures load --company golden --out build/lakehouse --rebase-times` | Bronze, silver, and gold lake files, the SQLite mart, and synthetic demo tasks, risks, a policy, vendor assessments, and metrics history. |
| Check posture   | `uv run grc-lake assessment status --lake build/lakehouse`                            | Scores, failing controls, and findings in the terminal.                                                                                   |
| Freeze evidence | `uv run grc-lake assessment snapshot --lake build/lakehouse --reason vendor_review`   | An immutable `gold/snapshots/assessment-*.json`.                                                                                          |
| Open the app    | `make demo-local`                                                                     | The console at `http://127.0.0.1:8787/console/dashboard/`.                                                                                |

The demo fixture is synthetic and includes failing controls on purpose, so the
findings, evidence, and remediation pages have something to show. `make
demo-local` disables authentication; a shared environment needs
[server auth](SERVER_AUTH.md).

## Console map

The navigation follows the flow: collect evidence, evaluate it, resolve what
fails, then review and export.

| Group           | Page           | What you do there                                                                     |
| --------------- | -------------- | ------------------------------------------------------------------------------------- |
| Overview        | Overview       | Read the assessment score, control pass rate, open findings, and evidence to refresh. |
| Overview        | Insights       | Follow posture and findings trends over time.                                         |
| Collect         | Connections    | Connect a read-only source: test, enable, sync.                                       |
| Collect         | Evidence       | Inspect normalized evidence rows and verify each row's hash.                          |
| Collect         | Access reviews | Run access certification campaigns.                                                   |
| Collect         | Vendor risk    | Record vendor questionnaires and assessments.                                         |
| Evaluate        | Controls       | See each control's result and the evidence behind it.                                 |
| Evaluate        | Frameworks     | Check requirement coverage and readiness gates per framework pack.                    |
| Evaluate        | Mapping review | Approve, reject, or send back safeguard-to-requirement mappings, with a logged trail. |
| Evaluate        | Findings       | Triage failing checks: assign, set a due date, record a note.                         |
| Evaluate        | Risk register  | Track risks with severity, owner, and status.                                         |
| Evaluate        | Policies       | Publish policies from templates and collect acknowledgments.                          |
| Evaluate        | AI governance  | Review AI assets and their governance controls.                                       |
| Evaluate        | Crosswalk      | Compare how requirements line up across frameworks.                                   |
| Evaluate        | Graph          | Trace framework → control → evidence → asset paths.                                   |
| Resolve         | Remediation    | Work tasks, evidence requests, and exceptions.                                        |
| Resolve         | Workflows      | Build and run automation on a canvas.                                                 |
| Resolve         | Agents         | Review agent runs and approve or reject their proposed decisions.                     |
| Review & export | Audit room     | Check audit readiness, freshness SLAs, snapshots, and blocking gaps.                  |
| Review & export | Trust center   | Share scoped, expiring views with auditors and customers.                             |
| Review & export | Audit log      | Read the record of who did what.                                                      |
| Settings        | Access & keys  | Manage users, invitations, and API keys.                                              |
| Settings        | Deploy         | Deployment guidance for your environment.                                             |

## Headless

Every page reads the same `/api/v1` resources that agents and CI use:

```bash
curl -s http://127.0.0.1:8787/api/v1/posture/current | jq .data.posture
curl -s 'http://127.0.0.1:8787/api/v1/control-tests?result=fail&limit=10' | jq .
grc-lake connectors list
grc-lake frameworks review --help
```

See the [agent API](api/AGENT_API.md), [headless GRC](HEADLESS_GRC.md), the
[connector catalog](CONNECTORS.md), and the [deployment guide](../deploy/README.md).
