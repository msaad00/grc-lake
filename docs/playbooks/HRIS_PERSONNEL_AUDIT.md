# HRIS personnel audit playbook

The `bamboohr-personnel`, `rippling-personnel`, and `workday-personnel` connectors bring employment records (status, hire and termination dates) into the lake ([CONNECTORS.md](../CONNECTORS.md#bamboohr-employment-records)). With Okta or Google Workspace also connected, the [offboarding check](../CONNECTORS.md#offboarding-check-hr-terminations--idp-accounts) flags any terminated employee whose account can still sign in. Use this playbook for identity providers GRC Lake does not read yet and for access-review evidence. Device posture comes from the `intune-devices` MDM connector ([CONNECTORS.md](../CONNECTORS.md#microsoft-intune-device-posture)).

## When to use this playbook

- Auditors ask for **hire / transfer / terminate** evidence
- You need **role-appropriate access** proof without Workday/Rippling integration
- ISO **A.6.1–A.6.5** or SOC 2 **CC1.4 / CC6.x** personnel themes are in scope

## Prerequisites

| Connector                                      | Purpose                                      |
| ---------------------------------------------- | -------------------------------------------- |
| `okta-identity` or `google-workspace-identity` | Authoritative user roster + group membership |
| `github-security` / `gitlab-security`          | Repo access for engineering population       |
| Optional `aws-posture` / `azure-posture`       | Cloud role assignments                       |

Run at least one successful sync per connector before starting a campaign.

## Workflow

### 1. Establish population

1. Open **Connectors** → confirm identity provider sync is **fresh** (SLO green).
2. Open **Evidence** → filter `source` = your IdP → export or tag rows for the audit period.
3. Document any contractors in a spreadsheet; attach as vendor evidence if outside IdP.

### 2. Launch access review campaign

1. Open **Access reviews** → **Create campaign**.
2. Name: `Q{quarter}-personnel-{year}` (e.g. `Q2-personnel-2026`).
3. **Seed** from IdP groups or manual CSV if groups are incomplete.
4. Assign certifiers = line managers or control owners from the control catalog.

### 3. Certify and capture proof

1. Certifiers approve or revoke each item in the campaign.
2. Export campaign decisions from **Access reviews** (API: `GET /api/v1/access-reviews/{id}`).
3. Link decisions to controls in **Remediation** → **Evidence requests** if gaps remain.

### 4. Close gaps

| Gap                       | Action                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Stale IdP sync            | Re-sync connector; check **Evidence freshness SLA** panel              |
| Orphan accounts           | Create remediation task; revoke in IdP; re-sync                        |
| Missing termination proof | Attach HR export manually to evidence room; tag `personnel`            |
| Repo access drift         | Run GitHub/GitLab governance sync; inspect **Graph → Repository** mode |

### 5. Auditor package

Include in the audit room export or trust share:

- Access review campaign summary (open + completed)
- IdP sync health + latest `evidence_collected_at`
- List of exceptions with approver and expiry
- POA&M items for any overdue certifications

API shortcut for agents:

```text
list_access_reviews
get_access_review
get_audit_readiness
list_evidence_freshness?status=stale
```

## Control mapping (examples)

| Theme                    | Example controls           | Primary evidence                           |
| ------------------------ | -------------------------- | ------------------------------------------ |
| Screening / terms        | ISO27001-A.6.1, SOC2-CC1.4 | HR policy attestation + manual hire packet |
| Access during employment | ISO27001-A.6.2, SOC2-CC6.1 | IdP groups + access review campaign        |
| Termination              | ISO27001-A.6.5, SOC2-CC6.2 | IdP deprovision events + ticket closure    |

## Roadmap

BambooHR, Rippling, and Workday connectors and the HR ↔ IdP offboarding check (Okta, Google Workspace) ship. Offboarding coverage is only as complete as the connected identity providers — do not claim it for systems GRC Lake does not read.

See also [AUDIT_READINESS.md](../AUDIT_READINESS.md).
