# Evidence evaluation semantics

An `observed` record describes collected inventory or an activity. It supplies
provenance and evidence types but does not establish a passing control. Alongside
evaluated evidence, it does not override the verdict or count toward rule evidence
presence/coverage predicates. Aggregate event and evidence counts still include
observations. Observation-only controls remain unevaluated; explicit unknown
and unevaluated outcomes still prevent a pass. An empty dataset has a zero
control pass rate. These changes affect newly evaluated generations; historical
evidence is retained. Manifests record `trustops.control_evaluation.v3`; the
incremental dependency fingerprint forces re-evaluation of older generations even
when raw inputs have not changed, while retaining the earlier generation.

Control failure follows the declared evaluation rule. For example, an open
low-severity finding does not fail a high-severity-only rule, while an open
violation rule does fail it. Unknown evidence and missing/future/stale collection
evidence can still prevent a pass. Downstream control-test results retain this
rule outcome rather than applying a second unconditional open-finding rule.

Workpapers include declared assets with valid, explicitly bound safeguard
observations by the assessment cutoff, even if those observations fall outside
the testing period. Missing period samples become gaps. Unrelated assets are not
assigned to every safeguard. Standalone plans without a declared population
retain their observed-period scope; neither scope proves inventory completeness.
The result reports observed and expected asset counts and the declared population
hash separately.

## Provider observations and findings

- Okta System Log login outcomes, including `FAILURE`, are activity observations.
  A failed authentication attempt alone does not establish a broken control.
- Kubernetes cluster-admin grants to all authenticated users, unauthenticated
  users, anonymous users, or all service accounts are reviewable findings.
  The built-in `system:masters` group remains inventory. Kubernetes documents
  [authentication identities](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
  and [RBAC scope](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
- GCP IAM collection requests policy version 3 and retains conditions. Conditional
  bindings have distinct identities; existing unconditional binding IDs remain
  stable. Public members (`allUsers` and `allAuthenticatedUsers`) are reviewable
  findings even with non-privileged roles. Expressions are retained for human
  review, not evaluated as proof of effective access. See the
  [policy contract](https://docs.cloud.google.com/iam/docs/reference/rest/v1/Policy)
  and [conditional policy reads](https://docs.cloud.google.com/iam/docs/managing-conditional-role-bindings).
- Azure privileged root, management-group and subscription assignments are broad
  grants requiring review. Resource-group grants and non-privileged roles remain
  inventory in this rule. See the
  [Azure scope hierarchy](https://learn.microsoft.com/en-gb/azure/role-based-access-control/scope-overview).
- Repository security findings retain the highest known severity among open
  alerts. Closed/dismissed alerts do not raise the open severity. Collection
  failures and inventory-only records cannot establish passing evidence. See
  [GitHub code scanning alerts](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning-alerts).

These rules are bounded signal classifications, not comprehensive provider
security assessments or authenticated deployment qualification.

## Scores and external summaries

SPRS reports distinguish passing, failing, and unevaluated requirements. Missing,
observed, stale, or conflicting evidence does not count as met. An incomplete
assessment returns `score: null` and `assessment_complete: false`; known failure
deductions remain available. A complete assessment retains the weighted score.
Metrics count explicit current passes, with a zero pass rate when no controls
are present.

Public framework shares expose only the selected framework and derive their
summary from that subset. Their issuer comes from the authenticated principal.
Observed control counts, evaluated counts, catalog counts, and coverage ratios
are separate: limited evidence is labeled `partial_evidence`, not full framework
readiness. Catalog coverage does not establish inventory completeness or an
auditor's opinion.

New evidence timestamps must normalize to UTC years 0002 through 9998, reserving
boundary years for freshness expiry and grace arithmetic. Validation rejects
out-of-range timestamps before normalization or pipeline writes.
