# Evidence evaluation semantics

An `observed` record describes collected inventory or an activity. It supplies
provenance and evidence types but does not establish a passing control. Alongside
evaluated evidence, it does not override the verdict or count toward rule evidence
presence/coverage predicates. Aggregate event and evidence counts still include
observations. Observation-only controls remain unevaluated; explicit unknown
and unevaluated outcomes still prevent a pass. An empty dataset has a zero
control pass rate. These changes affect newly evaluated generations; historical
evidence is retained. Manifests record `trustops.control_evaluation.v7`; the
incremental dependency fingerprint forces re-evaluation of older generations even
when raw inputs have not changed, while retaining the earlier generation.

Control failure follows the declared evaluation rule. For example, an open
low-severity finding does not fail a high-severity-only rule, while an open
violation rule does fail it. Unknown evidence and missing/future/stale collection
evidence can still prevent a pass. Downstream control-test results retain this
rule outcome rather than applying a second unconditional open-finding rule.

Catalog controls and explicitly bound CCF safeguards use the same rule-aware
verdict function. Observation rows cannot supply verdict evidence or override a
passing verdict; a bronze pointer is not proof that source evidence was supplied.
Freshness uses the latest observation per source tenant, connector, source, asset,
and evidence type. A fresh observation cannot mask another population's stale
evidence. CCF applicability, unobserved assets, and mapping-review requirements
remain additional gates; agreement is expected for identical rules and scope,
not for differently scoped requirements.

Program control tests can require more evidence types than a catalog control.
Materialized controls, program tests, current assessments, and reviewed CCF
requirements retain the union of catalog and applicable program evidence types.
A passing predicate alone does not clear a missing-evidence requirement. A
confirmed failure still takes precedence; missing evidence does not turn an
observation into an evaluated failure. AI framework summaries recheck current
evidence freshness and weight their aggregate by control counts, not pack counts.

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

Current framework scores are `100 × fresh passing controls / observed controls`.
Failing, stale, unknown and observation-only controls receive no credit. The
assessment score uses the same counts across frameworks, avoiding rounding
artifacts from intermediate framework percentages. A Ready state requires every
observed control to pass with current evidence. Catalog coverage is separate:
100% within a small observed scope does not establish full framework coverage.

Severity remains available in violation and control-risk metrics; passing
observations do not increase failure risk. A newly failing control cannot improve
the score, and refreshing a stale/unknown control into a failure grants no credit.
New assessments and snapshots identify `trustops.assessment_scoring.v2` with
`score_scope: observed_controls`. Historical snapshots retain their original
scores and metadata; snapshots without a scoring version used the legacy formula
and must not be treated as directly comparable score trends across this change.

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

## Connector applicability and provider fields

MFA observations for suspended/deprovisioned identities and AWS users without a
console password are not passing evidence. They remain observations outside the
checked population; unknown lifecycle or enrollment fields remain unevaluated.
Active applicable identities require affirmative enrollment evidence to pass.
See the [AWS console-MFA scope](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html),
[Okta lifecycle statuses](https://developer.okta.com/okta-sdk-java/20.0.1/apidocs/com/okta/sdk/resource/model/UserStatus.html),
and [Google Directory enrollment fields](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

GCP organization-policy v2 resource names and fixture constraint names resolve
to the same constraint. Only a recognized relevant constraint with an explicit
unconditional boolean enforcement rule establishes this policy signal's pass.
Conditional, reset and unsupported rule shapes remain unevaluated; unrelated
constraints remain observations. This does not prove the effective inherited
policy or the state of existing resources. See [GCP policy rules](https://docs.cloud.google.com/organization-policy/create-organization-policies).

## Collection and version boundaries

Inventory is an observation. AWS CloudTrail's explicit `multi_region=false`
setting is a finding; the presence of a resource is not a pass. Runtime gateway
blocked/denied/rejected events retain their original status in attributes and
count as observations of enforcement. Okta factor-read errors remain unknown;
a security question alone does not establish independent-factor enrollment.
Pagination exhaustion fails collection rather than silently returning a complete
result. These contracts are fixture-tested; they do not qualify a live provider.

A bronze pointer always preserves lineage. `evidence_available` separately records
whether source evidence was supplied, so a missing-evidence rule can fail even
when the raw record remains inspectable. Framework risk scores use the same
per-control aggregate regardless of the detail cap.

Connectors can declare `options.safeguard_bindings`, an object mapping an exact
event type to a list of safeguard IDs. Bindings must match the safeguard's asset
types. For example, an operator may explicitly bind `iam.access_review` to
`SG-IDENTITY-001`. Framework tags alone never create safeguard assertions. Review
this configuration against the source contract; it is not automatic assurance.

Mapping decisions pin the control and mapping definitions. Changes require a new
organization review. Shipped mappings carry their control version, retaining
historical versions where the catalog records them; mismatched versions become
proposed. The `fedramp-moderate` compatibility ID labels the NIST SP 800-53B
Moderate baseline only, without the FedRAMP overlay or an authorization claim.

## Connector verdict boundaries

Jira terminal status alone does not establish remediation. A done-category issue
passes only with an explicit Fixed, Done, or Resolved resolution; cancellation,
duplication, Won't Do, and unknown resolutions remain unevaluated. Transition
activity remains an observation. See [Jira resolutions](https://support.atlassian.com/jira-cloud-administration/docs/what-is-a-resolution-in-jira/).

Azure role assignments whose role definitions cannot be resolved remain
unevaluated. The published Owner, Contributor, and User Access Administrator
built-in IDs can identify those privileged roles even when their display names
are absent. See [Azure privileged roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged).

Kubernetes workload checks report added Linux capabilities outside the
[Pod Security Baseline allowlist](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
for application, init, and ephemeral containers. This is a bounded configuration
check, not a complete Restricted-profile assessment.

S3, Snowflake, and ClickHouse evidence readers preserve an explicit control
mapping instead of adding unrelated defaults. A list of nonempty strings or a
comma/pipe-delimited string is accepted. Empty or malformed explicit mappings
are rejected; default mappings apply only when no mapping field was provided.
