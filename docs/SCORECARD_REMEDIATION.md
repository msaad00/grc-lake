# Scorecard evidence and remediation

A successful Scorecard workflow uploads observations; it does not mean every
check passes. Keep the SARIF finding open until its underlying evidence changes.
See the [Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md).

| Check              | Required evidence                                                                   | Closure boundary                                                                                                      |
| ------------------ | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Code-Review        | Independent human approval of changes, plus required pull-request review policy     | Bot reviews and a policy change do not retroactively approve past changes. Scorecard inspects recent merged changes.  |
| Fuzzing            | A recognized fuzz integration that builds real targets and runs against the project | A workflow file alone is not proof of a successful fuzz run. Confirm build, execution, and the next main-branch scan. |
| CII-Best-Practices | A project entry in the OpenSSF Best Practices program with supported responses      | Repository documents alone do not register or earn a badge. Do not claim a badge until its public record exists.      |

## Best Practices registration evidence

A maintainer can use the following repository sources while completing the
[passing-badge criteria](https://www.bestpractices.dev/en/criteria/0):

- Project purpose and installation: `README.md` and `docs/`.
- License: `LICENSE`; contribution and test policy: `CONTRIBUTING.md`.
- Change history: Git history, `CHANGELOG.md`, and published release tags.
- Reporting: GitHub issues and `SECURITY.md` for vulnerability reporting.
- Build and validation: `Makefile`, `.github/workflows/ci.yml`, and `tests/`.
- Static analysis: `.github/workflows/codeql.yml` and security checks in CI.

These are evidence pointers, not completed questionnaire answers. Maintainers
must separately verify response-time history, security expertise, cryptographic
practices, and unresolved vulnerability age. Register the current repository URL
and verify the resulting badge through the program's public project record.
