# Dependency security scope

Reviewed 2026-10-03. Dependency advisories change; rerun both production and full
build-tool audits when reviewing or upgrading the lockfiles.

```bash
uv export --frozen --all-extras --no-emit-project --format requirements-txt --no-hashes > /tmp/trustops-requirements.txt
uv run pip-audit --strict -r /tmp/trustops-requirements.txt
cd app/web
npm audit --omit=dev --audit-level=high
npm audit
```

## Open build-tool advisory

[GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
(CVE-2026-93687) affects `braces <=3.0.3`: deeply nested brace patterns can exhaust
the stack. The advisory lists no patched release as of this review. The full npm
audit reports seven affected dependency nodes stemming from this one advisory,
including Tailwind 3 and the Next.js ESLint plugin through globbing dependencies.
This finding remains open; a clean production audit does not close it.

The repository's runtime image contains the Python environment and static browser
assets, not the Node build environment or its `node_modules`. The affected tools
run when building and linting repository content. The current CI uses time-bounded
jobs with read-only repository permissions; pull-request build content must be
treated as untrusted. Keep builds isolated from deployment credentials and do not
feed externally supplied glob patterns into these tools. These measures constrain
exposure but do not patch the vulnerable parser.

CI blocks known Python vulnerabilities and high-or-critical production npm
vulnerabilities. It also retains the full npm audit as a separate, non-blocking
build-tool report. A successful CI result is not a claim of zero development
dependency advisories. Do not silence this advisory or force unrelated major
upgrades to produce a clean audit. Close it only after a patched dependency chain
or verified replacement passes lint, typechecking, the static build, and browser
regressions. Recheck the upstream advisory during each dependency update.
