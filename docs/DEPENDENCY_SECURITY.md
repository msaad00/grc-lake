# Dependency security scope

Reviewed 2026-10-07. Dependency advisories change; rerun both production and full
build-tool audits when reviewing or upgrading the lockfiles.

```bash
uv export --frozen --all-extras --no-emit-project --format requirements-txt --no-hashes > /tmp/grc-lake-requirements.txt
uv run pip-audit --strict -r /tmp/grc-lake-requirements.txt
cd app/web
npm audit --omit=dev --audit-level=high
npm audit
```

## Patched template lookup

The Python lockfile uses Mako 1.4.3, above the 1.4.2 fix for Windows drive-letter
path traversal in `TemplateLookup`. Mako is used by Alembic migration tooling.
The server and development extras require Mako 1.4.3 or newer so package
upgrades also replace vulnerable versions in existing environments.

## Patched selector parser

[GHSA-rj75-hqrm-r3gf](https://github.com/advisories/GHSA-rj75-hqrm-r3gf)
(CVE-2026-104844) affects `postcss-selector-parser <7.1.6`: flat selector input can
cause quadratic CPU usage. Scoped npm overrides pin the copies used by Tailwind 3
and `postcss-nested` to patched version `7.1.6`. This removes the two affected
moderate dependency nodes without changing the Tailwind major version.

The console's static build produces byte-for-byte identical CSS before and after
the override. Keep lint, typechecking, static builds, and browser regressions in
the validation path. Remove the overrides once both upstream dependency ranges
resolve to a patched parser without them, and regenerate the lockfile.

## Bounded braces replacement

[GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
(CVE-2026-93687) affects `braces <=3.0.3`: deeply nested brace patterns can exhaust
the stack. There is still no official patched upstream release. The console
uses an exact npm override to
[`@dieub/braces-depth-guard@3.0.3-pn.3`](https://www.npmjs.com/package/@dieub/braces-depth-guard/v/3.0.3-pn.3),
a separately maintained MIT-licensed derivative of braces 3.0.3.

The reviewed package caps brace/parenthesis nesting and recursive AST traversal
at 100 levels. Excessive string nesting raises a controlled `SyntaxError`;
excessive direct AST depth raises a controlled `RangeError`. It retains ordinary
alternatives, ranges, escapes, and stringify behavior. This intentionally rejects
patterns deeper than 100 rather than allowing JavaScript stack exhaustion. It
does not establish general bounds on expansion cardinality, AST width, arbitrary
malformed objects, or regular-expression complexity.

The initial adoption review compared the published runtime files with both
upstream 3.0.3 and derivative source commit
[`305a2e4bfe324bb53c336c1b03387ee1251c926f`](https://github.com/dieub/braces-depth-guard/tree/305a2e4bfe324bb53c336c1b03387ee1251c926f).
The tarball matches that tagged source; registry signatures and publishing
provenance verify with `npm audit signatures`. The lockfile records the tarball
SHA-512 integrity. There are no install lifecycle scripts in the replacement.
Do not replace this exact pin with a floating range without reviewing the new
artifact and provenance.

`npm run test:dependencies` exercises the copies resolved by micromatch and
chokidar: 100/101 boundaries, 4,000-level inputs in a small-stack child process,
direct ASTs, stricter limits, and ordinary syntax. A clean npm audit alone does
not establish that a renamed dependency fixes the issue. Keep these behavioral
regressions, lint, typechecking, static builds, and browser checks in the gate.
Remove the override only when an official patched upstream dependency chain
passes those checks.

The runtime image contains Python and static browser assets, not the Node build
environment. CI blocks known Python vulnerabilities and high-or-critical npm
vulnerabilities across both production and development dependencies, and retains
the complete npm audit report. Builds still process untrusted repository content
and must remain isolated from deployment credentials.
