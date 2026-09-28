## Summary

<!-- What changed and why. Link the issue: "Closes #123". -->

-

## Verification

<!-- Tick what you ran and paste anything notable. See CONTRIBUTING.md for which checks fit which change. -->

- [ ] `make lint format-check` and the touched tests (`python -m pytest -q tests/test_<name>.py`)
- [ ] `make smoke` (catalogs, fixtures, pipeline, API)
- [ ] `make web-ci` (console changes)
- [ ] `make validate-doc-images validate-brand` (docs images or brand assets)
- [ ] `make pre-commit-run`
- [ ] Screenshots in light and dark mode (console changes)

## Checklist

- [ ] New behavior or a bug fix has a test that fails without the change.
- [ ] Docs, API contract, and console agree with the change.
- [ ] No framework, connector, or control is described as covered or live-verified beyond what the catalog and tests support.
- [ ] No secrets, tokens, or real customer evidence in code, fixtures, logs, or screenshots.
