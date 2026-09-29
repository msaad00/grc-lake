import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Rules this console satisfies and must keep satisfying. `svg-img-alt` stays
// off: it fails inside recharts-rendered sectors and needs a design decision.
const RULES = [
  "color-contrast",
  "select-name",
  "label",
  "button-name",
  "link-name",
  "scrollable-region-focusable",
  "aria-required-attr",
  "aria-valid-attr-value",
  "duplicate-id-aria",
  "image-alt",
];

const ROUTES = [
  "dashboard",
  "violations",
  "evidence",
  "controls",
  "remediation",
  "risks",
  "graph",
  "crosswalk",
  "mapping-review",
  "automation",
  "trust-center",
  "agents",
  "frameworks",
  "auth",
];

for (const route of ROUTES) {
  test(`${route} has no form controls or regions the keyboard cannot reach`, async ({
    page,
  }) => {
    await page.goto(`/console/${route}/`);
    await page.waitForSelector("main", { timeout: 30000 });
    // The surfaces render their controls after the first data read resolves.
    await page.waitForTimeout(2500);

    const { violations } = await new AxeBuilder({ page })
      .withRules(RULES)
      .analyze();

    const summary = violations.map(
      (v) => `${v.id} (${v.nodes.length}): ${v.nodes[0]?.html?.slice(0, 120)}`,
    );
    expect(summary, `axe violations on /console/${route}/`).toEqual([]);
  });
}
