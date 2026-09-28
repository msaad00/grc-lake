import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Rules this console currently satisfies and must keep satisfying. Scoped
// deliberately: `color-contrast` still fails (the brand accent #4f7cff reads
// 3.71 on white against a required 4.5) and `svg-img-alt` fails inside
// recharts-rendered sectors. Both need a design decision rather than a code
// fix, so enabling them here would land a permanently red test.
const RULES = [
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
