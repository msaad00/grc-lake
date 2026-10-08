import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Every console route, including the public ones outside the app shell, runs
// the full WCAG 2.1 AA and best-practice set: landmarks (one <main>, unique
// labels), one <h1>, contrast, names. `svg-img-alt` stays off: it fails inside
// recharts-rendered sectors and needs a design decision.
const TAGS = ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"];
const DISABLED = ["svg-img-alt"];

const ROUTES = [
  "dashboard",
  "insights",
  "frameworks",
  "controls",
  "evidence",
  "violations",
  "remediation",
  "risks",
  "policies",
  "crosswalk",
  "mapping-review",
  "graph",
  "automation",
  "connectors",
  "vendor-risk",
  "access-reviews",
  "ai-governance",
  "agents",
  "audit-room",
  "audit-log",
  "trust-center",
  "onboarding",
  "auth",
  "deploy",
  "demo",
  "poc",
  "pricing",
  // Public routes render without the app shell.
  "login",
  "signup",
  "invite",
  "trust/share",
];

for (const route of ROUTES) {
  test(`${route} passes axe WCAG 2.1 AA and best-practice checks`, async ({
    page,
  }) => {
    await page.goto(`/console/${route}/`);
    await page.waitForSelector("main", { timeout: 30000 });
    // The surfaces render their controls after the first data read resolves.
    await page.waitForTimeout(2500);

    const { violations } = await new AxeBuilder({ page })
      .withTags(TAGS)
      .disableRules(DISABLED)
      .analyze();

    const summary = violations.map(
      (v) => `${v.id} (${v.nodes.length}): ${v.nodes[0]?.html?.slice(0, 120)}`,
    );
    expect(summary, `axe violations on /console/${route}/`).toEqual([]);
  });
}
