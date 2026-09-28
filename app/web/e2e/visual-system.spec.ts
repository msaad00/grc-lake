import { expect, test, type Page } from "@playwright/test";

/** WCAG contrast between an element's text colour and its nearest opaque background. */
async function contrastOf(page: Page, selector: string) {
  return page
    .locator(selector)
    .first()
    .evaluate((el) => {
      const parse = (value: string) => {
        const m = value.match(/rgba?\(([^)]+)\)/);
        if (!m) return null;
        const [r, g, b, a = 1] = m[1]
          .split(/[ ,/]+/)
          .filter(Boolean)
          .map(Number);
        return { r, g, b, a };
      };
      const lum = ({ r, g, b }: { r: number; g: number; b: number }) => {
        const c = [r, g, b].map((v) => {
          const s = v / 255;
          return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
      };
      const fg = parse(getComputedStyle(el).color)!;
      let node: Element | null = el;
      let bg = null;
      while (node) {
        const candidate = parse(getComputedStyle(node).backgroundColor);
        if (candidate && candidate.a >= 0.99) {
          bg = candidate;
          break;
        }
        node = node.parentElement;
      }
      bg ??= { r: 255, g: 255, b: 255, a: 1 };
      const [hi, lo] = [lum(fg), lum(bg)].sort((a, b) => b - a);
      return (hi + 0.05) / (lo + 0.05);
    });
}

async function backgroundOf(page: Page, selector: string) {
  return page
    .locator(selector)
    .first()
    .evaluate((el) => getComputedStyle(el).backgroundColor);
}

for (const theme of ["light", "dark"] as const) {
  test(`${theme} theme: elevation steps and AA text contrast`, async ({
    page,
  }) => {
    await page.addInitScript((mode) => {
      window.localStorage.setItem("trustops:theme", JSON.stringify(mode));
    }, theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/console/dashboard/");
    const overview = page.getByRole("region", { name: "Current assessment" });
    await expect(overview).toBeVisible({ timeout: 20_000 });
    if (theme === "dark")
      await expect(page.locator("html")).toHaveClass(/dark/);

    // Page, rail and card are three distinct surfaces.
    const surfaces = new Set([
      await backgroundOf(page, "body"),
      await backgroundOf(page, "aside"),
      await backgroundOf(
        page,
        "section[aria-labelledby] a[href$='/controls/']",
      ),
    ]);
    expect(surfaces.size).toBe(3);

    // Body, muted, link, active nav and status chip text all clear 4.5:1.
    const checks = {
      title: "h1",
      muted: "section[aria-labelledby] a[href$='/controls/'] span.text-muted",
      activeNav: "aside a[aria-current='page']",
      statusChip: "section[aria-labelledby] .rounded-full",
      severityChip: "[aria-label='Findings to triage'] .rounded-full",
      link: "a.ui-link",
    };
    for (const [name, selector] of Object.entries(checks)) {
      const ratio = await contrastOf(page, selector);
      expect(ratio, `${name} contrast in ${theme}`).toBeGreaterThanOrEqual(4.5);
    }
  });
}

test("triage drawer groups summary, details, remediation, and actions", async ({
  page,
}) => {
  await page.goto("/console/violations/");
  await page
    .getByRole("button", { name: /Review finding/ })
    .first()
    .click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("region", { name: "Summary" })).toBeVisible();
  for (const heading of ["Details", "Remediation", "Triage history"]) {
    await expect(
      drawer.getByRole("heading", {
        level: 3,
        name: new RegExp(`^${heading}`),
      }),
    ).toBeVisible();
  }
  await expect(drawer.getByRole("group", { name: "Triage" })).toBeVisible();
  // Actions render as buttons (bordered, padded), not bare inline text links.
  for (const name of ["Create task", "Review control", "Trace in graph"]) {
    const action = drawer.getByRole("link", { name, exact: true });
    await expect(action).toBeVisible();
    const box = await action.boundingBox();
    expect(box!.height).toBeGreaterThanOrEqual(30);
    expect(
      await action.evaluate((el) => getComputedStyle(el).borderTopWidth),
    ).toBe("1px");
  }
  // Owner, environment and source live here, not on overview rows.
  const details = drawer.getByRole("region", { name: "Details" });
  for (const label of ["Owner", "Environment", "Source"]) {
    await expect(details.getByText(label, { exact: true })).toBeVisible();
  }
});

test("evidence paths name every lake reader from the connector catalog", async ({
  page,
}) => {
  const { data: connectors } = await (
    await page.request.get("/api/v1/connectors")
  ).json();
  type Lake = {
    category: string;
    vendor?: string;
    name: string;
    release_stage?: string;
  };
  const lakes = (connectors as Lake[]).filter((c) =>
    ["warehouse", "analytics_lake"].includes(c.category),
  );
  expect(lakes.length).toBeGreaterThan(2);
  await page.goto("/console/connectors/");
  const panel = page.getByRole("region", { name: "Choose an evidence path" });
  await expect(panel).toContainText(lakes[0].vendor || lakes[0].name);
  const text = (await panel.textContent()) ?? "";
  const preview = text.split("Preview:")[1]?.split(".")[0] ?? "";
  for (const lake of lakes) {
    const label = lake.vendor || lake.name;
    expect(text).toContain(label);
    expect(preview.includes(label)).toBe(lake.release_stage === "preview");
  }
});

test("connector drawer setup header spans the drawer at 390px", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/console/connectors/?connect=bamboohr-personnel");
  const progress = page.getByRole("region", { name: "Setup progress" });
  await expect(progress).toBeVisible();
  const box = await progress.boundingBox();
  const drawer = await page.getByRole("dialog").boundingBox();
  expect(box!.width).toBeGreaterThan(drawer!.width * 0.8);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});
