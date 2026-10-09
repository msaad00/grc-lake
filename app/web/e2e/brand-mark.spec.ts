import { expect, test } from "@playwright/test";

const MARKS =
  'header svg[aria-label="TrustOps"], aside svg[aria-label="TrustOps"], [role="dialog"] svg[aria-label="TrustOps"]';

test("the app shell shows the brand mark once, in the top bar", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  await expect(
    page.getByRole("heading", { level: 1, name: "Overview", exact: true }),
  ).toBeVisible();

  const marks = page.locator(MARKS);
  await expect(marks).toHaveCount(1);
  await expect(page.locator('header svg[aria-label="TrustOps"]')).toHaveCount(
    1,
  );
  // At 32px the source glyphs blur into specks: the bar mark is waves only.
  const header = page.locator('header svg[aria-label="TrustOps"]');
  await expect(header).toHaveAttribute("data-variant", "simple");
  expect(await header.locator("circle, rect[rx='3']").count()).toBe(0);
  expect(await header.locator("path").count()).toBe(1);
  await expect(
    page.getByRole("navigation", { name: "Breadcrumb" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "Overview" }).first(),
  ).toHaveAttribute("aria-current", "page");

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator("aside").first()).toBeHidden();
  await page.getByRole("button", { name: "Open navigation" }).click();
  const drawer = page.getByRole("dialog", { name: "Navigation" });
  await expect(drawer).toBeVisible();
  await expect(marks).toHaveCount(1);
  await drawer.getByRole("link", { name: "Graph" }).click();
  await expect(page).toHaveURL(/\/console\/graph\/?/);
  await expect(drawer).toBeHidden();
});

test("marks at 40px and below draw the waves only", async ({ page }) => {
  await page.goto("/console/agents/");
  const marks = page.locator('svg[aria-label="TrustOps"]');
  await expect(marks.first()).toBeVisible({ timeout: 20_000 });
  const sizes = await marks.evaluateAll((nodes) =>
    nodes.map((node) => ({
      size: Math.round(node.getBoundingClientRect().width),
      variant: node.getAttribute("data-variant"),
      glyphs: node.querySelectorAll("circle").length,
    })),
  );
  expect(sizes.length).toBeGreaterThan(1);
  for (const mark of sizes.filter((m) => m.size > 0 && m.size <= 40)) {
    expect(mark.variant).toBe("simple");
    expect(mark.glyphs).toBe(0);
  }
});
