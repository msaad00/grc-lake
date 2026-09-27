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
  await expect
    .poll(() =>
      marks.evaluateAll((nodes) =>
        nodes.every(
          (node) => node.querySelectorAll("g[transform]").length === 4,
        ),
      ),
    )
    .toBe(true);
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
