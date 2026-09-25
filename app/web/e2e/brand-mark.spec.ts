import { expect, test } from "@playwright/test";

const MARKS =
  'header svg[aria-label="TrustOps"], aside svg[aria-label="TrustOps"], nav[aria-label="Breadcrumb"] svg[aria-label="TrustOps"]';

test("the app shell shows the brand mark once, in the top bar", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  await expect(
    page.getByRole("heading", { name: "Dashboard", exact: true }),
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
  // A top-level page's breadcrumb would only repeat its own title.
  await expect(
    page.getByRole("navigation", { name: "Breadcrumb" }),
  ).toHaveCount(0);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("button", { name: "Sidebar is compact on small screens" }),
  ).toBeVisible();
  await expect(marks).toHaveCount(1);
});
