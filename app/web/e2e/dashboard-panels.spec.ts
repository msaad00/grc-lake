import { expect, test } from "@playwright/test";

test("dashboard panels switch independently, support keyboard tabs, and retain collapse state", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/dashboard/");
  const compliance = page.getByRole("tablist", {
    name: "Framework coverage views",
  });
  const operations = page.getByRole("tablist", {
    name: "Priority actions views",
  });
  await expect(compliance).toBeVisible();
  const left = await compliance.boundingBox();
  const right = await operations.boundingBox();
  expect(right!.x).toBeGreaterThan(left!.x + left!.width);
  await page
    .getByRole("tab", { name: "Control families", exact: true })
    .click();
  await expect(
    page.getByRole("tab", { name: "Findings", exact: true }),
  ).toHaveAttribute("aria-selected", "true");
  await page
    .getByRole("tab", { name: "Control families", exact: true })
    .press("ArrowRight");
  await expect(
    page.getByRole("tab", { name: "Test results", exact: true }),
  ).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Sources", exact: true }).click();
  await expect(
    page.getByRole("tab", { name: "Sources", exact: true }),
  ).toHaveAttribute("aria-selected", "true");
  // Export status lives once, in the header line; no duplicate Exports tab.
  await expect(page.getByRole("tab", { name: "Exports" })).toHaveCount(0);
  await page
    .getByRole("button", { name: "Framework coverage", exact: true })
    .click();
  await expect(compliance).toBeHidden();
  await expect(operations).toBeVisible();
  await page
    .getByRole("button", { name: "Framework coverage", exact: true })
    .click();
  await expect(
    page.getByRole("tab", { name: "Test results", exact: true }),
  ).toHaveAttribute("aria-selected", "true");
  await page
    .getByRole("button", { name: "Framework coverage", exact: true })
    .click();
  await page.reload();
  await expect(
    page.getByRole("button", { name: "Framework coverage", exact: true }),
  ).toHaveAttribute("aria-expanded", "false");
});

test("dashboard panels stack on mobile without page overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/console/dashboard/");
  const compliance = page.getByRole("tablist", {
    name: "Framework coverage views",
  });
  const operations = page.getByRole("tablist", {
    name: "Priority actions views",
  });
  await expect(operations).toBeVisible();
  expect((await operations.boundingBox())!.y).toBeGreaterThan(
    (await compliance.boundingBox())!.y,
  );
  for (const label of [
    "Control families",
    "Test results",
    "Sources",
    "Frameworks",
  ]) {
    await page.getByRole("tab", { name: label, exact: true }).click();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  }
});
