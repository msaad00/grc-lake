import { expect, test } from "@playwright/test";

test("crosswalk mappings are paginated and the page stays scannable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/crosswalk/");
  const status = page.getByText(/^Showing 1–25 of \d+ mappings$/);
  await expect(status).toBeVisible();

  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByText(/^Showing 26–50 of \d+ mappings$/)).toBeVisible();

  await page
    .getByPlaceholder(/search/i)
    .first()
    .fill("CC6.1");
  await expect(page.getByText(/^Showing 1–\d+ of \d+ mappings$/)).toBeVisible();

  await page
    .getByPlaceholder(/search/i)
    .first()
    .fill("");
  await page
    .locator("details")
    .evaluateAll((els) =>
      els.forEach((el) => ((el as HTMLDetailsElement).open = true)),
    );
  const height = await page.evaluate(
    () => document.documentElement.scrollHeight,
  );
  expect(height).toBeLessThan(12000);
});

test("equivalence groups and overlap matrices stay bounded as frameworks grow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/crosswalk/");
  await expect(page.getByText(/^Showing 1–25 of \d+ mappings$/)).toBeVisible();

  const groups = page.locator("#equivalence-groups > div.rounded-lg");
  const toggle = page.getByRole("button", { name: /^Show all \d+ groups$/ });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(groups).toHaveCount(6);
  const total = Number((await toggle.textContent())?.match(/\d+/)?.[0]);
  expect(total).toBeGreaterThan(6);
  await toggle.click();
  await expect(groups).toHaveCount(total);
  const collapse = page.getByRole("button", { name: "Show fewer groups" });
  await expect(collapse).toHaveAttribute("aria-expanded", "true");
  await collapse.click();
  await expect(groups).toHaveCount(6);

  await page
    .locator("details")
    .evaluateAll((els) =>
      els.forEach((el) => ((el as HTMLDetailsElement).open = true)),
    );
  for (const name of [
    "Reviewed framework overlap matrix",
    "Heuristic domain overlap matrix",
  ]) {
    const region = page.getByRole("region", { name });
    await expect(region).toHaveAttribute("tabindex", "0");
    const box = await region.evaluate((el) => ({
      client: el.clientHeight,
      scroll: el.scrollHeight,
      clientWidth: el.clientWidth,
      scrollWidth: el.scrollWidth,
    }));
    expect(box.client).toBeLessThanOrEqual(700);
    expect(box.scroll).toBeGreaterThan(box.client);
    expect(box.scrollWidth).toBeGreaterThan(box.clientWidth);
    const firstColumn = region.locator("tbody th").first();
    await expect(firstColumn).toHaveCSS("position", "sticky");
    const before = await firstColumn.boundingBox();
    await region.evaluate((el) => {
      el.scrollLeft = 400;
    });
    const after = await firstColumn.boundingBox();
    expect(after?.x).toBe(before?.x);
  }
});
