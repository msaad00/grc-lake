import { expect, test } from "@playwright/test";

async function fittedZoom(page: import("@playwright/test").Page) {
  const viewport = page.locator(".react-flow__viewport");
  await expect(viewport).toBeVisible();
  await page.waitForTimeout(600);
  return viewport.evaluate(
    (el) => new DOMMatrixReadOnly(getComputedStyle(el).transform).a,
  );
}

test("wide framework graphs fit at a readable zoom", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/graph/");
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  // The page opens on one control path; widen to the framework slice.
  await page.getByRole("button", { name: "Show whole framework" }).click();
  await expect
    .poll(() => page.locator(".react-flow__node").count())
    .toBeGreaterThan(60);
  expect(await fittedZoom(page)).toBeGreaterThanOrEqual(0.35);
  const boxes = await page
    .locator(".react-flow__node")
    .evaluateAll((els) => els.map((el) => el.getBoundingClientRect().toJSON()));
  const overlapping = boxes.filter((a, i) =>
    boxes.some(
      (b, j) =>
        j > i &&
        a.x < b.x + b.width &&
        b.x < a.x + a.width &&
        a.y < b.y + b.height &&
        b.y < a.y + a.height,
    ),
  );
  expect(overlapping).toHaveLength(0);
});

test("choosing All frameworks keeps the wide map", async ({ page }) => {
  await page.goto("/console/graph/");
  const framework = page.getByRole("combobox", {
    name: "Filter graph by framework",
  });
  await expect(framework).toBeVisible({ timeout: 45_000 });
  await expect(framework).not.toHaveValue("");
  await framework.selectOption("");
  await page.waitForTimeout(500);
  await expect(framework).toHaveValue("");
});
