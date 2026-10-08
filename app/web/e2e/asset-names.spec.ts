import { test, expect } from "@playwright/test";

// The golden demo names every asset. The console shows the name and keeps the
// stable ID for drawers and tooltips, so raw `golden:asset:*` IDs never stand in
// for an asset's name in a list.

test("findings list assets by name, not by demo ID", async ({ page }) => {
  await page.goto("/console/violations/");
  const table = page.getByRole("table");
  await expect(
    table.getByText("Production admin role", { exact: true }).first(),
  ).toBeVisible({ timeout: 20_000 });
  await expect(table.getByText(/^golden:asset:/)).toHaveCount(0);
});

test("evidence lists assets by name and the drawer keeps the ID", async ({
  page,
}) => {
  await page.goto("/console/evidence/?id=golden-001");
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible({ timeout: 20_000 });
  await expect(
    drawer.getByText("Customer records bucket", { exact: true }),
  ).toBeVisible();
  await expect(
    drawer.getByText("golden:asset:soc2-cc1.1", { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");

  const table = page.getByRole("table");
  await expect(table.getByRole("row").nth(1)).toBeVisible();
  await expect(table.getByText(/^golden:asset:/)).toHaveCount(0);
});

test("graph labels asset nodes with their names", async ({ page }) => {
  const nodes: { kind: string; label: string; asset_id?: string }[] = [];
  let query = "?limit=1000";
  for (;;) {
    const response = await page.request.get(`/api/v1/graph${query}`);
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    nodes.push(...(body.data?.nodes ?? []));
    const cursor = body.meta?.next_cursor;
    if (!cursor) break;
    query = `?limit=1000&cursor=${encodeURIComponent(cursor)}`;
  }
  const assets = nodes.filter((node) => node.kind === "asset");
  expect(assets.length).toBeGreaterThan(0);
  for (const node of assets) {
    expect(node.label).not.toMatch(/^golden:/);
    expect(node.asset_id).toBeTruthy();
  }
});
