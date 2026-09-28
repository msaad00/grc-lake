import { expect, test } from "@playwright/test";

type Coverage = {
  categories: { category_id: string; label: string; family_ids: string[] }[];
  families: { family_id: string; label: string; category_id: string }[];
};

test("control families render under their categories and link to review", async ({
  page,
}) => {
  const { data } = (await (
    await page.request.get("/api/v1/ccf/coverage")
  ).json()) as { data: Coverage };
  expect(data.categories.length).toBeGreaterThan(0);

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/dashboard/");
  await page
    .getByRole("tab", { name: "Control families", exact: true })
    .click();
  const panel = page.getByRole("tabpanel", { name: "Control families" });
  const sections = panel.locator("section[data-category]");
  await expect(sections).toHaveCount(data.categories.length);

  // Headings render in taxonomy order, each holding exactly its families.
  await expect(panel.getByRole("heading", { level: 3 })).toHaveText(
    data.categories.map((row) => row.label),
  );
  const seen = new Set<string>();
  for (const category of data.categories) {
    const section = panel.locator(
      `section[data-category="${category.category_id}"]`,
    );
    const ids = await section
      .locator("details[data-family]")
      .evaluateAll((nodes) =>
        nodes.map((node) => node.getAttribute("data-family") ?? ""),
      );
    expect(ids).toEqual(category.family_ids);
    for (const id of ids) {
      expect(seen.has(id), `${id} appears in two categories`).toBe(false);
      seen.add(id);
    }
  }
  expect(seen.size).toBe(data.families.length);

  const family = data.families.find((row) => row.family_id === "identity")!;
  const row = panel.locator('details[data-family="identity"]');
  await row.locator("summary").click();
  await row
    .getByRole("link", { name: `Review ${family.label} mappings` })
    .click();
  await expect(page).toHaveURL(/\/mapping-review\/\?family=identity/);
  await expect(page.getByLabel("Filter by family")).toHaveValue("identity");
});

test("control families stay inside the viewport on mobile", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/console/dashboard/");
  await page
    .getByRole("tab", { name: "Control families", exact: true })
    .click();
  const panel = page.getByRole("tabpanel", { name: "Control families" });
  await panel
    .locator("details[data-family]")
    .first()
    .locator("summary")
    .click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});
