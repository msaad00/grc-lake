import { expect, test } from "@playwright/test";

// Runs against a golden demo loaded with `fixtures load --company golden`,
// which seeds synthetic remediation, risk, policy, vendor, and metrics records.

test("golden demo seeds a remediation queue linked to real findings", async ({
  page,
  request,
}) => {
  const body = (await (
    await request.get("/api/v1/remediation/tasks?limit=200")
  ).json()) as {
    data: Array<{ title: string; violation_id: string; created_by: string }>;
  };
  // Other specs add their own tasks; check only the seeded ones.
  const tasks = {
    data: body.data.filter((task) => task.created_by === "trustops-demo-seed"),
  };
  expect(tasks.data.length).toBeGreaterThanOrEqual(3);
  const violations = (await (
    await request.get("/api/v1/violations?limit=200")
  ).json()) as { data: Array<{ violation_id: string }> };
  const open = new Set(violations.data.map((row) => row.violation_id));
  for (const task of tasks.data) expect(open.has(task.violation_id)).toBe(true);

  await page.goto("/console/remediation/");
  await expect(
    page.getByText(tasks.data[0].title, { exact: true }).first(),
  ).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("No tasks yet.")).toHaveCount(0);
});

test("golden demo fills the risk register, policies, and vendor risk", async ({
  request,
}) => {
  const risks = (await (await request.get("/api/v1/risks")).json()) as {
    data: unknown[];
  };
  expect(risks.data.length).toBeGreaterThanOrEqual(3);
  const policies = (await (await request.get("/api/v1/policies")).json()) as {
    data: Array<{ status: string }>;
  };
  expect(policies.data.some((row) => row.status === "published")).toBe(true);
  const vendors = (await (
    await request.get("/api/v1/vendor-assessments")
  ).json()) as { data: unknown[] };
  expect(vendors.data.length).toBeGreaterThanOrEqual(2);
});

test("insights trends draw from seeded history and say findings", async ({
  page,
}) => {
  await page.goto("/console/insights/");
  await expect(
    page.getByText("Open findings over time", { exact: true }),
  ).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("Open violations over time")).toHaveCount(0);
  await expect(page.getByText(/^No data points yet/)).toHaveCount(0);
  await expect(page.getByText(/^No metrics snapshots yet/)).toHaveCount(0);
});

test("onboarding explains why a fixture demo is not setup-ready", async ({
  page,
}) => {
  await page.goto("/console/onboarding/");
  const note = page.getByTestId("onboarding-demo-note");
  await expect(note).toBeVisible({ timeout: 20_000 });
  await expect(note).toContainText("loaded from a sample fixture");
});

test("overview headline score is the assessment score, with its definition", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  await expect(page.getByText(/^Headline score · \d+ of \d+/)).toBeVisible({
    timeout: 20_000,
  });
  await expect(
    page.getByRole("button", {
      name: /^About Assessment score: Headline score for the whole workspace/,
    }),
  ).toBeVisible();
});

test("audit room names its in-scope frameworks", async ({ page, request }) => {
  const audit = (await (
    await request.get("/api/v1/platform/audit-readiness")
  ).json()) as {
    data: {
      posture: { frameworks_ready: number; frameworks_total: number };
      frameworks: Array<{ framework: string }>;
    };
  };
  await page.goto("/console/audit-room/");
  const { frameworks_ready, frameworks_total } = audit.data.posture;
  await expect(
    page.getByText(`${frameworks_ready} of ${frameworks_total}`, {
      exact: true,
    }),
  ).toBeVisible({ timeout: 20_000 });
  await expect(
    page.getByText(
      audit.data.frameworks.map((row) => row.framework).join(", "),
      { exact: true },
    ),
  ).toBeVisible();
});

test("local demo avatar is an icon, not the placeholder address initial", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  const avatar = page.getByTestId("user-avatar").first();
  await expect(avatar.locator("svg")).toBeVisible({ timeout: 20_000 });
  await expect(avatar).not.toHaveText("I");
});

test("control results label confidence as evidence confidence", async ({
  page,
}) => {
  await page.goto("/console/controls/");
  const first = page.getByText(/^\d+% evidence confidence$/).first();
  await expect(first).toBeVisible({ timeout: 20_000 });
  await expect(first).toHaveAttribute(
    "title",
    /Evidence confidence, weighted from: evidence coverage \d+/,
  );
});

test("evidence table fits 1440px without splitting control IDs", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/console/evidence/");
  const table = page.locator("table").first();
  const id = table.getByText("NIST-AI-RMF-MANAGE-2.3", { exact: true }).first();
  await expect(id).toBeVisible({ timeout: 20_000 });
  // The table renders before freshness arrives; measure once styles apply.
  await expect(id).toHaveCSS("line-height", /px$/);
  const overflow = await table.evaluate((node) => {
    const scroller = node.parentElement!;
    return scroller.scrollWidth - scroller.clientWidth;
  });
  expect(overflow).toBeLessThanOrEqual(0);
  // A wrapped ID would be taller than one line of its own text.
  const lineHeight = await id.evaluate((node) =>
    parseFloat(getComputedStyle(node).lineHeight),
  );
  const box = await id.boundingBox();
  expect(box!.height).toBeLessThanOrEqual(lineHeight + 1);
});
