import { expect, test } from "@playwright/test";

test("evaluation polls a durable job before reporting completion", async ({
  page,
}) => {
  let polls = 0;
  await page.route("**/api/v1/ingestion/eval", async (route) => {
    expect(route.request().headers()["prefer"]).toBe("respond-async");
    expect(route.request().headers()["idempotency-key"]).toBeTruthy();
    await route.fulfill({
      status: 202,
      json: {
        meta: { resource: "operations" },
        errors: [],
        data: { id: "job-123", status: "queued" },
      },
    });
  });
  await page.route("**/api/v1/operations/job-123", async (route) => {
    polls += 1;
    await route.fulfill({
      json: {
        data: {
          status: polls < 2 ? "running" : "succeeded",
          http_status: 201,
          response:
            polls < 2
              ? null
              : {
                  data: {
                    result: "ok",
                    mode: "local_incremental",
                    duration_ms: 42,
                  },
                },
        },
      },
    });
  });
  await page.goto("/console/dashboard/");
  await page.getByRole("tab", { name: "Sources", exact: true }).click();
  await page
    .getByRole("button", { name: "Run control eval", exact: true })
    .click();
  await expect(
    page.getByText("Control eval complete (local_incremental, 42 ms)."),
  ).toBeVisible();
  expect(polls).toBeGreaterThanOrEqual(2);
});

test("interrupted work asks for inspection instead of reporting success", async ({
  page,
}) => {
  let submissions = 0;
  await page.route("**/api/v1/ingestion/eval", async (route) => {
    submissions += 1;
    await route.fulfill({
      status: 202,
      json: {
        meta: { resource: "operations" },
        errors: [],
        data: { id: "lost-job", status: "queued" },
      },
    });
  });
  await page.route("**/api/v1/operations/lost-job", (route) =>
    route.fulfill({
      json: { data: { status: "interrupted", response: null } },
    }),
  );
  await page.goto("/console/dashboard/");
  await page.getByRole("tab", { name: "Sources", exact: true }).click();
  await page
    .getByRole("button", { name: "Run control eval", exact: true })
    .click();
  await expect(
    page.getByText(/Operation lost-job interrupted. Check recent jobs/),
  ).toBeVisible();
  expect(submissions).toBe(1);
});

test("real snapshot completes through the server worker", async ({ page }) => {
  await page.goto("/console/dashboard/");
  await page
    .getByRole("button", { name: "Capture snapshot", exact: true })
    .click();
  const accepted = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/snapshots") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Freeze snapshot", exact: true })
    .click();
  const response = await accepted;
  expect(response.status()).toBe(202);
  expect(response.headers()["location"]).toMatch(/^\/api\/v1\/operations\//);
  await expect(page.getByText(/Snapshot frozen:/)).toBeVisible({
    timeout: 30_000,
  });
});
