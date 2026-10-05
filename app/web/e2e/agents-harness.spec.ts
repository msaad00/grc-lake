import { test, expect } from "@playwright/test";

test.describe("agents harness", () => {
  test("fixture-mode posture review surfaces proposed writes", async ({
    page,
    request,
  }) => {
    const create = await request.post("/api/v1/agent-runs", {
      data: {
        harness: "posture_review",
        objective: "e2e fixture review",
        use_model: false,
        idempotency_key: `e2e-posture-${Date.now()}`,
      },
    });
    expect(create.ok()).toBeTruthy();
    const run = (await create.json()).data;
    expect(run.mode).toBe("rules_only");
    expect(run.decisions.length).toBeGreaterThan(0);

    await page.goto("/console/agents/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("heading", { level: 1, name: "Agents" }),
    ).toBeVisible();
    await expect(page.getByText(/fixture/i).first()).toBeVisible({
      timeout: 15_000,
    });
    await expect(
      page
        .getByText(
          "Sign in with an independent SSO reviewer to approve or reject.",
        )
        .first(),
    ).toBeVisible();

    const approve = await request.post(
      `/api/v1/agent-runs/${run.id}/decisions/0/approve`,
      { data: { note: "e2e approve" } },
    );
    expect(approve.status()).toBe(403);
    const stored = await request.get(`/api/v1/agent-runs/${run.id}`);
    expect((await stored.json()).data.decisions[0].status).toBe("proposed");
  });

  test("local demo cannot claim an authenticated reviewer", async ({
    page,
    request,
  }) => {
    const create = await request.post("/api/v1/agent-runs", {
      data: {
        harness: "posture_review",
        objective: "e2e reject review",
        use_model: false,
        idempotency_key: `e2e-reject-${Date.now()}`,
      },
    });
    expect(create.ok()).toBeTruthy();
    const run = (await create.json()).data;

    await page.goto("/console/agents/");
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("button", { name: "Reject" })).toHaveCount(0);
    const rejected = await request.post(
      `/api/v1/agent-runs/${run.id}/decisions/0/reject`,
      {
        data: { reason: "Local demo is not an independent reviewer." },
      },
    );
    expect(rejected.status()).toBe(403);

    const stored = await request.get(`/api/v1/agent-runs/${run.id}`);
    const statuses = (await stored.json()).data.decisions.map(
      (d: { status?: string }) => d.status,
    );
    expect(statuses).not.toContain("rejected");
  });
});

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1440]) {
    test(`review authority notice at ${width}px in ${theme} theme`, async ({
      page,
      request,
    }) => {
      const created = await request.post("/api/v1/agent-runs", {
        data: {
          harness: "posture_review",
          objective: "Review authority layout",
          use_model: false,
        },
      });
      expect(created.ok()).toBeTruthy();
      await page.addInitScript((mode) => {
        window.localStorage.setItem("trustops:theme", JSON.stringify(mode));
      }, theme);
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/console/agents/");
      await expect(
        page
          .getByText(
            "Sign in with an independent SSO reviewer to approve or reject.",
          )
          .first(),
      ).toBeVisible();
      await expect(
        page.getByRole("button", { name: "Approve", exact: true }),
      ).toHaveCount(0);
      await expect(
        page.getByRole("button", { name: "Reject", exact: true }),
      ).toHaveCount(0);
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBeTruthy();
      await page.screenshot({
        path: test.info().outputPath(`approval-${theme}-${width}.png`),
      });
    });
  }
}
