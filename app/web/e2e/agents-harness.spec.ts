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
      page.getByRole("button", { name: "Approve" }).first(),
    ).toBeVisible();

    const approve = await request.post(
      `/api/v1/agent-runs/${run.id}/decisions/0/approve`,
      { data: { note: "e2e approve" } },
    );
    expect(approve.ok()).toBeTruthy();
    expect((await approve.json()).data.decisions[0].status).toBe("executed");
  });

  test("a proposed decision can be rejected with a reason", async ({
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
    const reject = page.getByRole("button", { name: "Reject" }).first();
    await expect(reject).toBeVisible({ timeout: 15_000 });

    await reject.click();
    await expect(
      page.getByText("Add a reason to reject this decision.").first(),
    ).toBeVisible();

    await page
      .getByPlaceholder("Optional for approval; required to reject")
      .first()
      .fill("Covered by the vendor SOC report.");
    const posted = page.waitForRequest(
      (req) => req.method() === "POST" && req.url().includes("/reject"),
    );
    await reject.click();
    const body = (await posted).postDataJSON();
    expect(body).toEqual({ reason: "Covered by the vendor SOC report." });
    await expect(page.getByText(/^Rejected by /).first()).toBeVisible();

    const stored = await request.get(`/api/v1/agent-runs/${run.id}`);
    const statuses = (await stored.json()).data.decisions.map(
      (d: { status?: string }) => d.status,
    );
    expect(statuses).toContain("rejected");
  });
});
