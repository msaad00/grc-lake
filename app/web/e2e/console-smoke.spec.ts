import { test, expect } from "@playwright/test";

test.describe("console smoke", () => {
  test("dashboard shows trust home shell", async ({ page }) => {
    await page.goto("/console/dashboard/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("heading", {
        level: 1,
        name: /^Overview$/,
      }),
    ).toBeVisible();
    await expect(
      page.getByRole("tab", { name: "Frameworks", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Control pass rate", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Open findings", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Assessment export", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("tab", { name: "Frameworks", exact: true }),
    ).toHaveAttribute("aria-selected", "true");
    await expect(
      page.getByRole("tab", { name: "Sources", exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("tab", { name: "Exports" })).toHaveCount(0);
    await expect(page.getByText("Scale tier")).toHaveCount(0);
  });

  test("dashboard framework portfolio sorts, expands, scrolls, and collapses", async ({
    page,
  }) => {
    await page.goto("/console/dashboard/");
    const portfolio = page.getByRole("region", {
      name: "Framework posture list",
    });
    await expect(portfolio).toBeVisible();
    await expect(portfolio.getByText("SOC 2", { exact: true })).toBeVisible();
    // One sort control, one expander: no parallel Priority/All filter.
    await expect(
      page.getByRole("button", { name: "Priority", exact: true }),
    ).toHaveCount(0);
    const sort = page.getByRole("combobox", { name: "Sort" });
    await expect(sort).toHaveValue("priority");
    const previewCount = await portfolio.getByRole("link").count();
    expect(previewCount).toBe(4);
    // Only packs with catalogued requirements count; stubs are noted apart.
    const { data: registry } = await (
      await page.request.get("/api/v1/frameworks")
    ).json();
    const packs = (registry as Array<{ pack_state: string }>).filter(
      (row) => row.pack_state === "seeded",
    ).length;
    const stubs = registry.length - packs;
    expect(stubs).toBeGreaterThan(0);
    const expand = page.getByRole("button", {
      name: new RegExp(`^Show all ${packs} framework packs`),
    });
    await expect(
      page.getByText(`Not counted: ${stubs} planned or superseded`),
    ).toBeVisible();
    await expect(
      page.getByText(new RegExp(`of ${packs} framework packs assessed`)),
    ).toBeVisible();
    await expand.click();
    expect(await portfolio.getByRole("link").count()).toBeGreaterThan(
      previewCount,
    );
    expect(
      await portfolio.evaluate((node) => node.scrollHeight > node.clientHeight),
    ).toBe(true);
    await sort.selectOption("name");
    const names = await portfolio
      .getByRole("link")
      .evaluateAll((links) =>
        links.map(
          (link) => link.querySelector(".font-medium")?.textContent ?? "",
        ),
      );
    const { data: assessment } = await (
      await page.request.get("/api/v1/posture/current")
    ).json();
    const assessed = (assessment.frameworks as { framework: string }[])
      .map((f) => f.framework)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    expect(names.slice(0, assessed.length)).toEqual(assessed);
    await page.getByRole("button", { name: "Show fewer", exact: true }).click();
    await expect(portfolio.getByRole("link")).toHaveCount(previewCount);
    const toggle = page.getByRole("button", {
      name: /^Framework coverage$/,
    });
    await toggle.click();
    await expect(portfolio).not.toBeVisible();
    await toggle.click();
    await expect(portfolio).toBeVisible();
    const families = page.getByRole("tab", {
      name: "Control families",
      exact: true,
    });
    await families.click();
    const family = page
      .getByRole("tabpanel", { name: "Control families" })
      .locator("details")
      .first();
    await family.locator("summary").click();
    await expect(family.getByRole("link").first()).toHaveAttribute(
      "href",
      /mapping-review\/\?family=/,
    );
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  });

  test("audit room shows readiness score", async ({ page }) => {
    await page.goto("/console/audit-room/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("heading", { level: 1, name: "Audit room" }),
    ).toBeVisible();
    // Distinct names: each is defined once, then labels its tile.
    await expect(
      page.getByText("Audit readiness index", { exact: true }),
    ).toHaveCount(2);
    await expect(
      page.getByText("Evaluated frameworks ready", { exact: true }),
    ).toHaveCount(2);
    await expect(page.getByText(/^Assessment score \d+\/100$/)).toBeVisible();
    await expect(page.getByText("Audit score", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Fresh rate", { exact: true })).toHaveCount(0);
    await expect(
      page.getByRole("tab", { name: "Freshness", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("tab", { name: "Runs", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("tab", { name: "Snapshots", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("tab", { name: "Gaps", exact: true }),
    ).toBeVisible();
  });

  test("evidence page separates facts from report exports", async ({
    page,
  }) => {
    await page.goto("/console/evidence/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("heading", {
        level: 1,
        name: "Evidence",
      }),
    ).toBeVisible();
    await expect(
      page.getByText("These rows are evidence facts, not reports."),
    ).toBeVisible();
    await expect(page.getByText("How evidence flows")).toBeVisible();
    await expect(
      page.getByText("This page shows the normalized facts."),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Manage schedules" }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Open audit room" }),
    ).toBeVisible();
  });

  test("core trust pages share pipeline orientation", async ({ page }) => {
    for (const [path, active] of [
      ["/console/frameworks/", "Framework map"],
      ["/console/controls/", "Control eval"],
      ["/console/violations/", "Findings"],
    ] as const) {
      await page.goto(path);
      const pipeline = page.getByLabel("Trust pipeline");
      await expect(pipeline).toBeVisible({ timeout: 20_000 });
      await expect(pipeline.getByText("Evidence facts")).toBeVisible();
      await expect(pipeline.getByText(active, { exact: true })).toBeVisible();
      await expect(pipeline.locator('[aria-current="page"]')).toContainText(
        active,
      );
    }
  });

  test("frameworks render governed identity assets", async ({ page }) => {
    await page.goto("/console/frameworks/");

    const nistBadge = page
      .getByRole("img", {
        name: "NIST AI Risk Management Framework 1.0 framework",
        exact: true,
      })
      .first();
    await expect(nistBadge).toBeVisible();
    await expect(nistBadge.locator("img")).toHaveAttribute(
      "src",
      "/console/frameworks/badges/nist-ai-rmf.svg",
    );
    await expect(
      page
        .getByRole("img", { name: "ISO/IEC 27001:2022 framework", exact: true })
        .first(),
    ).toBeVisible();
  });

  test("dashboard shows each number once, with no duplicate detail section", async ({
    page,
  }) => {
    await page.goto("/console/dashboard/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("button", { name: /Operational detail/ }),
    ).toHaveCount(0);
    await expect(page.getByText("At a glance", { exact: true })).toHaveCount(0);
    // Findings preview is a fixed-length list: nothing scrolls or clips.
    const findings = page.getByRole("region", { name: "Findings to triage" });
    const rows = findings.getByRole("link");
    expect(await rows.count()).toBeLessThanOrEqual(5);
    expect(
      await findings.evaluate((node) => node.scrollHeight <= node.clientHeight),
    ).toBe(true);
    await expect(findings.getByText(/Owner:/)).toHaveCount(0);
    await expect(
      page.getByRole("link", { name: "View all findings →" }),
    ).toHaveAttribute("href", "/console/violations/");
  });

  test("default navigation exposes the full trust workflow", async ({
    page,
  }) => {
    await page.goto("/console/dashboard/");
    const sidebar = page.getByRole("complementary");

    for (const label of [
      "Overview",
      "Insights",
      "Connections",
      "Evidence",
      "Access reviews",
      "Vendor risk",
      "Controls",
      "Frameworks",
      "Findings",
      "Risk register",
      "Policies",
      "AI governance",
      "Crosswalk",
      "Remediation",
      "Workflows",
      "Agents",
      "Audit room",
      "Trust center",
      "Audit log",
      "Graph",
      "Access & keys",
      "Deploy",
    ]) {
      await expect(
        sidebar.getByRole("link", { name: label, exact: true }),
      ).toBeVisible();
    }

    for (const label of [
      "Onboarding",
      "Launch",
      "Demo",
      "Agent harness",
      "Pricing",
    ]) {
      await expect(sidebar.getByRole("link", { name: label })).toHaveCount(0);
    }
  });

  test("shell exposes skip link and main landmark", async ({ page }) => {
    await page.goto("/console/dashboard/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    const skip = page.getByRole("link", { name: "Skip to main content" });
    await expect(skip).toHaveAttribute("href", "#main-content");
    await skip.focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#main-content$/);
    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("health endpoint responds while console is served", async ({
    request,
  }) => {
    const response = await request.get("/api/v1/healthz");
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.data).toMatchObject({
      ok: true,
      service: "trustops-assessment",
    });
  });
});
