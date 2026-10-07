import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

let directory: string;
let report: string;

test.beforeAll(() => {
  directory = mkdtempSync(path.join(tmpdir(), "trustops-offline-"));
  report = path.join(directory, "report.html");
  execFileSync(
    "uv",
    [
      "run",
      "--no-sync",
      "python",
      "-c",
      `
import sys
from pathlib import Path
from security_lakehouse.dashboard import render_dashboard
from security_lakehouse.pipeline import run_pipeline
root = Path(sys.argv[1])
run_pipeline(Path('data/raw/security_events.jsonl'), root / 'lake')
render_dashboard(root / 'lake', root / 'report.html')
`,
      directory,
    ],
    { cwd: path.resolve(process.cwd(), "../.."), timeout: 60_000 },
  );
});

test.afterAll(() => rmSync(directory, { recursive: true, force: true }));

for (const javaScriptEnabled of [true, false]) {
  test(`frozen report works offline with JavaScript ${javaScriptEnabled}`, async ({
    browser,
  }) => {
    const context = await browser.newContext({
      javaScriptEnabled,
      offline: true,
      viewport: { width: 390, height: 844 },
    });
    const page = await context.newPage();
    const errors: string[] = [];
    const requests: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => requests.push(request.url()));
    await page.goto(pathToFileURL(report).href);
    await expect(
      page.getByRole("heading", { name: "Overview", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("table", { name: "Framework coverage" }),
    ).toBeVisible();
    await expect(page.getByText("SOC 2", { exact: true })).toBeVisible();
    await expect(
      page.getByText("Insufficient coverage", { exact: true }).first(),
    ).toBeVisible();
    await page.getByText("Control results", { exact: true }).click();
    await expect(
      page.getByRole("table", { name: "Recorded control results" }),
    ).toBeVisible();
    expect(errors).toEqual([]);
    expect(requests).toEqual([pathToFileURL(report).href]);
    expect(await page.locator("body").innerText()).not.toContain(
      "--tw-border-spacing",
    );
    await context.close();
  });
}
