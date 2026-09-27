#!/usr/bin/env node
/**
 * Capture console screenshots for README / docs.
 * Requires: server at TRUSTOPS_SCREENSHOT_URL (default http://127.0.0.1:8787)
 *           and `npx playwright install chromium` once.
 *
 * Every theme is captured in one run against one server with the browser clock
 * frozen at a single instant, so light and dark variants show identical data
 * and identical relative times. Set TRUSTOPS_SCREENSHOT_NOW (ISO) to pin it.
 */
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const base =
  process.env.TRUSTOPS_SCREENSHOT_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8787";
const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);
const outDir = path.join(root, "docs", "images");
const frozenNow = new Date(process.env.TRUSTOPS_SCREENSHOT_NOW || Date.now());
if (Number.isNaN(frozenNow.getTime()))
  throw new Error("TRUSTOPS_SCREENSHOT_NOW is not a valid date");

const WIDE = { width: 1440, height: 1024 };
const TALL = { width: 1440, height: 1600 };

/**
 * file: output name; route: console path; viewport: capture size;
 * dark: also capture a -dark variant (README <picture> images);
 * setup: interaction before capture; crop: locators whose union is captured.
 */
const shots = [
  { file: "trustops-demo-dashboard.png", route: "/dashboard/", dark: true },
  { file: "trustops-demo-findings.png", route: "/violations/" },
  {
    file: "trustops-demo-remediation.png",
    route: "/remediation/",
    crop: (page) => [page.locator("main .page-shell")],
    pad: 0,
  },
  {
    file: "trustops-demo-triage.png",
    route: "/violations/",
    dark: true,
    setup: "finding-drawer",
    crop: (page) => [page.getByRole("dialog")],
  },
  { file: "trustops-demo-audit-room.png", route: "/audit-room/" },
  {
    file: "trustops-demo-evidence.png",
    route: "/evidence/",
    dark: true,
    viewport: { width: 1920, height: 1600 },
    crop: (page) => [
      page.getByText(/matching records/).first(),
      page.locator("table").first(),
    ],
    pad: 20,
    maxHeight: 820,
  },
  { file: "trustops-demo-insights.png", route: "/insights/" },
  { file: "trustops-demo-connectors.png", route: "/connectors/" },
  {
    file: "trustops-demo-frameworks.png",
    route: "/frameworks/",
    dark: true,
    viewport: TALL,
    crop: (page) => [
      page.getByRole("region", { name: "Framework coverage summary" }),
      page.getByLabel("Framework roster"),
    ],
    maxHeight: 960,
  },
  { file: "trustops-demo-policies.png", route: "/policies/" },
  { file: "trustops-demo-vendor-risk.png", route: "/vendor-risk/" },
  { file: "trustops-demo-workflows.png", route: "/automation/" },
  { file: "trustops-demo-trust-center.png", route: "/trust-center/" },
  { file: "trustops-demo-onboarding.png", route: "/onboarding/" },
  { file: "trustops-demo-auth.png", route: "/auth/" },
  {
    file: "trustops-demo-graph.png",
    route: "/graph/?focus=evidence:monitoring.detection",
    dark: true,
    setup: "graph-focus",
    crop: (page) => [page.locator(".react-flow").first()],
  },
  {
    file: "trustops-demo-control-drawer.png",
    route: "/controls/",
    setup: "control-drawer",
  },
];

const themes = (process.env.TRUSTOPS_SCREENSHOT_THEMES || "light,dark").split(
  ",",
);

async function api(method, route, body) {
  const response = await fetch(`${base}/api${route}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) throw new Error(`${method} ${route} → ${response.status}`);
  return response.json();
}

const daysFromNow = (days) =>
  new Date(frozenNow.getTime() + days * 86_400_000).toISOString();

/** Seed remediation work idempotently so the page shows a real queue. */
async function seedRemediation() {
  const violations = (await api("GET", "/v1/violations?limit=50")).data ?? [];
  const pick = (controlId) =>
    violations.find((v) => v.control_id === controlId) ?? violations[0];
  const existing = new Set(
    ((await api("GET", "/v1/remediation/tasks?limit=500")).data ?? []).map(
      (task) => task.title,
    ),
  );
  const tasks = [
    {
      title: "Remove stale admin grants after role change",
      control_id: "SOC2-CC6.4",
      owner: "identity-team",
      priority: "critical",
      due_at: daysFromNow(2),
    },
    {
      title: "Patch internet-facing hosts with critical CVEs",
      control_id: "SOC2-CC7.1",
      owner: "platform-sre",
      priority: "high",
      due_at: daysFromNow(5),
    },
    {
      title: "Require approvals on production change pipelines",
      control_id: "SOC2-CC8.1",
      owner: "devops",
      priority: "high",
      due_at: daysFromNow(9),
    },
    {
      title: "Document AI model risk tolerances for GOVERN 1.2",
      control_id: "NIST-AI-RMF-GOVERN-1.2",
      owner: "ai-governance",
      priority: "medium",
      due_at: daysFromNow(14),
    },
  ];
  for (const task of tasks) {
    if (existing.has(task.title)) continue;
    const violation = pick(task.control_id);
    await api("POST", "/v1/remediation/tasks", {
      ...task,
      violation_id:
        violation?.control_id === task.control_id
          ? violation.violation_id
          : undefined,
    });
  }
}

const browser = await chromium.launch();
await mkdir(outDir, { recursive: true });

async function waitForShell(page) {
  await page.waitForSelector("main", { timeout: 20_000 });
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(1000);
}

async function unionBox(locators, pad = 16) {
  const boxes = [];
  for (const locator of locators) {
    await locator.first().waitFor({ state: "visible", timeout: 15_000 });
    const box = await locator.first().boundingBox();
    if (box) boxes.push(box);
  }
  if (!boxes.length) throw new Error("crop target not found");
  const x = Math.max(0, Math.min(...boxes.map((b) => b.x)) - pad);
  const y = Math.max(0, Math.min(...boxes.map((b) => b.y)) - pad);
  const right = Math.max(...boxes.map((b) => b.x + b.width)) + pad;
  const bottom = Math.max(...boxes.map((b) => b.y + b.height)) + pad;
  return { x, y, width: right - x, height: bottom - y };
}

const requested = new Set(process.argv.slice(2));
const selected = requested.size
  ? shots.filter(({ file }) => requested.has(file))
  : shots;
if (requested.size && selected.length !== requested.size)
  throw new Error("Unknown screenshot filename");

await seedRemediation();

/** Freshness is evaluated live by the server, so a row can cross its SLO
 * between two captures. Each light/dark pair is taken back to back and
 * retaken when the posture moved underneath it. */
async function postureFingerprint() {
  const posture = (await api("GET", "/v1/posture/current")).data?.posture ?? {};
  return JSON.stringify([
    posture.score,
    posture.stale_evidence_count,
    posture.stale_control_count,
    posture.open_violation_count,
  ]);
}

async function capture(shot, theme) {
  const context = await browser.newContext({
    viewport: shot.viewport ?? WIDE,
    deviceScaleFactor: 2,
    colorScheme: theme,
    reducedMotion: "reduce",
  });
  await context.clock.setFixedTime(frozenNow);
  await context.addInitScript((mode) => {
    localStorage.setItem("trustops:theme", JSON.stringify(mode));
    // The rail ends on whole groups instead of clipping mid-section.
    localStorage.setItem(
      "trustops:sidebar:closed-groups",
      JSON.stringify({ "Review & export": true, Settings: true }),
    );
  }, theme);
  const page = await context.newPage();
  const file =
    theme === "light"
      ? shot.file
      : shot.file.replace(/\.png$/, `-${theme}.png`);
  await page.goto(`${base}/console${shot.route}`, {
    waitUntil: "domcontentloaded",
    timeout: 45_000,
  });
  await waitForShell(page);

  if (shot.setup === "finding-drawer") {
    await page
      .getByRole("button", { name: /Review finding/ })
      .first()
      .click();
    await page.getByRole("dialog").waitFor();
    await page.waitForTimeout(600);
  }
  if (shot.setup === "control-drawer") {
    const row = page
      .locator("button")
      .filter({ hasText: /SOC2|CC6|NIST/i })
      .first();
    if (await row.count()) {
      await row.click();
      await page.waitForTimeout(1200);
    }
  }
  if (shot.setup === "graph-focus") {
    // `?focus=` centres one evidence type at a readable zoom, with the
    // controls it proves above it and the assets it came from below.
    await page.waitForTimeout(1500);
    await page.addStyleTag({
      content: ".react-flow__minimap { display: none !important; }",
    });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
  }

  const target = path.join(outDir, file);
  if (shot.crop) {
    const clip = await unionBox(shot.crop(page), shot.pad ?? 16);
    if (shot.maxHeight) clip.height = Math.min(clip.height, shot.maxHeight);
    await page.screenshot({ path: target, clip });
  } else {
    await page.screenshot({ path: target, fullPage: false });
  }
  await context.close();
  return file;
}

for (const shot of selected) {
  const pair = themes.filter((theme) => theme === "light" || shot.dark);
  for (let attempt = 1; ; attempt += 1) {
    const before = await postureFingerprint();
    const written = [];
    for (const theme of pair) written.push(await capture(shot, theme));
    if ((await postureFingerprint()) === before) {
      written.forEach((file) => console.log("wrote", file));
      break;
    }
    if (attempt >= 5)
      throw new Error(`posture kept changing while capturing ${shot.file}`);
    console.log(`posture changed during ${shot.file}; retaking`);
  }
}

await browser.close();
