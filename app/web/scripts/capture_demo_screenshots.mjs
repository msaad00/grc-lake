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
// Tall so the capture can end on a row; fitPage trims it to the content.
const MOBILE = { width: 390, height: 1800 };

/**
 * Crop policy: every page is captured with the app shell (rail + top bar),
 * sized to its content by fitPage. Only drawer shots crop to the drawer.
 *
 * file: output name; route: console path; viewport: capture size;
 * dark: also capture a -dark variant (README <picture> images);
 * setup: interaction before capture; crop: locators whose union is captured
 * (drawers only); endAt: locator whose bottom ends the capture, so a long
 * table stops on a row boundary instead of mid-row.
 */
const shots = [
  { file: "trustops-demo-dashboard.png", route: "/dashboard/", dark: true },
  {
    file: "trustops-demo-overview-mobile.png",
    route: "/dashboard/",
    viewport: MOBILE,
    endAt: (page) =>
      page
        .getByRole("region", { name: "Framework posture list" })
        .locator("a")
        .nth(2),
  },
  {
    file: "trustops-demo-control-families.png",
    route: "/dashboard/",
    setup: "control-families-tab",
  },
  {
    file: "trustops-demo-crosswalk.png",
    route: "/crosswalk/",
    viewport: { width: 1440, height: 2400 },
    setup: "crosswalk-matrix",
    // End on a row boundary inside the scrollable matrix.
    endAt: (page) =>
      page
        .getByRole("region", { name: "Reviewed framework overlap matrix" })
        .locator("tbody tr")
        .nth(3),
  },
  { file: "trustops-demo-findings.png", route: "/violations/" },
  { file: "trustops-demo-remediation.png", route: "/remediation/" },
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
    viewport: TALL,
    endAt: (page) => page.locator("table tbody tr").nth(7),
  },
  { file: "trustops-demo-insights.png", route: "/insights/" },
  { file: "trustops-demo-connectors.png", route: "/connectors/" },
  {
    file: "trustops-demo-frameworks.png",
    route: "/frameworks/",
    dark: true,
    viewport: TALL,
    endAt: (page) => page.getByLabel("Framework roster").locator("li").nth(7),
  },
  {
    file: "trustops-demo-mapping-review.png",
    route: "/mapping-review/",
    dark: true,
    viewport: TALL,
    setup: "mapping-review-selection",
    endAt: (page) =>
      page
        .getByRole("table", { name: "Mappings to review" })
        .locator("tbody tr")
        .nth(4),
  },
  { file: "trustops-demo-policies.png", route: "/policies/" },
  { file: "trustops-demo-vendor-risk.png", route: "/vendor-risk/" },
  {
    file: "trustops-demo-workflows.png",
    route: "/automation/",
    // Tall enough for the whole canvas, so the fitted flow is not cut.
    viewport: { width: 1440, height: 1240 },
  },
  { file: "trustops-demo-trust-center.png", route: "/trust-center/" },
  { file: "trustops-demo-onboarding.png", route: "/onboarding/" },
  { file: "trustops-demo-auth.png", route: "/auth/" },
  {
    file: "trustops-demo-graph.png",
    route: "/graph/?focus=evidence:monitoring.detection",
    dark: true,
    setup: "graph-focus",
  },
  {
    file: "trustops-demo-control-drawer.png",
    route: "/controls/?id=SOC2-CC6.4",
    dark: true,
    setup: "control-drawer",
    crop: (page) => [page.getByRole("dialog")],
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

/** `fixtures load --company golden` seeds the remediation queue, risks, a
 * policy, vendor assessments, and metrics history. Fail loudly instead of
 * capturing empty pages from a lake that skipped that step. */
async function requireSeededDemo() {
  const tasks = (await api("GET", "/v1/remediation/tasks?limit=1")).data ?? [];
  if (tasks.length === 0) {
    throw new Error(
      "No remediation tasks: load the lake with `security-lakehouse fixtures load --company golden` (without --no-demo-records).",
    );
  }
}

const browser = await chromium.launch();
await mkdir(outDir, { recursive: true });

async function waitForShell(page) {
  await page.waitForSelector("main", { timeout: 20_000 });
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(1000);
}

/** Space kept below the lowest content, below the last nav group, and
 * between that group and the rail footer (Docs · Feedback · version). */
const CONTENT_PAD = 40;
const NAV_PAD = 32;
const RAIL_GAP = 16;

/**
 * Where a page capture should end (CSS px from the top of the page):
 * `content` is the lowest visible element in `main`, clipped by its scroll
 * containers; `nav` is the last rail nav group; `rail` also fits the rail
 * footer right under the nav.
 */
async function measureBottoms(page) {
  return page.evaluate(
    ({ contentPad, navPad, railGap }) => {
      const main = document.querySelector("main");
      const clips = new Map();
      const clipOf = (element) => {
        if (!clips.has(element)) {
          const style = getComputedStyle(element);
          clips.set(
            element,
            style.overflowX === "visible" && style.overflowY === "visible"
              ? Infinity
              : element.getBoundingClientRect().bottom,
          );
        }
        return clips.get(element);
      };
      let contentBottom = main ? main.getBoundingClientRect().top : 0;
      for (const element of main ? main.querySelectorAll("*") : []) {
        const box = element.getBoundingClientRect();
        if (box.width <= 1 || box.height <= 1) continue;
        const style = getComputedStyle(element);
        if (style.visibility === "hidden") continue;
        // A bare layout wrapper is measured through its children; its own
        // box (and bottom padding) is spacing, not content.
        const painted =
          style.backgroundColor !== "rgba(0, 0, 0, 0)" ||
          style.borderBottomWidth !== "0px" ||
          style.boxShadow !== "none";
        const hasText = [...element.childNodes].some(
          (node) => node.nodeType === Node.TEXT_NODE && node.data.trim(),
        );
        if (!painted && !hasText && element.children.length) continue;
        let bottom = box.bottom;
        for (
          let parent = element.parentElement;
          parent && parent !== main;
          parent = parent.parentElement
        )
          bottom = Math.min(bottom, clipOf(parent));
        contentBottom = Math.max(contentBottom, bottom);
      }
      const rail = document.querySelector("aside");
      const nav = rail?.querySelector("nav");
      let navBottom = 0;
      let railBottom = 0;
      let footer = 0;
      if (rail && nav && rail.getBoundingClientRect().width > 0) {
        // The nav fills its grid row, so measure its groups, not the nav.
        const groups = [...nav.children].map(
          (group) => group.getBoundingClientRect().bottom,
        );
        navBottom =
          Math.max(nav.getBoundingClientRect().top, ...groups) +
          parseFloat(getComputedStyle(nav).paddingBottom);
        footer = rail.lastElementChild?.getBoundingClientRect().height ?? 0;
        railBottom = navBottom + railGap + footer;
        navBottom += navPad;
      }
      const y = window.scrollY;
      return {
        content: Math.ceil(y + contentBottom + contentPad),
        nav: Math.ceil(y + navBottom),
        rail: Math.ceil(y + railBottom),
        footer: Math.ceil(footer),
      };
    },
    { contentPad: CONTENT_PAD, navPad: NAV_PAD, railGap: RAIL_GAP },
  );
}

/**
 * Size a page capture to its content, never past the configured viewport
 * height. The capture ends below whichever is lower, the content or the last
 * nav group. When the whole rail (nav + footer) fits in that height the
 * viewport is set to it, so the footer sits right under the nav; otherwise
 * the viewport is made one footer taller than the capture, so the footer
 * (which would sit below the content) lands just outside the clip.
 * Re-measures until the layout settles, since resizing can reflow the page.
 */
async function fitPage(page, viewport, endAt) {
  // An open drawer spans the viewport; shrinking it would cut the drawer.
  if (await page.getByRole("dialog").count())
    return { viewport: { ...viewport }, height: viewport.height };
  let frame = { viewport: { ...viewport }, height: viewport.height };
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const bottoms = await measureBottoms(page);
    let content = bottoms.content;
    if (endAt) {
      const target = endAt(page).first();
      await target.waitFor({ state: "visible", timeout: 15_000 });
      const box = await target.boundingBox();
      if (!box) throw new Error("endAt target has no box");
      content = Math.ceil(
        (await page.evaluate(() => window.scrollY)) + box.y + box.height + 1,
      );
    }
    const height = Math.min(viewport.height, Math.max(content, bottoms.nav));
    const next = {
      viewport: {
        width: viewport.width,
        height: bottoms.rail <= height ? height : height + bottoms.footer,
      },
      height,
    };
    if (
      next.height === frame.height &&
      next.viewport.height === frame.viewport.height
    )
      return frame;
    frame = next;
    await page.setViewportSize(frame.viewport);
    await page.waitForTimeout(300);
  }
  throw new Error("page layout kept changing while fitting the capture");
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

await requireSeededDemo();

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

/**
 * Capture one theme. `frame` ({ viewport, clip }) is measured by the first
 * theme of a pair; later themes reuse it so a light/dark pair always has
 * identical dimensions.
 */
async function capture(shot, theme, frame) {
  const context = await browser.newContext({
    viewport: frame?.viewport ?? shot.viewport ?? WIDE,
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
    // `?id=` opens the drawer; fail loudly rather than capture a bare page.
    await page.getByRole("dialog").waitFor({ timeout: 15_000 });
    await page.waitForTimeout(800);
  }
  if (shot.setup === "mapping-review-selection") {
    // Select three rows so the decision form, progress, and verified decision
    // log are all in frame.
    const rows = page
      .getByRole("table", { name: "Mappings to review" })
      .locator("tbody tr");
    await rows.nth(2).waitFor({ timeout: 20_000 });
    for (const index of [0, 1, 2])
      await rows.nth(index).getByRole("checkbox").check();
    await page
      .getByRole("region", { name: "Record a decision" })
      .getByText("3 selected")
      .waitFor();
    await page.waitForTimeout(400);
  }
  if (shot.setup === "control-families-tab") {
    await page
      .getByRole("tab", { name: "Control families", exact: true })
      .click();
    await page
      .getByRole("tabpanel", { name: "Control families" })
      .locator("section[data-category]")
      .first()
      .waitFor({ timeout: 15_000 });
    await page.waitForTimeout(400);
  }
  if (shot.setup === "crosswalk-matrix") {
    // Narrow the mapping table to one control so the capture reaches the
    // bounded overlap matrix below it.
    await page.getByText(/^Showing 1–25 of [\d,]+ mappings$/).waitFor();
    await page
      .getByPlaceholder(/search/i)
      .first()
      .fill("CC6.1");
    await page.getByText(/^Showing 1–\d+ of [\d,]+ mappings?$/).waitFor();
    await page.getByText("Reviewed framework overlap matrix").first().click();
    await page
      .getByRole("region", { name: "Reviewed framework overlap matrix" })
      .waitFor();
    await page.waitForTimeout(400);
  }
  if (shot.setup === "graph-focus") {
    // `?focus=` selects one evidence type and narrows the canvas to its
    // framework slice; fit that slice so no node is cut at the canvas edge.
    await page.waitForTimeout(1500);
    await page.addStyleTag({
      content: ".react-flow__minimap { display: none !important; }",
    });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: /fit view/i }).click();
    await page.waitForTimeout(600);
  }

  const target = path.join(outDir, file);
  if (!frame && shot.crop) {
    const clip = await unionBox(shot.crop(page), shot.pad ?? 16);
    const viewport = page.viewportSize();
    clip.width = Math.min(clip.width, viewport.width - clip.x);
    clip.height = Math.min(clip.height, viewport.height - clip.y);
    if (shot.maxHeight) clip.height = Math.min(clip.height, shot.maxHeight);
    frame = { viewport, clip };
  } else if (!frame) {
    const { viewport, height } = await fitPage(
      page,
      shot.viewport ?? WIDE,
      shot.endAt,
    );
    frame = { viewport, clip: { x: 0, y: 0, width: viewport.width, height } };
  }
  await page.screenshot({ path: target, clip: frame.clip });
  await context.close();
  return { file, frame };
}

for (const shot of selected) {
  const pair = themes.filter((theme) => theme === "light" || shot.dark);
  for (let attempt = 1; ; attempt += 1) {
    const before = await postureFingerprint();
    const written = [];
    let frame;
    for (const theme of pair) {
      const result = await capture(shot, theme, frame);
      frame = result.frame;
      const { width, height } = frame.clip;
      written.push(`${result.file} ${width}x${height}`);
    }
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
