/** Capture the generated synthetic auditor workpaper, never a staged mockup. */
import { chromium } from "playwright";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const input = path.resolve(
  root,
  process.argv[2] || "build/auditor-workpaper/index.html",
);
const output = path.join(root, "docs/images/grc-lake-auditor-workpaper.png");
const manifest = JSON.parse(
  await readFile(path.join(path.dirname(input), "manifest.json"), "utf8"),
);
const htmlHash = createHash("sha256").update(await readFile(input)).digest("hex");
if (manifest.files["index.html"] !== htmlHash) {
  throw new Error("Rendered workpaper does not match its export manifest");
}
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({
    viewport: { width: 1280, height: 1000 },
    deviceScaleFactor: 1,
  });
  await page.goto(pathToFileURL(input).href);
  await page.getByRole("heading", {
    name: "Control assurance, with the evidence.",
  }).waitFor();
  const text = await page.locator("body").innerText();
  if (!text.includes("Synthetic demonstration")) {
    throw new Error("Only synthetic fixture captures may be committed");
  }
  const overflows = () => page.evaluate(
    () => document.documentElement.scrollWidth > innerWidth,
  );
  if (await overflows()) throw new Error("Workpaper overflows desktop viewport");
  await page.screenshot({ path: output, fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator("details").first().evaluate((node) => { node.open = true; });
  if (await overflows()) throw new Error("Workpaper overflows mobile viewport");
  const receipt = {
    source: "examples/control-assurance",
    synthetic: true,
    viewport: { width: 1280, height: 1000 },
    content_sha256: manifest.content_sha256,
    html_sha256: htmlHash,
    image_sha256: createHash("sha256").update(await readFile(output)).digest("hex"),
  };
  await writeFile(
    path.join(root, "docs/images/grc-lake-auditor-workpaper.capture.json"),
    JSON.stringify(receipt, null, 2) + "\n",
  );
} finally {
  await browser.close();
}
