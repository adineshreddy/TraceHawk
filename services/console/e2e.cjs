/* Real Chromium UI rehearsal through a same-origin local proxy inside the test container. */
const { chromium, expect } = require("@playwright/test");
const http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
const root = process.env.PROJECT_ROOT || "/workspace";
const credentials = JSON.parse(
  fs.readFileSync(path.join(root, "tmp/credentials.json")),
);
const evidence = path.join(root, "docs/phase-1");
fs.mkdirSync(evidence, { recursive: true });
(async () => {
  const proxy = http.createServer((req, res) => {
    const upstream = http.request(
      {
        hostname: "console",
        port: 3100,
        path: req.url,
        method: req.method,
        headers: req.headers,
      },
      (r) => {
        res.writeHead(r.statusCode, r.headers);
        r.pipe(res);
      },
    );
    upstream.on("error", () => {
      res.writeHead(503);
      res.end();
    });
    req.pipe(upstream);
  });
  await new Promise((resolve) => proxy.listen(3100, "127.0.0.1", resolve));
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page.goto("http://127.0.0.1:3100");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.operator);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Network overview" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Replay", exact: true }).click();
    await page.getByLabel("Playback speed").selectOption("10");
    await page
      .getByLabel("Rule snapshot", { exact: true })
      .selectOption("phase1-scan-v1");
    await page
      .getByRole("button", { name: "Start replay", exact: true })
      .click();
    await expect(
      page.getByText("108/108 source records published", { exact: false }),
    ).toBeVisible({ timeout: 40000 });
    await expect(
      page.getByRole("button", { name: "Possible vertical port scan" }),
    ).toBeVisible({ timeout: 30000 });
    await page.screenshot({
      path: path.join(evidence, "overview.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "Possible vertical port scan" })
      .click();
    await expect(
      page.getByRole("heading", { name: "Supporting connections (24)" }),
    ).toBeVisible();
    await expect(
      page
        .locator("section")
        .filter({
          has: page.getByRole("heading", {
            name: "Supporting connections (24)",
            exact: true,
          }),
        })
        .locator("tbody tr"),
    ).toHaveCount(24);
    await page
      .getByLabel("Investigation reason")
      .fill("Controlled demo reviewed <img src=x onerror=alert(1)>");
    await page
      .getByRole("button", { name: "Acknowledge", exact: true })
      .click();
    await expect(
      page.getByText("Disposition saved: acknowledged"),
    ).toBeVisible();
    await expect(page.locator("img")).toHaveCount(0);
    await page.screenshot({
      path: path.join(evidence, "investigation.png"),
      fullPage: true,
    });
    await page.reload();
    await expect(
      page.getByRole("heading", { name: "Network overview" }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Possible vertical port scan" })
      .click();
    await expect(
      page.getByText("high · acknowledged", { exact: true }),
    ).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: path.join(evidence, "mobile-investigation.png"),
      fullPage: true,
    });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    );
    if (overflow) throw Error("Mobile document overflows");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Sign in to your local workspace" }),
    ).toBeVisible();
    await page.getByLabel("Username", { exact: true }).fill("analyst");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.analyst);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Replay", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "Start replay", exact: true }),
    ).toBeDisabled();
    if (errors.length) throw Error(errors.join("\n"));
    fs.writeFileSync(
      path.join(evidence, "browser-verification.json"),
      JSON.stringify(
        {
          status: "passed",
          browser: "Chromium / Playwright 1.63.0",
          checks: [
            "login",
            "replay through real Go/Kafka/Python/PostgreSQL pipeline",
            "108 events / 24 evidence rows",
            "acknowledge with audit reason",
            "HTML-like source text escaped",
            "session and disposition survive refresh",
            "mobile layout without document overflow",
            "logout",
            "analyst replay disabled",
          ],
          screenshots: [
            "overview.png",
            "investigation.png",
            "mobile-investigation.png",
          ],
          page_errors: errors,
        },
        null,
        2,
      ) + "\n",
    );
    console.log("Browser rehearsal passed; screenshots and report saved.");
  } finally {
    await browser.close();
    await new Promise((resolve) => proxy.close(resolve));
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
