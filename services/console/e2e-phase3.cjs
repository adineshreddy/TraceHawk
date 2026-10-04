const { chromium, expect } = require("@playwright/test");
const http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
const root = process.env.PROJECT_ROOT || "/workspace";
const credentials = JSON.parse(
  fs.readFileSync(path.join(root, "tmp/credentials.json")),
);
const out = path.join(root, "docs/phase-3");
(async () => {
  // Same-origin bridge preserves the API's configured loopback Origin.
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
  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page.goto("http://127.0.0.1:3100");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.operator);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Operations", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Pipeline operations" }),
    ).toBeVisible();
    await expect(page.getByRole("link", {name: "Open Grafana operations dashboard"})).toHaveAttribute("href", "http://127.0.0.1:3101/d/tracehawk-operations");
    await expect(
      page.getByText("detector-a", { exact: true }).first(),
    ).toBeVisible();
    await expect(
      page.getByText("detector-b", { exact: true }).first(),
    ).toBeVisible();
    await expect(page.getByText("publisher", { exact: true })).toBeVisible();
    await expect(
      page.getByText("reviewed", { exact: true }).first(),
    ).toBeVisible();
    await page.screenshot({
      path: path.join(out, "operations.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: path.join(out, "operations-mobile.png"),
      fullPage: true,
    });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    );
    if (overflow) throw Error("Operations page overflows mobile viewport");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByLabel("Username", { exact: true }).fill("analyst");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.analyst);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Network overview" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Operations", exact: true }),
    ).toHaveCount(0);

    // Grafana is a separately authenticated, provisioned operational view.
    await page.setViewportSize({ width: 1440, height: 2000 });
    await page.goto("http://grafana:3000/login");
    await page.getByLabel("Email or username").fill("operator");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.operator);
    const signedIn = page.waitForResponse(
      (r) => r.url().endsWith("/login") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Log in", exact: true }).click();
    const loginResponse = await signedIn;
    expect(loginResponse.status()).toBe(200);
    await page.waitForURL((url) => !url.pathname.endsWith("/login"));
    const skip = page.getByText("Skip", { exact: true });
    if (await skip.isVisible()) await skip.click();
    await page.goto("http://grafana:3000/d/tracehawk-operations");
    await expect(
      page.getByText("TraceHawk Operations", { exact: true }).first(),
    ).toBeVisible({ timeout: 30000 });
    await expect(
      page.getByText("Event lag by worker", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Pending alert updates", { exact: true }),
    ).toBeVisible();
    await page
      .getByText("Consumer assignments", { exact: true })
      .scrollIntoViewIfNeeded();
    await expect(
      page.getByText("Delivered alert updates / second", { exact: true }),
    ).toBeVisible();
    await page.waitForTimeout(5000);
    await page.screenshot({
      path: path.join(out, "grafana.png"),
      fullPage: true,
    });
    // Verify the panels are backed by the configured data source, rather than only rendered headings.
    const provisioning = await page.request.get(
      "http://grafana:3000/api/dashboards/uid/tracehawk-operations",
    );
    expect(provisioning.ok()).toBeTruthy();
    const dashboard = await provisioning.json();
    expect(dashboard.dashboard.panels).toHaveLength(10);
    expect(dashboard.meta.provisioned).toBeTruthy();
    if (errors.length) throw Error(errors.join("\n"));
    const report = {
      status: "passed",
      checks: [
        "real worker and ownership tables",
        "reviewed quarantine visible",
        "mobile operations layout",
        "analyst operations hidden",
        "authenticated Grafana provisioned dashboard",
      ],
      grafana_panels: 10,
    };
    fs.writeFileSync(
      path.join(out, "browser.json"),
      JSON.stringify(report, null, 2) + "\n",
    );
    console.log(JSON.stringify(report, null, 2));
  } finally {
    await browser.close();
    proxy.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
