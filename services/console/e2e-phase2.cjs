const { chromium, expect } = require("@playwright/test");
const http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
const root = process.env.PROJECT_ROOT || "/workspace",
  credentials = JSON.parse(
    fs.readFileSync(path.join(root, "tmp/credentials.json")),
  ),
  out = path.join(root, "docs/phase-2");
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
    await expect(
      page.getByRole("heading", { name: "Network overview" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Replay", exact: true }).click();
    await page
      .getByLabel("Rule snapshot", { exact: true })
      .selectOption("phase2-rules-v1");
    await page
      .getByRole("button", { name: "Start replay", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "Current run · completed" }),
    ).toBeVisible({ timeout: 40000 });
    await expect(page.locator("tbody tr")).toHaveCount(6);
    await page.screenshot({
      path: path.join(out, "overview.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Alerts", exact: true }).click();
    await page
      .getByLabel("Filter detector_id", { exact: true })
      .selectOption("dns_nxdomain_burst");
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await page
      .getByRole("button", { name: "DNS NXDOMAIN burst", exact: true })
      .click();
    await expect(
      page.getByRole("heading", {
        name: "Supporting events (40)",
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Measured matching windows" }),
    ).toBeVisible();
    await expect(
      page.getByRole("img", {
        name: "Observed events in ten-second event-time buckets",
      }),
    ).toBeVisible();
    await page.screenshot({
      path: path.join(out, "dns-investigation.png"),
      fullPage: true,
    });
    await page
      .getByLabel("Investigation reason", { exact: true })
      .fill("DNS lab result reviewed <img src=x onerror=alert(1)>");
    await page
      .getByRole("button", { name: "Acknowledge", exact: true })
      .click();
    await expect(
      page.getByText("Disposition saved: acknowledged", { exact: true }),
    ).toBeVisible();
    await expect(page.locator("img")).toHaveCount(0);
    await page.getByRole("button", { name: "192.0.2.30", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Host 192.0.2.30", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Host event timeline" }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Load more events", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Load more events", exact: true }),
    ).toBeDisabled();
    await page.screenshot({
      path: path.join(out, "host-investigation.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Rules", exact: true }).click();
    await page
      .getByLabel("Inspect rule snapshot", { exact: true })
      .selectOption("phase2-rules-v1");
    const rule = JSON.parse(
      await page.getByLabel("Rule JSON", { exact: true }).inputValue(),
    );
    rule.version = "browser-rule-" + Date.now();
    rule.vertical_tcp_scan.min_distinct_ports = 21;
    await page
      .getByLabel("Rule JSON", { exact: true })
      .fill(JSON.stringify(rule));
    await page
      .getByRole("button", { name: "Create rule version", exact: true })
      .click();
    await expect(
      page.getByText("Rule snapshot created: " + rule.version, { exact: true }),
    ).toBeVisible();
    await page
      .getByLabel("Inspect indicator snapshot", { exact: true })
      .selectOption("phase2-fictional-v1");
    expect(
      await page.getByLabel("Indicator JSON", { exact: true }).inputValue(),
    ).toContain("fictional");
    await page.getByRole("button", { name: "Replay", exact: true }).click();
    await page
      .getByLabel("Rule snapshot", { exact: true })
      .selectOption("phase2-rules-v1");
    await page
      .getByLabel(
        "Authorize the lab scanner for this replay (suppress port-scan alert only)",
        { exact: true },
      )
      .check();
    await page
      .getByRole("button", { name: "Start replay", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "Current run · completed" }),
    ).toBeVisible({ timeout: 40000 });
    await page.getByRole("button", { name: "Alerts", exact: true }).click();
    await page
      .getByLabel("Filter detector_id", { exact: true })
      .selectOption("");
    await page
      .getByLabel("Filter suppressed", { exact: true })
      .selectOption("true");
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await page
      .getByRole("button", { name: "Possible vertical port scan", exact: true })
      .click();
    await expect(
      page.getByText("Suppressed · evidence retained", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Supporting connections (24)" }),
    ).toBeVisible();
    await page.screenshot({
      path: path.join(out, "suppressed-investigation.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", {
        name: "Configure future suppression",
        exact: true,
      })
      .click();
    await page
      .getByLabel("Suppression reason", { exact: true })
      .fill("Reviewed authorized lab scanner");
    await page
      .getByRole("button", { name: "Save suppression", exact: true })
      .click();
    await expect(
      page.getByText(
        "Suppression saved for future alert episodes. Existing alerts retain their decision.",
        { exact: true },
      ),
    ).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: path.join(out, "mobile-suppressions.png"),
      fullPage: true,
    });
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      )
    )
      throw Error("Mobile document overflows");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByLabel("Username", { exact: true }).fill("analyst");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.analyst);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Rules", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "Create rule version", exact: true }),
    ).toBeDisabled();
    await expect(
      page.getByRole("button", {
        name: "Create indicator version",
        exact: true,
      }),
    ).toBeDisabled();
    await page
      .getByRole("button", { name: "Suppressions", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Save suppression", exact: true }),
    ).toBeDisabled();
    if (errors.length) throw Error(errors.join("\n"));
    fs.writeFileSync(
      path.join(out, "browser.json"),
      JSON.stringify(
        {
          status: "passed",
          browser: "Chromium / Playwright 1.63.0",
          checks: [
            "four-detector replay with six persisted alerts",
            "API-backed filtering",
            "DNS window measurements and timeline",
            "disposition with escaped reason",
            "host drill-down and event pagination",
            "create immutable rule snapshot",
            "fictional indicator inspection",
            "atomic pre-replay suppression",
            "retained suppressed evidence",
            "suppression audit creation",
            "mobile width",
            "analyst permissions",
          ],
          page_errors: errors,
        },
        null,
        2,
      ) + "\n",
    );
    console.log("Phase 2 browser rehearsal passed.");
  } finally {
    await browser.close();
    await new Promise((resolve) => proxy.close(resolve));
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
