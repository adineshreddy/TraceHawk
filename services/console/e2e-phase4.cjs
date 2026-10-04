const { chromium, expect } = require("@playwright/test");
const http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
const root = process.env.PROJECT_ROOT || "/workspace";
const credentials = JSON.parse(
  fs.readFileSync(path.join(root, "tmp/credentials.json")),
);
const out = path.join(root, "docs/phase-4");
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
    viewport: { width: 1440, height: 1100 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const base = "http://127.0.0.1:3100";
  try {
    const anonymous = await page.request.get(base + "/api/v1/evaluation");
    expect(anonymous.status()).toBe(401);
    await page.goto(base);
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.operator);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Evaluation", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Measured evaluation" }),
    ).toBeVisible();
    await expect(page.locator("tbody tr")).toHaveCount(9);
    await expect(
      page.getByText("horizontal_scan (unsupported)", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/Default enabled: no/)).toBeVisible();
    await expect(
      page.getByText(/500 events\/s × 600-second target: failed early/),
    ).toBeVisible();
    await page.screenshot({
      path: path.join(out, "evaluation.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      )
    )
      throw Error("Evaluation mobile overflow");
    await page.screenshot({
      path: path.join(out, "evaluation-mobile.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 1440, height: 1100 });
    const samples = [];
    for (let repeat = 0; repeat < 3; repeat++) {
      await page.getByRole("button", { name: "Replay", exact: true }).click();
      await page
        .getByLabel("Rule snapshot", { exact: true })
        .selectOption("phase2-rules-v1");
      const posted = page.waitForResponse(
        (r) =>
          r.url().endsWith("/api/v1/runs") && r.request().method() === "POST",
      );
      await page
        .getByRole("button", { name: "Start replay", exact: true })
        .click();
      const response = await posted;
      expect(response.status()).toBe(202);
      const run = await response.json();
      let first;
      const deadline = Date.now() + 40000;
      while (!first && Date.now() < deadline) {
        const r = await page.request.get(
          base +
            "/api/v1/alerts?scope_id=" +
            run.scope_id +
            "&detector_id=known_indicator",
        );
        expect(r.ok()).toBeTruthy();
        const alerts = (await r.json()).items;
        first = alerts.sort((a, b) => a.created_at_us - b.created_at_us)[0];
        if (!first) await page.waitForTimeout(100);
      }
      if (!first) throw Error("No persisted indicator alert");
      const observedAt = Date.now();
      await expect(
        page
          .getByRole("button", { name: "Exact indicator match", exact: true })
          .first(),
      ).toBeVisible({ timeout: 10000 });
      const visibleAt = Date.now();
      const delay = (visibleAt * 1000 - first.created_at_us) / 1e6;
      if (delay < 0) throw Error("Clock ordering invalid");
      samples.push({
        repeat,
        creation_to_visible_s: delay,
        first_api_observation_to_visible_s: (visibleAt - observedAt) / 1000,
      });
      await expect(
        page.getByRole("heading", { name: "Current run · completed" }),
      ).toBeVisible({ timeout: 40000 });
    }
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByLabel("Username", { exact: true }).fill("analyst");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.analyst);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Evaluation", exact: true }).click();
    await expect(page.locator("tbody tr")).toHaveCount(9);
    if (errors.length) throw Error(errors.join("\n"));
    const report = {
      status: "passed",
      checks: [
        "authenticated summary",
        "actual rule/model/benchmark tables",
        "explicit unsupported detector and failed capacity target",
        "desktop and mobile layout",
        "analyst summary access",
        "three completed real replay visibility samples",
      ],
      visibility_samples: samples,
      max_creation_to_visible_s: Math.max(
        ...samples.map((r) => r.creation_to_visible_s),
      ),
      three_second_target_met: samples.every(
        (r) => r.creation_to_visible_s <= 3,
      ),
      measurement_note:
        "Wall-clock alert creation is before transaction commit; includes commit, API polling (100ms), console polling (2s), scheduling and cross-container clock uncertainty. Three controlled samples do not establish a percentile or production SLA.",
      page_errors: errors,
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
