const { chromium, expect } = require("@playwright/test");
const http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
const root = process.env.PROJECT_ROOT || "/workspace",
  out = path.join(root, "docs/phase-5");
const credentials = JSON.parse(
  fs.readFileSync(path.join(root, "tmp/kubernetes-credentials.json")),
);
(async () => {
  const proxy = process.env.DIRECT_KUBERNETES_FORWARD
    ? null
    : http.createServer((req, res) => {
        const upstream = http.request(
          {
            hostname: "host.docker.internal",
            port: 3102,
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
  if (proxy)
    await new Promise((resolve) => proxy.listen(3102, "127.0.0.1", resolve));
  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page.goto("http://127.0.0.1:3102");
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.operator);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Replay", exact: true }).click();
    await page
      .getByLabel("Rule snapshot", { exact: true })
      .selectOption("phase2-rules-v1");
    await page
      .getByRole("button", { name: "Start replay", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "Current run · completed" }),
    ).toBeVisible({ timeout: 60000 });
    await expect(page.locator("tbody tr")).toHaveCount(6);
    await page.screenshot({
      path: path.join(out, "kubernetes-replay.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Operations", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Pipeline operations" }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Open Grafana operations dashboard" }),
    ).toHaveAttribute("href", "http://127.0.0.1:3103/d/tracehawk-operations");
    await expect(
      page.getByText("detector-a", { exact: true }).first(),
    ).toBeVisible();
    await expect(
      page.getByText("detector-b", { exact: true }).first(),
    ).toBeVisible();
    await page.screenshot({
      path: path.join(out, "kubernetes-operations.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Evaluation", exact: true }).click();
    await expect(page.locator("tbody tr")).toHaveCount(9);
    await page.setViewportSize({ width: 390, height: 844 });
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      )
    )
      throw Error("Mobile overflow");
    await page.screenshot({
      path: path.join(out, "kubernetes-mobile.png"),
      fullPage: true,
    });
    if (errors.length) throw Error(errors.join("\n"));
    const report = {
      status: "passed",
      runtime: "Kubernetes v1.35.0 / kind; actual loopback port-forward",
      checks: [
        "authenticated real replay with six persisted alerts",
        "both detector workers visible",
        "deployment-configured Grafana link",
        "packaged evaluation page",
        "mobile width",
      ],
      page_errors: errors,
    };
    fs.writeFileSync(
      path.join(out, "browser.json"),
      JSON.stringify(report, null, 2) + "\n",
    );
    console.log(JSON.stringify(report, null, 2));
  } finally {
    await browser.close();
    proxy?.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
