import http from "node:http";
import fs from "node:fs";
import path from "node:path";
const root = path.resolve("dist");
const grafana = new URL(
  process.env.GRAFANA_URL || "http://127.0.0.1:3101/d/tracehawk-operations",
);
if (!["http:", "https:"].includes(grafana.protocol))
  throw Error("Invalid dashboard URL");
const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
};
http
  .createServer((req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    );
    if (req.method === "GET" && req.url === "/runtime-config.json") {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify({ grafana_url: grafana.href }));
      return;
    }
    if (req.url === "/health/live") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"status":"ready"}');
      return;
    }
    if (req.url.startsWith("/api/v1/")) {
      const proxy = http.request(
        {
          hostname: "api",
          port: 8100,
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: "api:8100" },
        },
        (r) => {
          res.writeHead(r.statusCode, r.headers);
          r.pipe(res);
        },
      );
      proxy.setTimeout(10000, () => proxy.destroy());
      proxy.on("error", () => {
        if (!res.headersSent)
          res.writeHead(503, { "Content-Type": "application/json" });
        res.end(
          '{"code":"UNAVAILABLE","message":"API unavailable","request_id":"proxy"}',
        );
      });
      req.pipe(proxy);
      return;
    }
    if (req.url.startsWith("/internal/")) {
      res.writeHead(404);
      res.end();
      return;
    }
    if (req.method !== "GET") {
      res.writeHead(404);
      res.end();
      return;
    }
    let pathname;
    try {
      pathname = decodeURIComponent(new URL(req.url, "http://local").pathname);
    } catch {
      res.writeHead(400);
      res.end();
      return;
    }
    let file = path.resolve(root, "." + pathname);
    if (file !== root && !file.startsWith(root + path.sep)) {
      res.writeHead(404);
      res.end();
      return;
    }
    if (!fs.existsSync(file) || fs.statSync(file).isDirectory())
      file = path.join(root, "index.html");
    res.setHeader(
      "Content-Type",
      mime[path.extname(file)] || "application/octet-stream",
    );
    fs.createReadStream(file).pipe(res);
  })
  .listen(3100, "0.0.0.0");
