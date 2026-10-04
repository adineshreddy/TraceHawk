"""Bounded worker probes and low-cardinality Prometheus text exposition."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def log(component, event, **fields):
    # Callers supply metadata only, never record bodies, credentials or exception text.
    print(json.dumps({"component": component, "event": event, **fields}), flush=True)


class Probes:
    def __init__(self, component):
        self.component = component
        self.status = "starting"
        self.seen = time.monotonic()
        self.metrics = {}
        self.lock = threading.Lock()
        probe = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                with probe.lock:
                    fresh = time.monotonic() - probe.seen < 15
                    ready = probe.status == "ready" and fresh
                    metrics = dict(probe.metrics)
                    state = probe.status if fresh else "stalled"
                if self.path == "/metrics":
                    text = f"# TYPE tracehawk_worker_ready gauge\ntracehawk_worker_ready {int(ready)}\n"
                    text += "".join(
                        f"# TYPE {k} {'counter' if k.endswith('_total') else 'gauge'}\n{k} {v}\n"
                        for k, v in sorted(metrics.items())
                    )
                    content, code, typ = text.encode(), 200, "text/plain; version=0.0.4"
                elif self.path in ("/health/live", "/health/ready"):
                    content = json.dumps({"status": state}).encode()
                    code = (
                        200 if (self.path.endswith("live") and fresh) or ready else 503
                    )
                    typ = "application/json"
                else:
                    content, code, typ = b"", 404, "text/plain"
                self.send_response(code)
                self.send_header("Content-Type", typ)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        self.server = ThreadingHTTPServer(("0.0.0.0", 9100), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def update(self, status, **metrics):
        with self.lock:
            self.status, self.seen = status, time.monotonic()
            self.metrics.update(metrics)

    def increment(self, key):
        with self.lock:
            self.metrics[key] = self.metrics.get(key, 0) + 1


def snapshot(c):
    workers = c.execute(
        "SELECT component,status,details,updated_at>now()-interval '15 seconds' fresh FROM component_health WHERE component IN ('collector','detector-a','detector-b','publisher') ORDER BY component"
    ).fetchall()
    partitions = c.execute(
        "SELECT partition,next_offset,ownership_epoch,owner_id,broker_high,greatest(0,broker_high-next_offset) lag,owner_seen_at>now()-interval '15 seconds' fresh FROM partition_checkpoints ORDER BY partition"
    ).fetchall()
    queues = c.execute(
        "SELECT (SELECT count(*) FROM outbox WHERE delivered_at IS NULL) pending_alert_updates,(SELECT count(*) FROM deadletters WHERE delivered_at IS NULL) pending_deadletters,(SELECT count(*) FROM deadletters WHERE reviewed_at IS NULL) unreviewed_deadletters"
    ).fetchone()
    active_owners = {
        w["details"].get("owner_id")
        for w in workers
        if w["component"].startswith("detector-")
        and w["status"] == "ready"
        and w["fresh"]
    }
    ready = (
        len(workers) == 4
        and all(w["fresh"] and w["status"] == "ready" for w in workers)
        and all(p["owner_id"] in active_owners and p["fresh"] for p in partitions)
        and not queues["unreviewed_deadletters"]
    )
    return {
        "status": "ready" if ready else "degraded",
        "workers": workers,
        "partitions": partitions,
        "queues": queues,
    }
