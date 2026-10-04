"""Verify actual scrapes and authenticated provisioned Grafana in Kubernetes."""

import json, subprocess, time
import httpx
from kubernetes import ROOT, KUBECONFIG, kubectl, owned
from verify_kubernetes import wait

assert owned()
targets = json.loads(
    kubectl(
        "-n",
        "tracehawk",
        "exec",
        "deployment/prometheus",
        "--",
        "wget",
        "-q",
        "-O-",
        "http://127.0.0.1:9090/api/v1/targets",
        capture_output=True,
        text=True,
    ).stdout
)["data"]["activeTargets"]
assert len(targets) == 4 and all(t["health"] == "up" for t in targets)
log = (ROOT / "tmp/kubernetes-grafana-forward.log").open("a")
p = subprocess.Popen(
    [
        "kubectl",
        "--kubeconfig",
        str(KUBECONFIG),
        "-n",
        "tracehawk",
        "port-forward",
        "--address",
        "127.0.0.1",
        "service/grafana",
        "3103:3000",
    ],
    stdout=log,
    stderr=log,
)
try:
    base = "http://127.0.0.1:3103"
    wait(
        lambda: p.poll() is None and httpx.get(base + "/api/health").status_code == 200,
        30,
    )
    c = httpx.Client(base_url=base, timeout=15)
    credentials = json.loads((ROOT / "tmp/kubernetes-credentials.json").read_text())
    assert (
        c.post(
            "/login", json={"user": "operator", "password": credentials["operator"]}
        ).status_code
        == 200
    )
    dashboard = c.get("/api/dashboards/uid/tracehawk-operations")
    assert dashboard.status_code == 200
    d = dashboard.json()
    assert len(d["dashboard"]["panels"]) == 10 and d["meta"]["provisioned"]
    health = c.get("/api/datasources/uid/tracehawk-prometheus/health")
    assert health.status_code == 200 and health.json()["status"] == "OK"
    c.close()
    report = {
        "status": "passed",
        "scrape_targets": 4,
        "all_targets_up": True,
        "grafana_authenticated": True,
        "provisioned_panels": 10,
        "datasource_healthy": True,
    }
    (ROOT / "docs/phase-5/monitoring.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report))
finally:
    p.terminate()
    p.wait()
    log.close()
