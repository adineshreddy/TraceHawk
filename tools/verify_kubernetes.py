"""Actual replay, hardening, pod recovery and retained-data cluster recreation."""

from pathlib import Path
import argparse, hashlib, json, subprocess, time
import httpx
from kubernetes import ROOT, KUBECONFIG, kubectl, owned, up, down
from verify_phase1 import assert_response

BASE = "http://127.0.0.1:3102"
OUT = ROOT / "docs/phase-5"


def inside(code, service="api"):
    result = kubectl(
        "-n",
        "tracehawk",
        "exec",
        "-i",
        "deployment/" + service,
        "--",
        "python",
        "-",
        input=code,
        text=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def wait(fn, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (httpx.HTTPError, AssertionError, subprocess.CalledProcessError):
            pass
        time.sleep(0.4)
    raise AssertionError("Condition did not become true")


class Forward:
    def __enter__(self):
        self.log = (ROOT / "tmp/kubernetes-forward.log").open("a")
        self.proc = subprocess.Popen(
            [
                "kubectl",
                "--kubeconfig",
                str(KUBECONFIG),
                "-n",
                "tracehawk",
                "port-forward",
                "--address",
                "127.0.0.1",
                "service/console",
                "3102:3100",
            ],
            stdout=self.log,
            stderr=self.log,
        )
        wait(
            lambda: self.proc.poll() is None
            and httpx.get(BASE, timeout=2).status_code == 200,
            30,
        )
        return self

    def __exit__(self, *args):
        if self.proc.poll() is None:
            self.proc.terminate()
        self.proc.wait()
        self.log.close()


def login(role="operator"):
    credentials = json.loads((ROOT / "tmp/kubernetes-credentials.json").read_text())
    c = httpx.Client(
        base_url=BASE,
        headers={"Origin": BASE},
        timeout=15,
        event_hooks={"response": [assert_response]},
    )
    response = c.post(
        "/api/v1/session/login", json={"username": role, "password": credentials[role]}
    )
    assert response.status_code == 200
    c.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return c


def ops(c):
    response = c.get("/api/v1/operations")
    assert response.status_code == 200
    return response.json()


def start(c, scenario="phase0-controlled-network-v1", speed=10):
    response = c.post(
        "/api/v1/runs",
        json={
            "scenario_id": scenario,
            "rule_version": "phase2-rules-v1",
            "playback_speed": speed,
        },
    )
    assert response.status_code == 202, response.text
    return response.json()


def finish(c, run):
    wait(
        lambda: c.get("/api/v1/runs/" + run["run_id"]).json()["status"] == "completed",
        150,
    )
    return c.get("/api/v1/overview", params={"scope_id": run["scope_id"]}).json()


def signature(run):
    # Compare complete normalized bodies, evidence provenance and matching windows;
    # remove only identities/arrival clocks that differ across distinct runs.
    code = (
        """import json
from tracehawk.core import db
with db() as c:
 run=%r
 events=[]
 for e in c.execute('SELECT body,eligible FROM events WHERE run_id=%%s',(run,)).fetchall():
  body={k:v for k,v in e['body'].items() if k not in ('event_id','run_id','scope_id','published_at_us','ingested_at_us')}
  events.append([body,e['eligible']])
 alerts=[]
 for a in c.execute('SELECT * FROM alerts WHERE run_id=%%s',(run,)).fetchall():
  b=a['body']
  evidence=c.execute("SELECT e.body->'provenance'->>'log_kind' kind,(e.body->'provenance'->>'record_offset')::bigint record_position FROM alert_evidence a JOIN events e USING(event_id) WHERE a.alert_id=%%s ORDER BY kind,record_position",(a['alert_id'],)).fetchall()
  windows=c.execute('SELECT window_end_us,window_start_us,observed FROM alert_windows WHERE alert_id=%%s ORDER BY window_end_us',(a['alert_id'],)).fetchall()
  alerts.append([{k:b[k] for k in ('detector_id','source_ip','destination_ip','observed','thresholds','suppressed','severity')},evidence,windows])
 receipts=c.execute('SELECT count(*) n FROM event_processing_receipts WHERE run_id=%%s',(run,)).fetchone()['n']
 assert receipts==len(events)
 assert c.execute('SELECT count(*) n FROM run_partitions p JOIN runs r USING(run_id) WHERE p.run_id=%%s AND p.completed_generation=r.generation',(run,)).fetchone()['n']==3
 print(json.dumps({'events':sorted(events,key=lambda x:json.dumps(x,sort_keys=True)),'alerts':sorted(alerts,key=lambda x:json.dumps(x,sort_keys=True)),'receipts':receipts},sort_keys=True))
"""
        % run["run_id"]
    )
    data = inside(code)
    return {
        "events": len(data["events"]),
        "alerts": len(data["alerts"]),
        "receipts": data["receipts"],
        "effect_sha256": hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest(),
    }


def hardening():
    data = json.loads(
        kubectl(
            "-n",
            "tracehawk",
            "get",
            "pods",
            "-o",
            "json",
            capture_output=True,
            text=True,
        ).stdout
    )
    checks = 0
    for pod in data["items"]:
        spec = pod["spec"]
        assert spec["automountServiceAccountToken"] is False
        assert spec["securityContext"]["runAsNonRoot"]
        assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        for c in spec["containers"] + spec.get("initContainers", []):
            ctx = c["securityContext"]
            assert (
                ctx["allowPrivilegeEscalation"] is False
                and ctx["readOnlyRootFilesystem"]
            )
            assert ctx["capabilities"]["drop"] == ["ALL"]
            assert c["resources"]["limits"] and c["resources"]["requests"]
            checks += 1
    services = json.loads(
        kubectl(
            "-n",
            "tracehawk",
            "get",
            "services",
            "-o",
            "json",
            capture_output=True,
            text=True,
        ).stdout
    )["items"]
    assert all(
        s["spec"]["type"] == "ClusterIP" and not s["spec"].get("externalIPs")
        for s in services
    )
    result = subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            str(KUBECONFIG),
            "auth",
            "can-i",
            "get",
            "secrets",
            "--as=system:serviceaccount:tracehawk:workload",
            "-n",
            "tracehawk",
        ],
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "no"
    assert (
        inside(
            "import os,json;print(json.dumps({'mounted':os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token')}))"
        )["mounted"]
        is False
    )
    return {
        "restricted_containers_checked": checks,
        "services_cluster_internal": True,
        "workload_secret_rbac_denied": True,
        "serviceaccount_token_unmounted": True,
    }


def network():
    code = "import json,socket\nresults={}\nfor name,host,port in [('database_allowed','postgres',5432),('kafka_denied','kafka',9092)]:\n address=socket.gethostbyname(host)\n try:\n  s=socket.create_connection((address,port),timeout=2);s.close();results[name]=True\n except OSError:results[name]=False\nprint(json.dumps(results))"
    results = inside(code)
    assert results == {"database_allowed": True, "kafka_denied": False}
    js = "const net=require('net');require('dns').promises.lookup('postgres').then(({address})=>{const s=net.connect({host:address,port:5432});s.on('connect',()=>{console.log('allowed');s.destroy()});s.on('error',()=>console.log('denied'));s.setTimeout(2000,()=>{console.log('denied');s.destroy()});}).catch(()=>process.exit(2));"
    r = kubectl(
        "-n",
        "tracehawk",
        "exec",
        "deployment/console",
        "--",
        "node",
        "-e",
        js,
        capture_output=True,
        text=True,
    )
    assert r.stdout.strip() == "denied"
    # Even a matching app label in another namespace must not gain API ingress.
    name = "tracehawk-untrusted"
    namespace = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": {
                "pod-security.kubernetes.io/enforce": "restricted",
                "app.kubernetes.io/part-of": "tracehawk-test",
            },
        },
    }
    security = {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "probe", "namespace": name, "labels": {"app": "console"}},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "probe",
                    "image": "tracehawk-backend:phase4",
                    "imagePullPolicy": "Never",
                    "command": ["python", "-c", "import time;time.sleep(180)"],
                    "securityContext": security,
                    "resources": {
                        "requests": {"memory": "32Mi", "cpu": "10m"},
                        "limits": {"memory": "128Mi", "cpu": "100m"},
                    },
                }
            ],
        },
    }
    existing = subprocess.run(
        ["kubectl", "--kubeconfig", str(KUBECONFIG), "get", "namespace", name],
        capture_output=True,
    )
    assert existing.returncode != 0, "Unexpected existing test namespace"
    try:
        kubectl(
            "apply",
            "-f",
            "-",
            input=json.dumps(namespace),
            text=True,
            stdout=subprocess.DEVNULL,
        )
        kubectl(
            "apply",
            "-f",
            "-",
            input=json.dumps(pod),
            text=True,
            stdout=subprocess.DEVNULL,
        )
        kubectl(
            "-n",
            name,
            "wait",
            "--for=condition=Ready",
            "pod/probe",
            "--timeout=60s",
            stdout=subprocess.DEVNULL,
        )
        code = "import socket,json\naddress=socket.gethostbyname('api.tracehawk.svc.cluster.local')\ntry:\n s=socket.create_connection((address,8100),timeout=2);s.close();ok=True\nexcept OSError:ok=False\nprint(json.dumps(ok))"
        result = kubectl(
            "-n",
            name,
            "exec",
            "probe",
            "--",
            "python",
            "-c",
            code,
            capture_output=True,
            text=True,
        )
        assert json.loads(result.stdout) is False
    finally:
        kubectl("delete", "namespace", name, "--wait=false", stdout=subprocess.DEVNULL)
    return {
        "api_to_database_allowed": True,
        "api_to_kafka_denied": True,
        "console_to_database_denied": True,
        "foreign_namespace_spoofed_console_to_api_denied": True,
        "enforcement": "Calico v3.33.0, real connection attempts",
    }


def restart(name):
    kind = "statefulset" if name in ("kafka", "postgres") else "deployment"
    kubectl(
        "-n",
        "tracehawk",
        "rollout",
        "restart",
        kind + "/" + name,
        stdout=subprocess.DEVNULL,
    )
    kubectl(
        "-n",
        "tracehawk",
        "rollout",
        "status",
        kind + "/" + name,
        "--timeout=180s",
        stdout=subprocess.DEVNULL,
    )


def main(recreate):
    assert owned()
    OUT.mkdir(exist_ok=True)
    report = {"status": "running", "checks": {}, "runs": {}}
    with Forward():
        c = login()
        wait(lambda: ops(c)["status"] == "ready")
        state = ops(c)
        assert {p["owner_id"].split(":")[0] for p in state["partitions"]} == {
            "detector-a",
            "detector-b",
        }
        report["checks"]["hardening"] = hardening()
        report["checks"]["network_policy"] = network()
        reference = start(c)
        overview = finish(c, reference)
        baseline = signature(reference)
        assert baseline["events"] == 108 and baseline["alerts"] == 6
        report["runs"]["reference"] = reference["run_id"]
        report["reference"] = baseline
        benign = start(c, "benign-network-v1")
        overview = finish(c, benign)
        assert (
            overview["event_count"] == 17
            and not c.get(
                "/api/v1/alerts", params={"scope_id": benign["scope_id"]}
            ).json()["items"]
        )
        report["checks"]["benign_17_events_zero_alerts"] = True
        # Restart a real worker during replay; restored effects must match the reference.
        run = start(c, speed=1)
        wait(
            lambda: c.get(
                "/api/v1/overview", params={"scope_id": run["scope_id"]}
            ).json()["event_count"]
            >= 10
        )
        restart("detector")
        finish(c, run)
        assert signature(run) == baseline
        report["checks"]["loaded_worker_restart_effect_parity"] = True
        # Replacement of both stateful pods must preserve existing effects and credentials.
        for service in ("postgres", "kafka"):
            restart(service)
        wait(lambda: ops(c)["status"] == "ready", 180)
        assert signature(reference) == baseline
        report["checks"]["database_and_broker_pod_replacement_preserves_state"] = True
        report["checks"]["evaluation_summary"] = (
            c.get("/api/v1/evaluation").status_code == 200
        )
        c.close()
    if recreate:
        before = kubectl(
            "get",
            "node/tracehawk-control-plane",
            "-o",
            "jsonpath={.metadata.uid}",
            capture_output=True,
            text=True,
        ).stdout
        down()
        up(build=False)
        after = kubectl(
            "get",
            "node/tracehawk-control-plane",
            "-o",
            "jsonpath={.metadata.uid}",
            capture_output=True,
            text=True,
        ).stdout
        assert before != after
        with Forward():
            c = login()
            wait(lambda: ops(c)["status"] == "ready")
            assert (
                c.get("/api/v1/runs/" + reference["run_id"]).json()["status"]
                == "completed"
            )
            assert signature(reference) == baseline
            run = start(c)
            finish(c, run)
            assert signature(run) == baseline
            c.close()
        report["checks"]["cluster_recreated_with_new_node_uid"] = True
        report["checks"]["host_retained_state_and_login_preserved"] = True
        report["checks"]["post_recreation_replay_effect_parity"] = True
    report["status"] = "passed"
    report["cluster_recreation_tested"] = recreate
    report["limits"] = (
        "Single local kind node, one broker and database; host-mounted data retained. Not cloud deployment, HA, backup recovery or production capacity."
    )
    (OUT / "kubernetes.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--recreate", action="store_true")
    a = p.parse_args()
    main(a.recreate)
