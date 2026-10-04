"""Exercise the actual local API and persisted pipeline; never print credentials."""

from pathlib import Path
import json, time, subprocess, re
import httpx
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:3100"
CREDENTIALS = json.loads((ROOT / "tmp/credentials.json").read_text())
REPORT = {}


OPENAPI = json.loads((ROOT / "contracts/openapi.json").read_text())


def assert_response(response):
    response.read()
    path = response.request.url.path
    method = response.request.method.lower()
    for pattern, operations in OPENAPI["paths"].items():
        if (
            re.fullmatch(re.sub(r"\{[^}]+\}", r"[^/]+", pattern), path)
            and method in operations
        ):
            op = operations[method]
            spec = op["responses"].get(str(response.status_code))
            assert spec is not None, (path, response.status_code)
            schema = spec.get("content", {}).get("application/json", {}).get("schema")
            if schema:
                Draft202012Validator(
                    dict(schema, components=OPENAPI["components"]),
                    format_checker=FormatChecker(),
                ).validate(response.json())
            return
    raise AssertionError("Undocumented API route: " + method + " " + path)


def client(role="operator"):
    c = httpx.Client(
        base_url=BASE,
        timeout=15,
        headers={"Origin": BASE},
        event_hooks={"response": [assert_response]},
    )
    r = c.post(
        "/api/v1/session/login", json={"username": role, "password": CREDENTIALS[role]}
    )
    assert r.status_code == 200, (r.status_code, r.text)
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def start(c, scenario="phase0-controlled-network-v1", speed=10):
    r = c.post(
        "/api/v1/runs",
        json={
            "scenario_id": scenario,
            "rule_version": "phase1-scan-v1",
            "playback_speed": speed,
        },
    )
    assert r.status_code == 202, r.text
    return r.json()


def wait(c, run, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = c.get("/api/v1/runs/" + run["run_id"])
        assert r.status_code == 200, r.text
        result = r.json()
        if result["status"] == "completed":
            return result
        assert result["status"] not in ("failed", "cancelled"), result
        time.sleep(0.5)
    raise AssertionError("Replay timed out: " + json.dumps(result))


def verify(c, run, events=108, alert_count=1):
    complete = wait(c, run)
    assert complete["processed_records"] == events, complete
    overview = c.get("/api/v1/overview", params={"scope_id": run["scope_id"]}).json()
    assert overview["event_count"] == events, overview
    alerts = c.get("/api/v1/alerts", params={"scope_id": run["scope_id"]}).json()[
        "items"
    ]
    assert len(alerts) == alert_count, alerts
    for a in alerts:
        Draft202012Validator(
            json.loads((ROOT / "contracts/schemas/alert.json").read_text()),
            format_checker=FormatChecker(),
        ).validate(a)
        assert a["observed"]["distinct_ports"] == 24, a
        evidence = c.get("/api/v1/alerts/" + a["alert_id"] + "/evidence").json()[
            "items"
        ]
        assert len(evidence) == 24 and len({e["event_id"] for e in evidence}) == 24
        validator = Draft202012Validator(
            json.loads((ROOT / "contracts/schemas/event.json").read_text()),
            format_checker=FormatChecker(),
        )
        for e in evidence:
            validator.validate(e)
    return alerts


def main():
    with httpx.Client(base_url=BASE) as anon:
        assert anon.get("/api/v1/runs").status_code == 401
        assert (
            anon.post(
                "/api/v1/session/login",
                json={"username": "operator", "password": "wrong"},
            ).status_code
            == 403
        )
        assert anon.get("/internal/jobs/claim").status_code == 404
    c = client()
    a = client("analyst")
    assert a.post("/api/v1/runs", json={}).status_code == 403
    rules = c.get("/api/v1/rules/phase1-scan-v1").json()
    assert a.post("/api/v1/rules", json=rules).status_code == 403
    assert (
        c.post(
            "/api/v1/runs", json={}, headers={"Origin": "http://evil.invalid"}
        ).status_code
        == 403
    )
    assert (
        c.post("/api/v1/runs", json={}, headers={"X-CSRF-Token": "bad"}).status_code
        == 403
    )
    assert (
        c.post(
            "/api/v1/runs",
            json={
                "scenario_id": "../../etc/passwd",
                "rule_version": "phase1-scan-v1",
                "playback_speed": 10,
            },
        ).status_code
        == 400
    )
    assert c.post("/api/v1/runs", content=b"x" * 65537).status_code == 413
    scan = start(c)
    assert (
        c.post(
            "/api/v1/runs",
            json={
                "scenario_id": "benign-network-v1",
                "rule_version": "phase1-scan-v1",
                "playback_speed": 10,
            },
        ).status_code
        == 409
    )
    alerts = verify(c, scan)
    REPORT["scan"] = {
        "run_id": scan["run_id"],
        "events": 108,
        "alerts": 1,
        "distinct_ports": 24,
        "evidence": 24,
    }
    aid = alerts[0]["alert_id"]
    assert c.get("/api/v1/alerts/" + "f" * 64 + "/evidence").status_code == 404
    assert c.get("/api/v1/overview", params={"scope_id": "unknown"}).status_code == 404
    assert (
        c.get(
            "/api/v1/alerts", params={"scope_id": scan["scope_id"], "cursor": "bad"}
        ).status_code
        == 400
    )
    r = c.patch(
        "/api/v1/alerts/" + aid + "/status",
        json={"status": "acknowledged", "reason": "Verified controlled scan"},
    )
    assert r.status_code == 200, r.text
    assert c.get("/api/v1/alerts/" + aid).json()["status"] == "acknowledged"
    # An authenticated user in another workspace cannot read local runs or evidence.
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "from tracehawk.core import db,password_hash; c=db(); c.execute(\"INSERT INTO users(username,password_hash,role,workspace) VALUES('scope-check',%s,'analyst','isolated-check') ON CONFLICT(username) DO UPDATE SET workspace='isolated-check'\",(password_hash('ephemeral-scope-check'),)); c.commit()",
        ],
        cwd=ROOT,
        check=True,
    )
    outsider = httpx.Client(
        base_url=BASE,
        headers={"Origin": BASE},
        event_hooks={"response": [assert_response]},
    )
    try:
        response = outsider.post(
            "/api/v1/session/login",
            json={"username": "scope-check", "password": "ephemeral-scope-check"},
        )
        assert response.status_code == 200
        assert outsider.get("/api/v1/runs").json()["items"] == []
        assert outsider.get("/api/v1/runs/" + scan["run_id"]).status_code == 404
        assert (
            outsider.get(
                "/api/v1/overview", params={"scope_id": scan["scope_id"]}
            ).status_code
            == 404
        )
        assert (
            outsider.get(
                "/api/v1/alerts", params={"scope_id": scan["scope_id"]}
            ).status_code
            == 404
        )
        assert outsider.get("/api/v1/alerts/" + aid + "/evidence").status_code == 404
    finally:
        outsider.close()
        subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "api",
                "python",
                "-c",
                "from tracehawk.core import db; c=db(); c.execute(\"DELETE FROM sessions WHERE username='scope-check'\"); c.execute(\"DELETE FROM users WHERE username='scope-check'\"); c.commit()",
            ],
            cwd=ROOT,
            check=True,
        )
    REPORT["workspace_isolation"] = (
        "authenticated outsider cannot read local runs, scope overview, alert list or evidence"
    )
    benign = start(c, "benign-network-v1")
    verify(c, benign, 17, 0)
    REPORT["benign"] = {"run_id": benign["run_id"], "events": 17, "alerts": 0}
    # Restart while a window contains only a partial set of scan connections.
    recovering = start(c, speed=5)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        o = c.get(
            "/api/v1/overview", params={"scope_id": recovering["scope_id"]}
        ).json()
        if o["event_count"] >= 10:
            break
        time.sleep(0.2)
    assert 10 <= o["event_count"] < 108, o
    subprocess.run(
        ["docker", "compose", "restart", "detector"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    verify(c, recovering)
    REPORT["detector_restart"] = {
        "run_id": recovering["run_id"],
        "partial_events_at_restart": o["event_count"],
        "final_events": 108,
        "alerts": 1,
        "evidence": 24,
    }
    cancelled = start(c, speed=1)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        progress = c.get(
            "/api/v1/overview", params={"scope_id": cancelled["scope_id"]}
        ).json()
        if progress["event_count"] > 0:
            break
        time.sleep(0.2)
    assert progress["event_count"] > 0
    result = c.post("/api/v1/runs/" + cancelled["run_id"] + "/cancel", json={})
    assert result.status_code == 202 and result.json()["status"] == "cancelled"
    time.sleep(2)
    partial = c.get(
        "/api/v1/overview", params={"scope_id": cancelled["scope_id"]}
    ).json()
    assert (
        0 < partial["event_count"] < 108 and partial["pipeline_status"] == "ready"
    ), partial
    REPORT["cancellation"] = {
        "run_id": cancelled["run_id"],
        "status": "cancelled",
        "partial_evidence_retained": partial["event_count"],
        "pipeline_status": partial["pipeline_status"],
    }
    assert c.post("/api/v1/session/logout", json={}).status_code == 200
    assert c.get("/api/v1/runs").status_code == 401
    REPORT["security"] = (
        "anonymous, operator/analyst, origin, CSRF, body limit, unknown scopes, active-run uniqueness, logout passed"
    )
    (ROOT / "docs/phase-1/api-verification.json").write_text(
        json.dumps(REPORT, indent=2) + "\n"
    )
    print(json.dumps(REPORT, indent=2))


if __name__ == "__main__":
    main()
