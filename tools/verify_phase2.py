"""Integration checks for four detectors and persisted investigation controls."""

from pathlib import Path
import json, time, uuid, copy, subprocess
import httpx
from verify_phase1 import assert_response

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:3100"
CREDS = json.loads((ROOT / "tmp/credentials.json").read_text())


def login(role="operator"):
    c = httpx.Client(
        base_url=BASE,
        timeout=15,
        headers={"Origin": BASE},
        event_hooks={"response": [assert_response]},
    )
    r = c.post(
        "/api/v1/session/login", json={"username": role, "password": CREDS[role]}
    )
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def replay(
    c, scenario="phase0-controlled-network-v1", templates=None, rule="phase2-rules-v1"
):
    body = {"scenario_id": scenario, "rule_version": rule, "playback_speed": 10}
    if templates is not None:
        body["suppression_templates"] = templates
    r = c.post("/api/v1/runs", json=body)
    assert r.status_code == 202, r.text
    run = r.json()
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        r = c.get("/api/v1/runs/" + run["run_id"])
        assert r.status_code == 200, r.text
        if r.json()["status"] == "completed":
            return r.json()
        assert r.json()["status"] not in ("failed", "cancelled"), r.text
        time.sleep(0.3)
    raise AssertionError("Replay timed out")


def main():
    c = login()
    a = login("analyst")
    report = {}
    rules = c.get("/api/v1/rules/phase2-rules-v1").json()
    assert all(
        rules[k]["enabled"]
        for k in (
            "vertical_tcp_scan",
            "failed_tcp_connections",
            "dns_nxdomain_burst",
            "known_indicator",
        )
    )
    indicators = c.get("/api/v1/indicators/phase2-fictional-v1").json()
    assert "fictional" in indicators["provenance"]
    run = replay(c)
    scope = run["scope_id"]
    assert run["indicator_version"] == "phase2-fictional-v1"
    allalerts = c.get(
        "/api/v1/alerts", params={"scope_id": scope, "limit": 100}
    ).json()["items"]
    ids = {
        k: [r for r in allalerts if r["detector_id"] == k]
        for k in (
            "vertical_tcp_scan",
            "failed_tcp_connections",
            "dns_nxdomain_burst",
            "known_indicator",
        )
    }
    assert {k: len(v) for k, v in ids.items()} == {
        "vertical_tcp_scan": 1,
        "failed_tcp_connections": 1,
        "dns_nxdomain_burst": 1,
        "known_indicator": 3,
    }, allalerts
    assert ids["failed_tcp_connections"][0]["observed"]["attempts"] == 24
    assert ids["dns_nxdomain_burst"][0]["observed"]["completed_responses"] == 40
    for alert in allalerts:
        from jsonschema import Draft202012Validator, FormatChecker

        Draft202012Validator(
            json.loads((ROOT / "contracts/schemas/alert.json").read_text()),
            format_checker=FormatChecker(),
        ).validate(alert)
        detail = c.get("/api/v1/alerts/" + alert["alert_id"] + "/evidence").json()
        assert len(detail["items"]) == alert["evidence_total_count"]
        assert (
            sum(x["event_count"] for x in detail["timeline"])
            == alert["evidence_total_count"]
        )
        if alert["detector_id"] == "known_indicator":
            assert (
                detail["indicator_matches"]
                and alert["indicator_version"] == run["indicator_version"]
            )
        else:
            assert detail["matched_windows"]
        if alert["detector_id"] == "dns_nxdomain_burst":
            assert sum(bin["dns_nxdomain"] for bin in detail["timeline"]) == 32
        filtered = c.get(
            "/api/v1/alerts",
            params={
                "scope_id": scope,
                "detector_id": alert["detector_id"],
                "source_ip": alert["source_ip"],
                "severity": alert["severity"],
                "status": "open",
                "suppressed": "false",
            },
        ).json()["items"]
        assert alert["alert_id"] in [x["alert_id"] for x in filtered]
    # Stable pagination with no omitted or duplicated alerts/events.
    paged = []
    cursor = None
    while True:
        params = {"scope_id": scope, "limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = c.get("/api/v1/alerts", params=params).json()
        paged += page["items"]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert {x["alert_id"] for x in paged} == {x["alert_id"] for x in allalerts} and len(
        paged
    ) == 6
    events = []
    cursor = None
    while True:
        params = {"scope_id": scope, "limit": 17}
        if cursor:
            params["cursor"] = cursor
        page = c.get("/api/v1/events", params=params).json()
        events += page["items"]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(events) == 108 and len({e["event"]["event_id"] for e in events}) == 108
    assert (
        sum(
            e["event"]["connection"] is not None
            and e["event"]["connection"]["duration_us"] is None
            for e in events
        )
        == 3
    )
    host = c.get("/api/v1/hosts/192.0.2.10", params={"scope_id": scope}).json()
    assert host["event_count"] == 24 and host["coverage"]["tcp_classified"] == 24
    assert c.get("/api/v1/hosts", params={"scope_id": scope}).status_code == 200
    assert (
        c.get(
            "/api/v1/events", params={"scope_id": scope, "host_ip": "bad"}
        ).status_code
        == 400
    )
    scan = ids["vertical_tcp_scan"][0]
    # A historical rule inserted AFTER detection must not retroactively hide an existing alert.
    request = {
        "scope_id": scope,
        "detector_id": "vertical_tcp_scan",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "reason": "Authorized lab scanner",
        "validity_mode": "scenario_interval",
    }
    assert a.post("/api/v1/suppressions", json=request).status_code == 403
    assert c.post("/api/v1/suppressions", json=request).status_code == 201
    assert not c.get("/api/v1/alerts/" + scan["alert_id"]).json()["suppressed"]
    templates = [
        {
            k: request[k]
            for k in ("detector_id", "source_ip", "destination_ip", "reason")
        }
    ]
    suppressed = replay(c, templates=templates)
    inbox = c.get(
        "/api/v1/alerts",
        params={"scope_id": suppressed["scope_id"], "suppressed": "true"},
    ).json()["items"]
    assert len(inbox) == 1 and inbox[0]["detector_id"] == "vertical_tcp_scan"
    assert (
        c.get("/api/v1/alerts/" + inbox[0]["alert_id"] + "/evidence").json()[
            "suppression"
        ]["reason"]
        == "Authorized lab scanner"
    )
    assert (
        c.get("/api/v1/overview", params={"scope_id": suppressed["scope_id"]}).json()[
            "suppressed_alert_count"
        ]
        == 1
    )
    assert (
        len(
            c.get(
                "/api/v1/alerts",
                params={"scope_id": suppressed["scope_id"], "suppressed": "false"},
            ).json()["items"]
        )
        == 5
    )
    benign = replay(c, "benign-network-v1")
    assert (
        c.get("/api/v1/alerts", params={"scope_id": benign["scope_id"]}).json()["items"]
        == []
    )
    # Canonical immutable indicator versions and rules must be selected explicitly.
    new = copy.deepcopy(indicators)
    new["version"] = "test-" + uuid.uuid4().hex
    new["entries"] = [
        {
            "kind": "domain",
            "value": "HOST0.EXAMPLE.TEST.",
            "description": "Canonicalization test",
        }
    ]
    created = c.post("/api/v1/indicators", json=new)
    assert created.status_code == 201, created.text
    assert created.json()["entries"][0]["value"] == "host0.example.test"
    assert c.post("/api/v1/indicators", json=new).status_code == 409
    assert a.post("/api/v1/indicators", json=new).status_code == 403
    changed = copy.deepcopy(rules)
    changed["version"] = "test-" + uuid.uuid4().hex
    changed["known_indicator"]["indicator_version"] = new["version"]
    assert c.post("/api/v1/rules", json=changed).status_code == 201
    assert c.post("/api/v1/rules", json=changed).status_code == 409
    selected = replay(c, rule=changed["version"])
    assert selected["indicator_version"] == new["version"]
    found = c.get(
        "/api/v1/alerts",
        params={"scope_id": selected["scope_id"], "detector_id": "known_indicator"},
    ).json()["items"]
    assert len(found) == 1 and found[0]["destination_ip"] is None
    # Scope authorization must also hold on all newly added investigation endpoints.
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "from tracehawk.core import db,password_hash; c=db(); c.execute(\"INSERT INTO users(username,password_hash,role,workspace) VALUES('phase2-scope-check',%s,'operator','phase2-isolated') ON CONFLICT(username) DO UPDATE SET workspace='phase2-isolated',role='operator'\",(password_hash('ephemeral-phase2-scope-check'),)); c.commit()",
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
        auth = outsider.post(
            "/api/v1/session/login",
            json={
                "username": "phase2-scope-check",
                "password": "ephemeral-phase2-scope-check",
            },
        )
        assert auth.status_code == 200
        outsider.headers["X-CSRF-Token"] = auth.json()["csrf_token"]
        for path in ["/hosts", "/hosts/192.0.2.10", "/events", "/suppressions"]:
            assert (
                outsider.get("/api/v1" + path, params={"scope_id": scope}).status_code
                == 404
            )
        assert outsider.post("/api/v1/suppressions", json=request).status_code == 404
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
                "from tracehawk.core import db; c=db(); c.execute(\"DELETE FROM sessions WHERE username='phase2-scope-check'\"); c.execute(\"DELETE FROM users WHERE username='phase2-scope-check'\"); c.commit()",
            ],
            cwd=ROOT,
            check=True,
        )
    report = {
        "status": "passed",
        "controlled_run": run["run_id"],
        "events": 108,
        "alerts_by_detector": {k: len(v) for k, v in ids.items()},
        "benign_run": benign["run_id"],
        "benign_alerts": 0,
        "suppressed_run": suppressed["run_id"],
        "suppressed_alerts": 1,
        "visible_unsuppressed_alerts": 5,
        "checks": [
            "measured window snapshots and timelines",
            "exact indicator versions and canonicalization",
            "immutable rule creation and run snapshot",
            "filtered persisted alerts",
            "stable alert/event pagination",
            "host investigation",
            "unknown duration preservation",
            "operator-only suppression and indicator changes",
            "outsider operator cannot read hosts/events/suppressions or create another workspace policy",
            "no retroactive suppression",
            "suppressed evidence retained",
        ],
    }
    (ROOT / "docs/phase-2/integration.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
