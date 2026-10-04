"""Real fault/recovery checks against this project's Compose stack only."""

from pathlib import Path
import copy, json, subprocess, time, uuid
from verify_phase2 import login, replay

ROOT = Path(__file__).resolve().parents[1]
REPORT = {"checks": {}, "runs": {}}


def compose(*args):
    subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=True, stdout=subprocess.DEVNULL
    )


def inside(code, service="api"):
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", service, "python", "-"],
        input=code,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def wait(fn, timeout=75):
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        try:
            last = fn()
            if last:
                return last
        except Exception:
            pass
        time.sleep(0.4)
    raise AssertionError(f"Condition timed out; last={last}")


def operations(c):
    r = c.get("/api/v1/operations")
    assert r.status_code == 200, r.text
    return r.json()


def completed(c, run):
    r = c.get("/api/v1/runs/" + run["run_id"])
    return r.status_code == 200 and r.json()["status"] == "completed"


def start(c, speed=5):
    r = c.post(
        "/api/v1/runs",
        json={
            "scenario_id": "phase0-controlled-network-v1",
            "rule_version": "phase2-rules-v1",
            "playback_speed": speed,
        },
    )
    assert r.status_code == 202, r.text
    return r.json()


def event_count(c, run):
    r = c.get("/api/v1/overview", params={"scope_id": run["scope_id"]})
    return r.json().get("event_count", 0) if r.status_code == 200 else 0


def signature(run):
    return inside(
        """import json
from tracehawk.core import db
with db() as c:
 run=%r
 events=c.execute("SELECT body,eligible FROM events WHERE run_id=%%s",(run,)).fetchall()
 normalized=[]
 for e in events:
  body={k:v for k,v in e['body'].items() if k not in ('event_id','run_id','scope_id','published_at_us','ingested_at_us')}
  normalized.append([body,e['eligible']])
 alerts=[]
 for a in c.execute('SELECT * FROM alerts WHERE run_id=%%s',(run,)).fetchall():
  b=a['body']
  evidence=c.execute("SELECT e.body->'provenance'->>'log_kind' kind,(e.body->'provenance'->>'record_offset')::bigint record_position FROM alert_evidence a JOIN events e USING(event_id) WHERE a.alert_id=%%s ORDER BY kind,record_position",(a['alert_id'],)).fetchall()
  windows=c.execute('SELECT window_end_us,window_start_us,observed FROM alert_windows WHERE alert_id=%%s ORDER BY window_end_us',(a['alert_id'],)).fetchall()
  alerts.append([ {k:b[k] for k in ('detector_id','source_ip','destination_ip','observed','thresholds','suppressed','severity')},evidence,windows])
 parts=c.execute("SELECT host(e.source_ip) source,max(e.event_time_us) max_time_us,max(p.watermark_us) watermark_us,max(p.next_window_end_us) next_window_end_us FROM events e JOIN run_partitions p ON p.run_id=e.run_id AND p.partition=e.partition WHERE e.run_id=%%s GROUP BY e.source_ip ORDER BY e.source_ip",(run,)).fetchall()
 assert c.execute('SELECT count(*) n FROM run_partitions p JOIN runs r USING(run_id) WHERE p.run_id=%%s AND p.completed_generation=r.generation',(run,)).fetchone()['n']==3
 print(json.dumps({'events':sorted(normalized,key=lambda x:json.dumps(x,sort_keys=True)),'alerts':sorted(alerts,key=lambda x:json.dumps(x,sort_keys=True)),'partitions':parts},sort_keys=True))
"""
        % run["run_id"]
    )


def probes(service, path):
    return inside(
        "import urllib.request,json\nfrom urllib.error import HTTPError\ntry:\n r=urllib.request.urlopen('http://127.0.0.1:9100/%s',timeout=3); code=r.status\nexcept HTTPError as e: code=e.code\nprint(json.dumps({'code':code}))"
        % path,
        service,
    )["code"]


def main():
    c = login()
    analyst = login("analyst")
    assert analyst.get("/api/v1/operations").status_code == 403
    assert analyst.get("/api/v1/deadletters").status_code == 403
    wait(lambda: operations(c)["status"] == "ready")
    state = operations(c)
    owners = {p["owner_id"].split(":")[0] for p in state["partitions"]}
    assert owners == {"detector-a", "detector-b"}, state
    REPORT["checks"]["two_consumers_three_partitions"] = True
    reference = replay(c)
    baseline = signature(reference)
    assert len(baseline["events"]) == 108 and len(baseline["alerts"]) == 6
    REPORT["runs"]["reference"] = reference["run_id"]

    # Fence both old epoch and wrong owner, before any payload or offset mutation.
    fenced = inside(
        """import json
from tracehawk.core import db
from tracehawk.detector import apply
c=db()
try:
 with c.transaction():
  p=c.execute('SELECT * FROM partition_checkpoints WHERE partition=0 FOR UPDATE').fetchone()
  for epoch,owner in [(p['ownership_epoch']-1,p['owner_id']),(p['ownership_epoch'],'stale-owner')]:
   try: apply(c,0,p['next_offset'],b'{}',epoch,owner_id=owner)
   except RuntimeError as e: assert str(e)=='Ownership lost'
   else: raise AssertionError('Stale owner wrote')
  assert c.execute('SELECT * FROM partition_checkpoints WHERE partition=0').fetchone()==p
  raise ValueError('rollback')
except ValueError: pass
print(json.dumps({'passed':True}))
"""
    )
    REPORT["checks"]["stale_epoch_and_owner_fenced"] = fenced["passed"]

    run = start(c, 1)
    REPORT["runs"]["rebalance_crash"] = run["run_id"]
    wait(lambda: event_count(c, run) >= 10)
    compose("stop", "detector-b")
    wait(
        lambda: len({p["owner_id"] for p in operations(c)["partitions"] if p["fresh"]})
        == 1
        and all(p["fresh"] for p in operations(c)["partitions"])
    )
    compose("kill", "-s", "SIGKILL", "detector")
    compose("up", "-d", "detector", "detector-b")
    wait(lambda: completed(c, run), 100)
    assert signature(run) == baseline
    wait(lambda: operations(c)["status"] == "ready")
    REPORT["checks"]["rebalance_and_sigkill_state_matches_reference"] = True

    run = start(c)
    REPORT["runs"]["database_outage"] = run["run_id"]
    wait(lambda: event_count(c, run) >= 5)
    try:
        compose("stop", "postgres")
        wait(lambda: probes("detector", "health/ready") == 503, 25)
        assert probes("detector", "health/live") == 200
        REPORT["checks"]["database_outage_paused_readiness_live_process"] = True
    finally:
        compose("start", "postgres")
    wait(lambda: completed(c, run), 100)
    assert signature(run) == baseline
    wait(lambda: operations(c)["status"] == "ready")
    REPORT["checks"]["database_outage_state_matches_reference"] = True

    run = start(c)
    REPORT["runs"]["broker_outage"] = run["run_id"]
    wait(lambda: event_count(c, run) >= 5)
    try:
        compose("stop", "kafka")
        wait(lambda: probes("detector", "health/ready") == 503, 30)
    finally:
        compose("start", "kafka")
    wait(lambda: completed(c, run), 100)
    assert signature(run) == baseline
    wait(lambda: operations(c)["status"] == "ready")
    REPORT["checks"]["broker_outage_state_matches_reference"] = True

    # No new source is leased while there is no consumer coverage.
    compose("stop", "detector", "detector-b")
    try:
        wait(lambda: all(p["owner_id"] is None for p in operations(c)["partitions"]))
        queued = start(c, 10)
        time.sleep(3)
        r = c.get("/api/v1/runs/" + queued["run_id"]).json()
        assert r["status"] == "queued" and event_count(c, queued) == 0
        assert (
            next(w for w in operations(c)["workers"] if w["component"] == "collector")[
                "status"
            ]
            == "paused"
        )
    finally:
        compose("up", "-d", "detector", "detector-b")
    wait(lambda: completed(c, queued))
    assert signature(queued) == baseline
    wait(lambda: operations(c)["status"] == "ready")
    REPORT["runs"]["backpressure"] = queued["run_id"]
    REPORT["checks"]["intake_pauses_without_consumers_and_resumes"] = True

    # Produce a malformed record on the real input topic, not a direct DB insert.
    poisoned = inside(
        """import json
from confluent_kafka import Producer
p=Producer({'bootstrap.servers':'kafka:9092','message.timeout.ms':5000})
ack=[]
p.produce('tracehawk.events.v1',partition=0,value=b'{invalid-json',on_delivery=lambda err,msg:ack.append([err is None,msg.partition(),msg.offset()]))
assert p.flush(6)==0 and ack[0][0]
print(json.dumps({'partition':ack[0][1],'offset':ack[0][2]}))
"""
    )
    part, offset = poisoned["partition"], poisoned["offset"]

    def dlq_done():
        rows = c.get("/api/v1/deadletters").json()["items"]
        return next(
            (
                r
                for r in rows
                if r["partition"] == part
                and r["broker_offset"] == offset
                and r["delivered_at"]
            ),
            None,
        )

    rejected = wait(dlq_done)
    assert rejected["record_bytes"] == 13 and len(rejected["record_sha256"]) == 64
    assert operations(c)["status"] == "degraded"
    r = c.post(
        f"/api/v1/deadletters/{part}/{offset}/review",
        json={
            "reason": "Recovery verifier: malformed synthetic input investigated; no replay required."
        },
    )
    assert r.status_code == 200, r.text
    wait(lambda: operations(c)["status"] == "ready")
    REPORT["checks"]["durable_quarantine_delivery_review_and_recovery"] = True

    # Crash the publisher between Kafka ACK and SQL delivery checkpoint.
    compose("stop", "publisher")
    try:
        alert = c.get(
            "/api/v1/alerts", params={"scope_id": reference["scope_id"], "limit": 100}
        ).json()["items"][0]
        r = c.patch(
            "/api/v1/alerts/" + alert["alert_id"] + "/status",
            json={
                "status": "acknowledged",
                "reason": "Outbox ACK-before-checkpoint recovery test",
            },
        )
        assert r.status_code == 200, r.text
        update = inside(
            "import json; from tracehawk.core import db\nwith db() as c:\n r=c.execute(\"SELECT update_id FROM outbox WHERE alert_id=%s AND delivered_at IS NULL ORDER BY (body->>'revision')::bigint DESC LIMIT 1\",(%r,)).fetchone(); print(json.dumps(r))"
            % ("%s", alert["alert_id"])
        )["update_id"]
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "10001:10001",
                "-v",
                "tracehawk_publisher_state:/state",
                "--entrypoint",
                "python",
                "tracehawk-backend:phase4",
                "-c",
                f"from pathlib import Path; Path('/state/fault_after_ack').write_text({update!r})",
            ],
            cwd=ROOT,
            check=True,
        )
    finally:
        compose("up", "-d", "publisher")
    wait(
        lambda: inside(
            "import json; from tracehawk.core import db\nwith db() as c: print(json.dumps(bool(c.execute('SELECT delivered_at FROM outbox WHERE update_id=%s',(%r,)).fetchone()['delivered_at'])))"
            % ("%s", update)
        )
    )
    # Read the retained output topic, count duplicates by ID and apply monotonic revisions.
    delivered = inside(
        """import json, time, uuid
from confluent_kafka import Consumer, TopicPartition
c=Consumer({'bootstrap.servers':'kafka:9092','group.id':'phase3-verifier-'+uuid.uuid4().hex,'enable.auto.commit':False,'enable.partition.eof':True})
parts=[]; ends={}
for p in range(3):
 low,high=c.get_watermark_offsets(TopicPartition('tracehawk.alerts.v1',p),timeout=5)
 parts.append(TopicPartition('tracehawk.alerts.v1',p,low)); ends[p]=high
c.assign(parts)
seen={}; latest={}; done={p for p,h in ends.items() if h==0}; deadline=time.monotonic()+30
while len(done)<3 and time.monotonic()<deadline:
 m=c.poll(.2)
 if not m: continue
 if m.error():
  if m.error().code()==-191: done.add(m.partition())
  else: raise RuntimeError('Output consumer error')
  continue
 e=json.loads(m.value()); key=e['update_id']; seen[key]=seen.get(key,0)+1
 a=e['alert_id']
 if a not in latest or latest[a]['revision']<e['revision']: latest[a]=e
 if m.offset()+1>=ends[m.partition()]: done.add(m.partition())
c.close()
assert len(done)==3
assert seen.get(%r,0)>=2,seen.get(%r,0)
assert latest[%r]['alert']['status']=='acknowledged'
print(json.dumps({'target_occurrences':seen[%r],'unique_updates':len(seen),'deduplicated_latest_status':latest[%r]['alert']['status']}))
"""
        % (update, update, alert["alert_id"], update, alert["alert_id"])
    )
    REPORT["checks"]["outbox_ack_before_checkpoint_duplicates_identified"] = delivered

    metrics = wait(
        lambda: inside(
            """import json, urllib.request
r=json.load(urllib.request.urlopen('http://prometheus:9090/api/v1/targets'))
targets=r['data']['activeTargets']; assert len(targets)==4 and all(t['health']=='up' for t in targets)
x=json.load(urllib.request.urlopen('http://prometheus:9090/api/v1/query?query=tracehawk_pipeline_ready'))
assert x['data']['result'] and x['data']['result'][0]['value'][1]=='1'
print(json.dumps({'scrape_targets':len(targets),'pipeline_ready_metric':True}))
"""
        ),
        30,
    )
    REPORT["checks"]["prometheus_live_scrapes"] = metrics
    REPORT["status"] = "passed"
    REPORT["limits"] = (
        "Small controlled replay; single broker/database; no high-availability or load claim."
    )
    (ROOT / "docs/phase-3/recovery.json").write_text(
        json.dumps(REPORT, indent=2) + "\n"
    )
    print(json.dumps(REPORT, indent=2))


if __name__ == "__main__":
    try:
        main()
    finally:
        # Restore only this project after any failed assertion during fault injection.
        compose("start", "postgres", "kafka")
        compose("up", "-d", "detector", "detector-b", "publisher")
