"""Bounded real Kafka/PostgreSQL workload, run only by the local benchmark CLI."""

import hashlib, json, os, time, uuid, math
from confluent_kafka import Producer
from psycopg.types.json import Jsonb
from tracehawk.core import db, digest, now_us, VALIDATORS
from evaluation_common import partition

cfg = json.loads(os.environ["BENCH_CONFIG"])
rate = cfg["rate"]
duration = cfg["seconds"]
hosts = cfg["hosts"]
total = int(rate * duration)
assert (
    1 <= rate <= 500 and 1 <= duration <= 600 and 1 <= hosts <= 64 and total <= 300000
)
run = "benchmark-" + uuid.uuid4().hex
scenario = "synthetic-load-v1"
base = 1791028800000000
source_hash = digest(
    {
        "generator": "load-v1",
        "seed": cfg.get("seed", 7),
        "rate": rate,
        "hosts": hosts,
        "pattern": cfg.get("pattern", "benign"),
    }
)
manifest_hash = digest({"source_hash": source_hash, "total": total})
meta = {
    "time_start_us": base,
    "time_end_us": base + int(duration * 1000000),
    "manifest_sha256": manifest_hash,
    "log_hashes": {"conn": source_hash},
    "input_mode": "synthetic_fixture",
    "generator": "tools/benchmark_workload.py",
    "planned_total": total,
}
c = db()
c.autocommit = True
with c.transaction():
    c.execute(
        "INSERT INTO runs(run_id,scope_id,workspace,scenario_id,rule_version,status,speed,metadata,total_records,generation,indicator_version,lease_until) VALUES(%s,%s,'benchmark',%s,'phase2-rules-v1','finalizing',10,%s,%s,1,'phase2-fictional-v1',now()+interval '1 hour')",
        (run, run, scenario, Jsonb(meta), total),
    )
    for p in range(3):
        c.execute(
            "INSERT INTO run_partitions(run_id,partition) VALUES(%s,%s)", (run, p)
        )
database_bytes_before = c.execute(
    "SELECT pg_database_size(current_database()) bytes"
).fetchone()["bytes"]
producer = Producer(
    {
        "bootstrap.servers": "kafka:9092",
        "enable.idempotence": True,
        "queue.buffering.max.messages": 1000,
        "queue.buffering.max.kbytes": 2048,
        "message.timeout.ms": 5000,
    }
)
acked = set()
seen = set()
offsets = [None] * 3
errors = []
latencies = []
insert_latencies = []
last_receipt = 0
peak_backlog = 0
sample_times = []
last_sample = 0
start = time.monotonic()
wall_start = now_us()
accepted = 0
abort = None
event_offset = 0
input_hash = hashlib.sha256()


def ack(err, msg, identity):
    if err:
        errors.append(type(err).__name__)
    else:
        acked.add(identity)
        p = msg.partition()
        offsets[p] = max(offsets[p] if offsets[p] is not None else -1, msg.offset())


def sample():
    global last_receipt, peak_backlog, last_sample
    rows = c.execute(
        "SELECT r.receipt_id,r.event_id,r.inserted_at_us,(e.body->>'ingested_at_us')::bigint ingested FROM event_processing_receipts r JOIN events e USING(event_id) WHERE r.run_id=%s AND r.receipt_id>%s ORDER BY r.receipt_id",
        (run, last_receipt),
    ).fetchall()
    observed = now_us()
    for r in rows:
        seen.add(r["event_id"])
        last_receipt = r["receipt_id"]
        if r["ingested"] >= wall_start + 2000000:
            latencies.append((observed - r["ingested"]) / 1000000)
            insert_latencies.append((r["inserted_at_us"] - r["ingested"]) / 1000000)
    backlog = max(0, len(acked) - len(seen))
    peak_backlog = max(peak_backlog, backlog)
    sample_times.append(
        {
            "elapsed_s": round(time.monotonic() - start, 3),
            "acknowledged": len(acked),
            "persisted": len(seen),
            "backlog": backlog,
        }
    )
    last_sample = time.monotonic()
    return backlog


def quantiles(values):
    ordered = sorted(values)
    return {
        "samples": len(values),
        **{
            k: (
                ordered[min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))]
                if ordered
                else None
            )
            for k, q in [("p50_s", 0.5), ("p95_s", 0.95), ("p99_s", 0.99)]
        },
    }


try:
    for i in range(total):
        due = start + i / rate
        if time.monotonic() < due:
            time.sleep(max(0, due - time.monotonic()))
        src = f"192.0.2.{100+i%hosts}"
        target = "198.51.100.201"
        port = 7000 + (i // hosts) % 32 if cfg.get("pattern") == "scan" else 443
        t = base + int(i / rate * 1000000)
        ingested = now_us()
        event_id = digest([run, "synthetic-load", source_hash, "conn", event_offset])
        e = {
            "schema_version": "1.0",
            "event_id": event_id,
            "scope_id": run,
            "sensor_id": "synthetic-load",
            "run_id": run,
            "event_kind": "connection",
            "event_time_us": t + 1,
            "original_timestamp_us": t,
            "ingested_at_us": ingested,
            "published_at_us": now_us(),
            "time_basis": "connection_activity_end",
            "source_ip": src,
            "destination_ip": target,
            "source_port": 30000 + i % 30000,
            "destination_port": port,
            "protocol": "tcp",
            "zeek_uid": f"load{i}",
            "provenance": {
                "log_kind": "conn",
                "source_generation_id": source_hash,
                "record_offset": event_offset,
                "zeek_version": "synthetic-v1",
                "capture_id": scenario,
                "input_mode": "synthetic_fixture",
            },
            "connection": {
                "state": "SF",
                "duration_us": 1,
                "orig_bytes": 64,
                "resp_bytes": 64,
                "missed_bytes": 0,
            },
            "dns": None,
        }
        event_offset += (
            len(
                json.dumps(
                    {"index": i, "time": t, "source": src, "port": port},
                    separators=(",", ":"),
                ).encode()
            )
            + 1
        )
        raw = json.dumps(e, separators=(",", ":")).encode()
        producer.produce(
            "tracehawk.events.v1",
            partition=partition(run, src),
            key=json.dumps([run, src], separators=(",", ":")),
            value=raw,
            on_delivery=lambda err, msg, key=event_id: ack(err, msg, key),
        )
        accepted += 1
        input_hash.update(json.dumps([t + 1, src, target, port, "SF"]).encode())
        producer.poll(0)
        if time.monotonic() - last_sample >= 0.5:
            if sample() >= cfg.get("max_backlog", 3000):
                abort = "acknowledged backlog reached configured bound"
                break
        if errors:
            raise RuntimeError("Producer delivery error")
    assert producer.flush(6) == 0 and not errors
    publication_s = time.monotonic() - start
    sample()
    with c.transaction():
        c.execute(
            "UPDATE runs SET total_records=%s,next_index=%s,source_offsets=%s WHERE run_id=%s",
            (accepted, accepted, Jsonb(offsets), run),
        )
    control_acks = []
    for p in range(3):
        control = {
            "schema_version": "1.0",
            "control_kind": "replay_partition_complete",
            "run_id": run,
            "scope_id": run,
            "partition": p,
            "producer_generation": 1,
            "manifest_sha256": manifest_hash,
            "last_data_offset": offsets[p],
            "final_watermark_us": (meta["time_end_us"] + 9999999) // 10000000 * 10000000
            + 60000000,
        }
        VALIDATORS["replay-control"].validate(control)
        producer.produce(
            "tracehawk.events.v1",
            partition=p,
            value=json.dumps(control),
            on_delivery=lambda err, msg: control_acks.append(err is None),
        )
    assert producer.flush(6) == 0 and len(control_acks) == 3 and all(control_acks)
    drained_start = time.monotonic()
    deadline = drained_start + 180
    while time.monotonic() < deadline:
        sample()
        completed = (
            c.execute("SELECT status FROM runs WHERE run_id=%s", (run,)).fetchone()[
                "status"
            ]
            == "completed"
        )
        if seen == acked and completed:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Drain timeout")
    assert len(acked) == accepted and seen == acked
    alerts = [
        r["body"]
        for r in c.execute("SELECT body FROM alerts WHERE run_id=%s", (run,)).fetchall()
    ]
    signatures = sorted(
        [
            {
                "detector": a["detector_id"],
                "source": a["source_ip"],
                "observed": a["observed"],
                "evidence_count": a["evidence_total_count"],
            }
            for a in alerts
        ],
        key=lambda x: x["source"],
    )
    persisted_hash = hashlib.sha256()
    for e in c.execute(
        "SELECT event_time_us,host(source_ip) src,host(destination_ip) dst,destination_port FROM events WHERE run_id=%s ORDER BY event_time_us",
        (run,),
    ).fetchall():
        persisted_hash.update(
            json.dumps(
                [e["event_time_us"], e["src"], e["dst"], e["destination_port"], "SF"]
            ).encode()
        )
    assert persisted_hash.hexdigest() == input_hash.hexdigest()
    drain_s = time.monotonic() - drained_start
    elapsed = time.monotonic() - start
    report = {
        "status": "passed",
        "run_id": run,
        "config": cfg,
        "input_mode": "synthetic_fixture",
        "planned": total,
        "attempted": accepted,
        "kafka_acknowledged": len(acked),
        "unique_persisted": len(seen),
        "publication_s": publication_s,
        "total_to_completion_s": elapsed,
        "drain_after_publication_s": drain_s,
        "acknowledged_events_per_s": len(acked) / publication_s,
        "durable_events_per_s_including_drain": len(seen) / elapsed,
        "peak_acknowledged_backlog": peak_backlog,
        "target_completed": accepted == total and abort is None,
        "early_stop_reason": abort,
        "warmup_s": 2,
        "ingestion_to_durable_observation": quantiles(latencies),
        "ingestion_to_insertion_lower_bound": quantiles(insert_latencies),
        "durable_alerts": len(alerts),
        "durable_alert_effects_per_s": len(alerts) / elapsed,
        "database_bytes_before": database_bytes_before,
        "database_bytes_after": c.execute(
            "SELECT pg_database_size(current_database()) bytes"
        ).fetchone()["bytes"],
        "alert_effects": signatures,
        "content_sha256": input_hash.hexdigest(),
        "samples": sample_times,
        "monitoring": "on",
        "measurement_note": "Durable latency includes up to ~0.5s observer polling plus query scheduling; insertion clock is not commit time. Kafka controls excluded from event counters.",
    }
    print(json.dumps(report))
except Exception:
    with c.transaction():
        c.execute(
            "UPDATE runs SET status='failed' WHERE run_id=%s AND status<>'completed'",
            (run,),
        )
    raise
finally:
    c.close()
