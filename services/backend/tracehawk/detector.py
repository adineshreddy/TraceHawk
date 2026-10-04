"""Consumer-group detection with PostgreSQL checkpoint and ownership fencing."""

import json, os, signal, time, hashlib, uuid
from jsonschema.exceptions import ValidationError
from confluent_kafka import Consumer, TopicPartition
from psycopg.types.json import Jsonb
from .core import db, VALIDATORS, validate_event, health
from .operations import Probes, log
from .detections import scan_groups, temporal_matches, persist_alert, match_indicator

STOP = False
STEP = 10000000
WINDOW = 60000000
LATENESS = 30000000
BUCKET = 300000000


def stop(*_):
    global STOP
    STOP = True


def window_end(t):
    return t // STEP * STEP + STEP


def finalize(c, run, p, watermark, rules):
    end = p["next_window_end_us"]
    if end is None:
        return
    if (watermark - end) // STEP > 1000:
        raise RuntimeError("Window saturation")
    while end <= watermark:
        for detector, g, observed, thresholds in temporal_matches(
            c, run, p["partition"], end, rules
        ):
            persist_alert(c, run, rules, detector, g, end, observed, thresholds)
        end += STEP
    c.execute(
        "UPDATE run_partitions SET next_window_end_us=%s,watermark_us=%s WHERE run_id=%s AND partition=%s",
        (end, watermark, run["run_id"], p["partition"]),
    )


def apply(c, partition, offset, raw, epoch, fault=None, owner_id=None):
    checkpoint = c.execute(
        "SELECT * FROM partition_checkpoints WHERE partition=%s FOR UPDATE",
        (partition,),
    ).fetchone()
    if checkpoint["ownership_epoch"] != epoch or (
        owner_id is not None and checkpoint["owner_id"] != owner_id
    ):
        raise RuntimeError("Ownership lost")
    if offset < checkpoint["next_offset"]:
        return
    try:
        with c.transaction():
            if len(raw) > 65536:
                raise ValueError("Oversized event")
            e = json.loads(raw)
            if not isinstance(e, dict):
                raise ValueError("Invalid envelope")
            run = c.execute(
                "SELECT * FROM runs WHERE run_id=%s FOR NO KEY UPDATE",
                (e.get("run_id"),),
            ).fetchone()
            if not run:
                raise ValueError("Unknown run")
            if run["status"] in ("cancelled", "failed"):
                # Cancellation retains accepted evidence and skips already queued records.
                c.execute(
                    "UPDATE partition_checkpoints SET next_offset=%s WHERE partition=%s",
                    (offset + 1, partition),
                )
                return
            p = c.execute(
                "SELECT * FROM run_partitions WHERE run_id=%s AND partition=%s FOR UPDATE",
                (run["run_id"], partition),
            ).fetchone()
            rules = c.execute(
                "SELECT body FROM rule_versions WHERE version=%s",
                (run["rule_version"],),
            ).fetchone()["body"]
            if "control_kind" in e:
                VALIDATORS["replay-control"].validate(e)
                expected = (
                    run["metadata"]["time_end_us"] + STEP - 1
                ) // STEP * STEP + WINDOW
                if (
                    e["scope_id"] != run["scope_id"]
                    or e["partition"] != partition
                    or e["producer_generation"] != run["generation"]
                    or e["manifest_sha256"] != run["metadata"]["manifest_sha256"]
                    or e["last_data_offset"] != p["last_data_offset"]
                    or e["final_watermark_us"] != expected
                ):
                    raise ValueError("Untrusted completion")
                finalize(c, run, p, expected, rules)
                c.execute(
                    "UPDATE run_partitions SET completed_generation=%s WHERE run_id=%s AND partition=%s",
                    (run["generation"], run["run_id"], partition),
                )
                n = c.execute(
                    "SELECT count(*) n FROM run_partitions WHERE run_id=%s AND completed_generation=%s",
                    (run["run_id"], run["generation"]),
                ).fetchone()["n"]
                if n == 3:
                    c.execute(
                        "UPDATE runs SET status='completed' WHERE run_id=%s",
                        (run["run_id"],),
                    )
            else:
                validate_event(e, run)
                eligible = (
                    p["watermark_us"] is None or e["event_time_us"] > p["watermark_us"]
                )
                inserted = c.execute(
                    "INSERT INTO events VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(event_id) DO NOTHING RETURNING event_id",
                    (
                        e["event_id"],
                        run["run_id"],
                        partition,
                        offset,
                        e["event_time_us"],
                        e["source_ip"],
                        e["destination_ip"],
                        e["destination_port"],
                        e["event_kind"],
                        e["protocol"],
                        eligible,
                        Jsonb(e),
                    ),
                ).fetchone()
                c.execute(
                    "UPDATE run_partitions SET last_data_offset=%s WHERE run_id=%s AND partition=%s",
                    (offset, run["run_id"], partition),
                )
                if inserted:
                    if not eligible:
                        c.execute(
                            "INSERT INTO event_exclusions VALUES(%s,%s,%s)",
                            (
                                e["event_id"],
                                "at_or_before_watermark",
                                p["watermark_us"],
                            ),
                        )
                    match_indicator(c, run, rules, e)
                    size = c.execute(
                        "SELECT count(*) n,count(DISTINCT source_ip) sources FROM events WHERE run_id=%s AND partition=%s AND event_time_us>%s",
                        (
                            run["run_id"],
                            partition,
                            (p["watermark_us"] or e["event_time_us"]) - WINDOW,
                        ),
                    ).fetchone()
                    if size["n"] > 100000 or size["sources"] > 1000:
                        raise RuntimeError("State saturation")
                    if p["next_window_end_us"] is None or (
                        eligible
                        and window_end(e["event_time_us"]) < p["next_window_end_us"]
                    ):
                        p["next_window_end_us"] = window_end(e["event_time_us"])
                        c.execute(
                            "UPDATE run_partitions SET next_window_end_us=%s WHERE run_id=%s AND partition=%s",
                            (p["next_window_end_us"], run["run_id"], partition),
                        )
                    maximum = max(
                        p["max_time_us"] or e["event_time_us"], e["event_time_us"]
                    )
                    watermark = max(
                        p["watermark_us"] or maximum - LATENESS, maximum - LATENESS
                    )
                    c.execute(
                        "UPDATE run_partitions SET max_time_us=%s WHERE run_id=%s AND partition=%s",
                        (maximum, run["run_id"], partition),
                    )
                    finalize(c, run, p, watermark, rules)
            if fault:
                raise RuntimeError("Injected transaction rollback")
    except (ValueError, KeyError, TypeError, ValidationError) as error:
        c.execute(
            "INSERT INTO deadletters(partition,broker_offset,reason,record_sha256,record_bytes) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (
                partition,
                offset,
                type(error).__name__,
                hashlib.sha256(raw).hexdigest(),
                len(raw),
            ),
        )
    c.execute(
        "UPDATE partition_checkpoints SET next_offset=%s WHERE partition=%s",
        (offset + 1, partition),
    )


def serve_group(probe, worker, owner):
    connection = db()
    connection.autocommit = True
    epochs = {}
    consumer = Consumer(
        {
            "bootstrap.servers": os.getenv("KAFKA_BROKERS", "kafka:9092"),
            "group.id": "tracehawk-detector-v1",
            "client.id": worker,
            "group.protocol": "classic",
            "partition.assignment.strategy": "roundrobin",
            "session.timeout.ms": 6000,
            "heartbeat.interval.ms": 1000,
            "max.poll.interval.ms": 60000,
            "socket.timeout.ms": 5000,
            "enable.auto.commit": False,
            "enable.auto.offset.store": False,
            "auto.offset.reset": "error",
            "queued.max.messages.kbytes": 1024,
            "fetch.message.max.bytes": 65536,
        }
    )

    def assign(client, partitions):
        probe.update("assigning")
        assignments = []
        with connection.transaction():
            for part in sorted(partitions, key=lambda p: p.partition):
                row = connection.execute(
                    "UPDATE partition_checkpoints SET ownership_epoch=ownership_epoch+1,owner_id=%s,owner_seen_at=now() WHERE partition=%s RETURNING *",
                    (owner, part.partition),
                ).fetchone()
                low, high = client.get_watermark_offsets(part, timeout=3)
                if not low <= row["next_offset"] <= high:
                    raise RuntimeError("Required Kafka history unavailable")
                epochs[part.partition] = row["ownership_epoch"]
                assignments.append(
                    TopicPartition(part.topic, part.partition, row["next_offset"])
                )
        client.assign(assignments)
        with connection.transaction():
            health(
                connection,
                worker,
                "ready" if epochs else "idle",
                {"owner_id": owner, "partitions": sorted(epochs)},
            )
        probe.increment("tracehawk_rebalances_total")
        log(worker, "assigned", partitions=sorted(epochs))

    def revoke(client, partitions):
        probe.update("rebalancing")
        # No Kafka commit here: the database is the sole recovery authority.
        with connection.transaction():
            for part in partitions:
                connection.execute(
                    "UPDATE partition_checkpoints SET ownership_epoch=ownership_epoch+1,owner_id=NULL,owner_seen_at=NULL WHERE partition=%s AND owner_id=%s",
                    (part.partition, owner),
                )
        with connection.transaction():
            health(
                connection, worker, "rebalancing", {"owner_id": owner, "partitions": []}
            )
        epochs.clear()
        client.unassign()
        log(worker, "revoked", partitions=[p.partition for p in partitions])

    consumer.subscribe(
        ["tracehawk.events.v1"], on_assign=assign, on_revoke=revoke, on_lost=revoke
    )
    last = 0
    try:
        while not STOP:
            msg = consumer.poll(0.2)
            if msg:
                if msg.error():
                    raise RuntimeError("Kafka consumer error")
                with connection.transaction():
                    apply(
                        connection,
                        msg.partition(),
                        msg.offset(),
                        msg.value(),
                        epochs[msg.partition()],
                        owner_id=owner,
                    )
                probe.increment("tracehawk_processed_records_total")
                # A failed broker commit is safe: the next assignment seeks DB progress.
                consumer.commit(message=msg, asynchronous=False)
            if time.monotonic() - last >= 2:
                lag = 0
                with connection.transaction():
                    for part, epoch in epochs.items():
                        low, high = consumer.get_watermark_offsets(
                            TopicPartition("tracehawk.events.v1", part), timeout=3
                        )
                        row = connection.execute(
                            "UPDATE partition_checkpoints SET owner_seen_at=now(),broker_high=%s WHERE partition=%s AND ownership_epoch=%s AND owner_id=%s RETURNING next_offset",
                            (high, part, epoch, owner),
                        ).fetchone()
                        if not row or row["next_offset"] < low:
                            raise RuntimeError("Ownership or history lost")
                        lag += max(0, high - row["next_offset"])
                    health(
                        connection,
                        worker,
                        "ready" if epochs else "idle",
                        {"owner_id": owner, "partitions": sorted(epochs), "lag": lag},
                    )
                probe.update(
                    "ready" if epochs else "idle",
                    tracehawk_partition_lag=lag,
                    tracehawk_assigned_partitions=len(epochs),
                )
                last = time.monotonic()
    finally:
        try:
            consumer.close()
        finally:
            connection.close()


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    worker = os.getenv("WORKER_ID", "detector-a")
    probe = Probes(worker)
    while not STOP:
        try:
            serve_group(probe, worker, worker + ":" + uuid.uuid4().hex)
        except Exception as error:
            # Unassign/close on dependency failure; no records are consumed past a
            # failed transaction. A new session reloads durable state and offsets.
            probe.increment("tracehawk_recovery_errors_total")
            probe.update("paused")
            try:
                with db() as c:
                    health(c, worker, "paused", {"error_type": type(error).__name__})
            except Exception:
                pass
            log(worker, "paused", error_type=type(error).__name__)
            for _ in range(10):
                if STOP:
                    break
                time.sleep(0.2)
                probe.update("paused")
    probe.update("stopped")


if __name__ == "__main__":
    main()
