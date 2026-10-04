"""At-least-once transactional outbox delivery; keys identify duplicate updates."""

import json
import os
import signal
import time
from pathlib import Path
from confluent_kafka import Producer
from .core import db, digest, health
from .operations import Probes, log, snapshot

STOP = False


def stop(*_):
    global STOP
    STOP = True


def deliver(c, producer, deadletter=False):
    if deadletter:
        row = c.execute(
            "SELECT * FROM deadletters WHERE delivered_at IS NULL ORDER BY created_at,partition,broker_offset FOR UPDATE SKIP LOCKED LIMIT 1"
        ).fetchone()
        if not row:
            return False
        key = digest(["tracehawk.events.v1", row["partition"], row["broker_offset"]])
        topic = "tracehawk.deadletters.v1"
        body = {
            "schema_version": "1.0",
            "deadletter_id": key,
            "source_topic": "tracehawk.events.v1",
            **{
                k: row[k]
                for k in (
                    "partition",
                    "broker_offset",
                    "reason",
                    "record_sha256",
                    "record_bytes",
                )
            },
        }
    else:
        row = c.execute(
            "SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY created_at,alert_id,(body->>'revision')::bigint FOR UPDATE SKIP LOCKED LIMIT 1"
        ).fetchone()
        if not row:
            return False
        key, topic = row["update_id"], "tracehawk.alerts.v1"
        body = {"schema_version": "1.0", "update_id": key, **row["body"]}
    ack = []
    producer.produce(
        topic,
        key=key if deadletter else row["alert_id"],
        value=json.dumps(body, separators=(",", ":")),
        on_delivery=lambda err, msg: ack.append(err),
    )
    if producer.flush(4) or not ack or ack[0] is not None:
        raise RuntimeError("Delivery not acknowledged")
    # Explicit local crash hook used by the recovery verifier. It contains only
    # an update ID and is consumed once before exiting, after ACK and before SQL.
    hook = Path("/state/fault_after_ack")
    if not deadletter and hook.exists() and hook.read_text().strip() == key:
        hook.unlink()
        log("publisher", "injected_crash_after_ack", update_id=key)
        os._exit(17)
    if deadletter:
        c.execute(
            "UPDATE deadletters SET delivered_at=now() WHERE partition=%s AND broker_offset=%s",
            (row["partition"], row["broker_offset"]),
        )
    else:
        c.execute("UPDATE outbox SET delivered_at=now() WHERE update_id=%s", (key,))
    return True


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    probe = Probes("publisher")
    producer = Producer(
        {
            "bootstrap.servers": os.getenv("KAFKA_BROKERS", "kafka:9092"),
            "enable.idempotence": True,
            "message.timeout.ms": 3000,
            "socket.timeout.ms": 2000,
            "queue.buffering.max.messages": 100,
            "queue.buffering.max.kbytes": 1024,
        }
    )
    while not STOP:
        try:
            with db() as c:
                # Singleton ordering across revisions, separate from row safety.
                if not c.execute(
                    "SELECT pg_try_advisory_xact_lock(841103) held"
                ).fetchone()["held"]:
                    raise RuntimeError("Publisher already active")
                delivered = deliver(c, producer)
                delivered_dlq = deliver(c, producer, True)
            with db() as c:
                health(c, "publisher")
                state = snapshot(c)
                health(c, "detector", state["status"], state["queues"])
            q = state["queues"]
            probe.update(
                "degraded" if q["unreviewed_deadletters"] else "ready",
                tracehawk_pending_alert_updates=q["pending_alert_updates"],
                tracehawk_pending_deadletters=q["pending_deadletters"],
                tracehawk_unreviewed_deadletters=q["unreviewed_deadletters"],
                tracehawk_pipeline_ready=int(state["status"] == "ready"),
            )
            if delivered:
                probe.increment("tracehawk_delivered_alert_updates_total")
            if delivered_dlq:
                probe.increment("tracehawk_delivered_deadletters_total")
            if not delivered and not delivered_dlq:
                time.sleep(0.5)
        except Exception as error:
            probe.update("paused")
            try:
                with db() as c:
                    health(
                        c, "publisher", "paused", {"error_type": type(error).__name__}
                    )
                    health(c, "detector", "degraded")
            except Exception:
                pass
            probe.increment("tracehawk_delivery_errors_total")
            log("publisher", "paused", error_type=type(error).__name__)
            time.sleep(1)
    probe.update("stopped")


if __name__ == "__main__":
    main()
