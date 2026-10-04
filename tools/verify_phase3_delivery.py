"""Inspect actual retained output values using stable delivery IDs and alert schema."""

import json, time, uuid
from confluent_kafka import Consumer, TopicPartition, KafkaError
from tracehawk.core import db, digest, VALIDATORS

with db() as c:
    target = c.execute(
        "SELECT update_id,alert_id FROM outbox WHERE delivered_at IS NOT NULL ORDER BY created_at DESC,(body->>'revision')::bigint DESC LIMIT 1"
    ).fetchone()
    rejected = c.execute(
        "SELECT * FROM deadletters ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
assert target and rejected and rejected["delivered_at"]
dlq_id = digest(
    ["tracehawk.events.v1", rejected["partition"], rejected["broker_offset"]]
)
consumer = Consumer(
    {
        "bootstrap.servers": "kafka:9092",
        "group.id": "delivery-verifier-" + uuid.uuid4().hex,
        "enable.auto.commit": False,
        "enable.partition.eof": True,
    }
)
assignments = []
ends = {}
done = set()
counts = {"alert_updates": 0, "quarantines": 0}
found = set()
for topic in ["tracehawk.alerts.v1", "tracehawk.deadletters.v1"]:
    for part in range(3):
        low, high = consumer.get_watermark_offsets(
            TopicPartition(topic, part), timeout=5
        )
        assignments.append(TopicPartition(topic, part, low))
        ends[(topic, part)] = high
        if low == high:
            done.add((topic, part))
consumer.assign(assignments)
deadline = time.monotonic() + 30
try:
    while len(done) < 6 and time.monotonic() < deadline:
        msg = consumer.poll(0.2)
        if not msg:
            continue
        pair = (msg.topic(), msg.partition())
        if msg.error():
            assert msg.error().code() == KafkaError._PARTITION_EOF
            done.add(pair)
            continue
        body = json.loads(msg.value())
        assert body["schema_version"] == "1.0"
        if msg.topic() == "tracehawk.alerts.v1":
            assert set(body) == {
                "schema_version",
                "update_id",
                "alert_id",
                "revision",
                "alert",
            }
            assert body["update_id"] == digest([body["alert_id"], body["revision"]])
            VALIDATORS["alert"].validate(body["alert"])
            assert body["alert"]["alert_id"] == body["alert_id"]
            counts["alert_updates"] += 1
            if body["update_id"] == target["update_id"]:
                assert msg.key().decode() == body["alert_id"]
                found.add("latest_alert_key")
        else:
            assert set(body) == {
                "schema_version",
                "deadletter_id",
                "source_topic",
                "partition",
                "broker_offset",
                "reason",
                "record_sha256",
                "record_bytes",
            }
            assert body["deadletter_id"] == digest(
                [body["source_topic"], body["partition"], body["broker_offset"]]
            )
            assert msg.key().decode() == body["deadletter_id"]
            counts["quarantines"] += 1
            if body["deadletter_id"] == dlq_id:
                assert (
                    body["record_sha256"] == rejected["record_sha256"]
                    and body["record_bytes"] == rejected["record_bytes"]
                )
                found.add("durable_quarantine_fingerprint")
        if msg.offset() + 1 >= ends[pair]:
            done.add(pair)
finally:
    consumer.close()
assert len(done) == 6 and found == {
    "latest_alert_key",
    "durable_quarantine_fingerprint",
}
print(
    json.dumps(
        {
            "status": "passed",
            "checked_retained_records": counts,
            "checks": [
                "alert schema and deterministic update identity",
                "latest update routes by alert ID",
                "dead-letter identity and committed input fingerprint",
                "operational records exclude raw payloads",
            ],
        },
        indent=2,
    )
)
