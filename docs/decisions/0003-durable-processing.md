# ADR 0003: PostgreSQL processing state and idempotent effects

Status: Accepted architecture; crash/rebalance behavior must be verified in implementation.

Persist events, window state, watermark, next Kafka offset, alert/evidence and outbox update together. Acknowledge Kafka only after database commit. Resume from the DB next offset and reject recovery when required retained broker history has expired. Offsets can have gaps; compare broker positions rather than assuming consecutive integers.

Assignment protocol: pause newly assigned partitions; obtain a database partition-row lock; atomically claim a new monotonically increasing ownership epoch; load durable offsets/state; seek; resume. Each batch locks the row and verifies its epoch. A newer assignment fences older writers. On revocation pause and finish/rollback the current transaction before dropping cached state; relinquish ownership conditionally on the current epoch. A process death leaves an old epoch that the next assignment replaces. An old transaction holding the row may commit before a new claimant obtains the lock; new state load must include that commit.

Phase 1 uses one consumer and the same transactional persistence shape. Phase 3 must test concurrent claims, revocation/crash points and callback behavior in the actual client before claiming fencing correctness. Heartbeat/rebalance timeouts must exceed bounded DB work; no background thread may bypass ownership checks.

Outbox messages may repeat after an acknowledgment/mark-delivered crash. Stable update IDs and alert revisions identify duplicates; database alert state is authoritative. Collector source IDs/checkpoints similarly tolerate Kafka publish/checkpoint replay.

Consequence: at-least-once delivery with idempotent durable effects within tested boundaries. No global exactly-once claim. Database batch overhead is a known profiling target. In-memory caches never advance durable progress and reload after rollback.
