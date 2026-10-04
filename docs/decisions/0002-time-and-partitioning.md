# ADR 0002: Event time, replay controls and source partitioning

Status: Accepted for replay-driven release.

Use microsecond integer times; connection time is activity-end approximation with a labeled start-time fallback; DNS uses transaction start. Duration unknown is distinct from zero. The measured unanswered records justify this policy.

Use three partitions and explicit Java-compatible Murmur2 routing of compact JSON `[scope_id, source_ip]`. Watermarks are scoped per run within each partition. First rules aggregate by originating host, so source affinity preserves local state; destination-wide detectors would require another stream.

Finalize 60-second windows on 10-second boundaries behind a 30-second watermark delay. Too-late temporal events are searchable but excluded. Ordered, verified completion barriers flush each scope/partition. Live idle-time handling is deferred.

Consequence: reproducible results independent of replay wall-clock speed under the declared ordering/lateness policy. One hot source remains a partition bottleneck. Independent sensors cannot be summed without an explicit overlap model. See detection-spec.md for boundaries and alert buckets.
