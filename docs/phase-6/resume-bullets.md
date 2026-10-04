# TraceHawk project entry

**TraceHawk — Distributed Network Security Monitoring** · [GitHub](https://github.com/adineshreddy/TraceHawk)

Go, Python, Kafka, PostgreSQL, React, Docker, Kubernetes, Prometheus, Grafana

- Built a Zeek-based network monitoring pipeline with a Go collector and two Python consumers across three Kafka partitions, implementing four explainable detectors and an authenticated console with event evidence, host timelines and audited alert dispositions.
- Implemented transactional checkpoints, consumer ownership fencing and an at-least-once alert outbox; verified worker, broker and database recovery against a 108-event replay, and tested Kubernetes network isolation and retained-data cluster recreation.

The numbers describe tested configuration and laboratory evidence. Avoid “production-ready,” “exactly-once delivery,” “500 events/s sustained,” “deployed ML detection,” or an unqualified detection-accuracy percentage. For an interview, explain the two ML experiments, their false-positive tradeoffs and why the retrained models remain disabled. These bullets target the supplied networking/distributed-systems/Python/DevOps requirements; they do not establish job eligibility or promise an interview.
