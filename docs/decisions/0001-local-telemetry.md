# ADR 0001: Offline Zeek and local deployment

Status: Accepted for initial release.

Use Zeek 8.0.10 with an immutable image digest and ARM64 execution. Begin with controlled offline PCAP -> JSON logs, then replay normalized records. Go remains the collector language and Python the detector/API language. The baseline has no LLM or Redis.

The local host/Docker resource budget supports a phased Compose build. UI uses port 3100 and monitoring 9190/3190, avoiding observed 8080/5173 conflicts. Kafka/PostgreSQL are private in the application profile. The Phase 0 temporary Kafka probe is loopback-bound and removed afterward.

Consequence: reproducible demos without live capture permissions or cloud charges. Replay latency does not establish live-capture latency. Kubernetes is a later local deployment outcome. See dependencies.json for digest/version pins and evidence for what actually ran.
