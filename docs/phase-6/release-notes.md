# TraceHawk v1.0.0 — network monitoring laboratory

TraceHawk turns offline Zeek network telemetry into explainable alerts and an authenticated investigation workflow. The release includes a Go collector, three Kafka event partitions, two Python detection workers, PostgreSQL evidence/state, a durable at-least-once alert publisher, a React console, Prometheus and Grafana.

The demo includes a controlled 108-event replay with six alerts, a 17-event benign baseline with zero alerts, DNS evidence/host investigation, audited acknowledgement and scan suppression with retained evidence. Two consecutive fresh-scope Chromium rehearsals pass. A 92-second silent walkthrough is attached; the repository also includes a five-minute narration script and project resume bullets.

Local Kubernetes includes enforced network isolation, application container hardening, pod restart and retained-data cluster recreation tests. Original evaluation PCAPs, provenance, labels, safe model artifacts and reproducible tooling are included. Both ML experiments remain offline. The 500-events/s ten-minute capacity target failed early and remains visible in the reports. This release makes no production accuracy, HA, live capture or cloud deployment claim.

Start locally with `python3 tools/demo.py`. See the README for prerequisites and generated private operator credentials, and `docs/phase-6/README.md` for the demo/runbook. GitHub Actions status and remote verification evidence are linked from the repository.
