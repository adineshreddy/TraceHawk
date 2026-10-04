# Scenarios

`phase0/manifest.json` describes the original controlled development capture. It contains 137 offline constructed packets; no traffic was transmitted. `zeek/` contains actual Zeek output, and `normalized-events.jsonl` is a contract fixture with explicitly synthetic ingestion/publication times. Ground truth is in the manifest, separate from runtime events.

| Planned scenario | Purpose | State |
|---|---|---|
| Controlled TCP/DNS development capture | Feasibility and known-pattern coverage | Generated; telemetry verified |
| Benign browsing/DNS | Negative end-to-end baseline | Phase 1 |
| Authorized scanner | Suppression and ambiguous scan behavior | Phase 2 |
| Service outage/retries | Failure-rule benign counterexample | Phase 2 |
| Threshold and temporal edges | Window, ratios, missing fields and late events | Phase 1/2 |
| Fictional indicator match/non-match | Exact matching without real malicious endpoints | Contract examples now; pipeline Phase 2 |
| Duplicate/reordered replay | Delivery/window correctness | Phase 1/3 |
| Crash/rebalance/DB outage | Recovery comparison | Phase 3 |
| Independent benign/attack captures | Held-out quality evaluation | Phase 4 |

Development patterns are not independent evaluation. Each later scenario must have provenance, license, hashes, bounds and ground-truth episodes before use in an accuracy report. Small source fixtures belong in Git; large captures need separate bounded storage.
