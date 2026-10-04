# TraceHawk evaluation v1

Frozen synthetic sensitivity/counterexample corpus; not representative real-world accuracy.

Inputs: 28 pinned-Zeek captures; 12 held out. Production phase2-rules-v1 unchanged. Matching was frozen before evaluation; labels never enter canonical events.

## Held-out rule episodes

| Family | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| vertical_tcp_scan | 1 | 0 | 1 | 100.0% | 50.0% |
| failed_tcp_connections | 1 | 1 | 0 | 50.0% | 100.0% |
| dns_nxdomain_burst | 1 | 1 | 0 | 50.0% | 100.0% |
| known_indicator | 2 | 0 | 0 | 100.0% | 100.0% |
| horizontal_scan (unsupported) | 0 | 0 | 1 | — | 0.0% |

The fast scan, rejected-attempt episode, DNS burst and two fictional exact-indicator episodes were detected. The low-rate vertical scan was missed. Horizontal scanning is outside the implemented rule families. Legitimate outage retries and stale/typo DNS bursts each caused an actionable alert. An explicit pre-replay authorization suppressed one scan finding while preserving its evidence.

The six held-out benign sources have **0.50 declared laboratory host-hours** and **2 actionable alerts**, yielding 4.0 alerts/host-hour within these synthetic intervals. This tiny constructed exposure is not a production false-positive-rate estimate.

## Optional ML experiment

Isolation Forest uses 50 benign training windows, 30 development-validation windows and 60 held-out windows. Its strict cutoff is selected only from validation benign windows. Features do not contain labels, IP addresses or capture names. Missing denominators have explicit flags.

Exported JSON score parity error: 7.22e-16; artifact SHA-256: `9b65008f107bf5453359b38cc61a9f80dfa3730135471d540877692a137475e3`.

| Source-episode method | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| rules | 4 | 2 | 2 | 66.7% | 66.7% |
| ml | 1 | 1 | 5 | 50.0% | 16.7% |
| combined | 4 | 2 | 2 | 66.7% | 66.7% |

The generic source-episode comparison includes horizontal scanning, collapses indicator/other families from the same source/bucket, and applies the same explicit authorization policy. It differs from the per-family table. The model adds no new true positives; the union reproduces the rules results. **The model remains offline and is not enabled in the application.** A score is neither an attack probability nor a detector-family attribution.

## Measured short load trials

Real Kafka/PostgreSQL consumers, default rules, monitoring on; 480 synthetic events per trial, 40 events/s offered for 12 seconds, two repeats per configuration. The direct generator bypasses Go source replay and API admission. A two-second warm-up is excluded from latency samples; rate denominators include publication and drain.

| Workers | Sources | Mean durable events/s incl. drain | Maximum observed p95 (s) |
|---:|---:|---:|---:|
| 1 | 1 | 38.40 | 0.523 |
| 1 | 32 | 38.40 | 0.503 |
| 2 | 1 | 38.41 | 0.503 |
| 2 | 32 | 38.43 | 0.502 |

The 500 events/s × 600 seconds engineering attempt failed early after 27.65 seconds of publication. Reason: acknowledged backlog reached configured bound. **The ten-minute sustained-capacity target is not established.** See benchmark.json for acknowledged/persisted counts, the observed peak backlog (which can exceed the sampled stopping threshold), drain time and overloaded latency.

Durable-observation latency is an upper bound measured by committed receipt polling and includes roughly 0.5 seconds of observer delay plus query scheduling. Database insertion clocks are lower bounds, not commit timestamps. No packet-capture availability or Go normalization throughput is inferred. Hardware/resource samples and full publication/backlog/drain curves are in benchmark.json.

## Recovery and limits

A loaded 480-event scan workload was repeated with a detector SIGKILL/restart. The persisted time/source/destination/port projection and alert metrics/evidence counts match the uninterrupted reference. Every acknowledged event was uniquely persisted. This supplements Phase 3 database/broker/rebalance tests; it does not demonstrate high availability or unlimited retention.

UI visibility measurements are in docs/phase-4/browser.json. Short trial rates and tiny synthetic precision/recall fractions must not become broad production claims. Frozen data and original generator are included; Zeek-generated UIDs are frozen outputs, not guaranteed to repeat byte-for-byte when reprocessing PCAPs.

Regenerate with the commands in docs/phase-4/README.md.
