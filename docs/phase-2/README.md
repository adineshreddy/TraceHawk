# Phase 2: four detectors and evidence-led investigation

Phase 2 extends the working replay pipeline with failed TCP connection patterns, DNS NXDOMAIN bursts and exact indicator matching alongside port-scan detection. The console adds host drill-down, measured evidence timelines, query-backed alert filters, immutable configuration editing and scoped suppression records.

## Run and demonstrate

```sh
python3 tools/setup_dev.py
docker compose up -d --build --wait --wait-timeout 180
python3 tools/doctor.py
```

Open **http://127.0.0.1:3100**. Use the generated `operator` credentials in `tmp/credentials.json`. Existing Phase 1 data is preserved by migration `002_detection_investigation.sql`; old runs keep the `phase1-scan-v1` snapshot.

A three-minute demonstration:

1. **Replay** the controlled scan + DNS scenario at 10× using **phase2-rules-v1**. The 108 events yield **six alerts**: one scan, one failed-connection pattern, one DNS burst, and three indicator episodes grouped by source/destination. These are overlapping observations of the same capture, not six independent attacks.
2. In **Alerts**, filter to the DNS detector. Open its 40 response records, 10-second evidence timeline and measured matching windows. Explain why peak count and ratio can come from different qualifying windows; each window's actual values remain available.
3. Follow the source address into **Host investigation**. Inspect activity, related alerts, chronological event pages and known/unknown coverage. Failed TCP connections are not failed authentication. Missing response codes remain unknown.
4. Record a reason and acknowledge an alert. Refresh to show persisted status and relevant audit history.
5. Replay with **Authorize the lab scanner** enabled. The suppression is installed atomically before publishing. The scan finding remains inspectable with 24 connections and its reason; five findings remain unsuppressed. The overview counts open unsuppressed and suppressed findings separately.
6. Replay the **benign baseline** with the same default rule: 17 events and no alerts.
7. In **Rules**, inspect the rule and indicator JSON. To change configuration, create a new version and explicitly select it for another replay. Existing versions and runs do not change.

## Detector behavior

| Detector | Group | Default trigger | Evidence |
|---|---|---|---|
| Vertical TCP scan | source + destination | 20 distinct ports / 60s | Recognized TCP records, including established connections |
| Failed TCP connections | source + destination | 20 classified attempts and failure ratio ≥0.8 | S0/REJ in the numerator; recognized TCP states except OTH in the denominator |
| DNS NXDOMAIN burst | source | 30 completed responses and NXDOMAIN ratio ≥0.6 | Numeric response code; missing codes excluded |
| Exact indicator | source + destination IP, or source + DNS queries | Exact canonical destination IP or normalized query match | Matched value, immutable version, description and event |

The default **phase2-fictional-v1** list deliberately matches the reserved-address destination `192.0.2.20` and the fixture query `host0.example.test`. Its provenance and the UI explicitly label it as fictional development data. There is no threat-feed download, suffix/domain expansion, DNS lookup or claim that these addresses are malicious.

Temporal rules retain the existing 60-second half-open windows, 10-second cadence, 30-second lateness and scoped completion barriers. Indicator matching also applies to stored late events, with their temporal exclusion reason retained. An on-time earlier event can initialize an earlier still-open window; it cannot revise a finalized window.

Alerts keep deterministic five-minute bucket identities, unique evidence and peak metrics. New `alert_windows` rows preserve each qualifying window's coherent counts and ratios, avoiding the implication that independently observed peaks belong to one window. Indicator counts mean unique matching events, not duplicate deliveries.

## Suppression semantics

Suppressions are immutable, source- and scope-specific records. A destination is exact when supplied; null means any destination. The validity interval is **[start, expiry)** and uses the latest contributing event time when an alert episode is first created. That decision is frozen for the episode: later configuration or expiry does not rewrite an existing finding. A different episode can receive a different decision. If multiple policies match, the lowest immutable suppression ID is chosen deterministically.

The operator may choose the historical capture interval for a controlled replay, or wall-clock now plus one hour. Historical event-time validity is stored separately from the current audit creation timestamp. A wall-clock suppression will not match older replay events. Pre-replay suppression templates avoid racing the collector; **Authorize the lab scanner** uses this path.

Adding a suppression to an already completed run records a policy and audit entry but does not retroactively hide its existing alerts. Suppressed findings retain status, exact suppression ID, reason, evidence and rule snapshot. Analysts can read and record dispositions; rule, indicator, replay and suppression creation requires an operator plus the existing origin/CSRF checks.

## Verification

| Check | Result / evidence |
|---|---|
| Fresh migrations and upgrade | [Migration report](migrations.json): fresh schema, idempotent seeds and checksum mismatch rejection in a disposable private database; actual Phase 1 database upgraded without a reset |
| Actual controlled and benign replays | [Integration report](integration.json): 108 events and 1/1/1/3 alerts; benign 17 events / zero alerts |
| Configuration and suppression | Immutable versions, canonical indicators, explicit run snapshots, operator checks, cross-workspace isolation, atomic pre-replay suppression and retained evidence |
| Thresholds and unknown outcomes | [Semantics report](semantics.json): inclusive counts/ratios and below-threshold cases; null/OTH/UDP exclusion from classified denominators |
| Event-time order | Ordered and on-time reordered events yield identical bucket features, evidence counts and measured windows; duplicate completion has no effect |
| Late records and exact matching | Watermark equality stores the exclusion reason; exact indicators still apply; subdomain/suffix lookalikes do not match |
| Suppression boundaries | Inclusive start, exclusive expiry; explicit event-time basis; 201 evidence events preserve exact totals while IDs cap at 200 |
| Browser workflow | [Browser report](browser.json), actual screenshots in this directory |
| Contracts | 24 implemented public operations match OpenAPI; integration responses validate against their schemas |
| Existing pipeline guarantees | Phase 1 replay, restart, collector crash and transaction regression scripts remain in CI |

Repeat Phase 2 checks after the stack is ready:

```sh
python3 tools/verify_phase2_migrations.py
.venv/bin/python tools/verify_phase2.py
docker compose exec -T api python - < tools/verify_phase2_semantics.py > docs/phase-2/semantics.json
tools/verify_browser.sh phase2
```

Use the [Phase 1 guide](../phase-1/README.md) to install the locked Python/tooling dependencies and console packages. The semantics tests call production queries and processing functions with synthetic boundary cases inside one transaction and roll back their rows and checkpoint changes. The integration/browser scripts create actual replay runs; run them sequentially when no user replay is active. The GitHub workflow now runs both phases but has not executed remotely during local development.

## Boundaries and next work

This remains an offline, single-detector-instance development deployment. Broker redundancy, two-consumer rebalance, alert outbox delivery, streamed dead letters, metrics/Grafana, outage/backpressure tests and live ingestion remain Phase 3 or later work. No LLM is needed. The two small fixtures demonstrate behavior; they do not establish false-positive rates, accuracy or throughput.

Host lists and related alerts are bounded at 100 entries; event inspection uses chronological keyset pagination. Evidence rows cap at 200 while total counts and timelines remain exact. Configuration lists are bounded at 100 versions, and the replay selector shows the latest 50 runs. Indicator payloads are subject to the API's 64 KiB body limit and schema limits.

Phase 3 will establish reliability and operational evidence before broader deployment or resume performance claims.
