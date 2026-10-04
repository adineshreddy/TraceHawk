# Detection specification v1

Status: Defined in Phase 0; implemented and tested in Phase 2. See [implementation evidence](../phase-2/README.md). Defaults are engineering hypotheses for development, not proven optimal security thresholds.

| Rule ID | Eligible events / group | Trigger | Default severity |
|---|---|---|---|
| vertical_tcp_scan | TCP connection, source + destination | >=20 distinct destination ports in 60 seconds | high |
| failed_tcp_connections | TCP connection, source + destination | >=20 classified attempts and failure count / classified count >=0.8 | medium |
| dns_nxdomain_burst | DNS response records, source | >=30 responses with numeric rcode and NXDOMAIN count / response count >=0.6 | medium |
| known_indicator | Connection destination IP; DNS normalized query | Exact match against snapshotted indicator list | high |

TCP classified denominator includes recognized states except OTH; missing states and OTH are unknown and excluded with separate counts. Failure numerator contains S0 and REJ only. Established/responder-reset states are not failed authentication. Scan counting includes any recognized TCP record with a valid destination port, including established connections, because the behavior is port diversity. It never equates scanning to confirmed exploitation.

DNS completed-response denominator requires numeric rcode; rcode=3 contributes to NXDOMAIN. Missing response codes are unknown, not failures. Preserve qtype and trans_id for evidence. DNS over TLS/HTTPS is not visible as plaintext query metadata in these logs.

Indicator names are lowercased and stripped of one terminal root dot; IPs are canonicalized. No suffix matching, external feed fetch or DNS resolution occurs. Fictional indicators are labeled as such.

## Time contract

All contract times are integer Unix microseconds bounded by JavaScript's safe integer limit. Parse Zeek decimals without binary-float conversion; round to nearest microsecond with half-even rounding. `original_timestamp_us` preserves first activity/transaction start.

Connection event time is original time plus known duration, labelled `connection_activity_end`. When duration is missing, use original time and label `original_start_fallback`. Zero duration is known and distinct from null. This is an activity-end approximation: Zeek duration does not include all trailing TCP packets and is not the time the record was written. DNS uses original transaction start, labelled `dns_transaction_start`. Ingestion/publication times measure collector processing separately.

Windows `[end-60s,end)` end on UTC 10-second boundaries. For each scope within each Kafka partition, watermark is the maximum eligible event time observed minus 30 seconds, monotonic. No run may advance another run's watermark. Reject timestamps outside declared replay bounds before advancing time.

An arrival at/before the pre-arrival watermark is too late for temporal features; persist it and its reason but do not revise final windows. Exact indicator matching still applies. On-time events belong to all not-yet-finalized applicable windows. At the watermark equality boundary the matching window is final. Specify/test ties and empty windows.

Replay producer merges normalized log records by `(event_time_us, event_id)` and preserves per-partition order. Completion control is separate from telemetry and explicitly sent to each of three partitions after all that partition's data acknowledgments. The detector verifies registered producer epoch, scope/run/manifest, Kafka partition, and expected last data offset. Only then advance that scope's final watermark through `ceil(last_event_time/10s)*10s + 60s`. Duplicate completion is idempotent. This flushes all potential trailing windows; no forged event field grants control authority.

Live capture and idle-time watermarks are deferred. Connection log latency and duration fallback prevent promises of packet-instant alerts.

## Alert grouping and identity

Identity tuple is `[scope_id, rule_version, detector_id, source_ip, destination_ip_or_null, floor(first_matching_window_end_us/300000000)*300000000]`. Serialize as canonical UTF-8 compact JSON and SHA-256. Each matching window belongs to the bucket determined by its own end time; its first matching window creates that bucket's alert. The bucket may contain multiple matching windows. Deterministic fixed buckets can split one sustained incident; this is an explicit limitation.

Use unique event evidence and maximum observed metrics; never sum overlapping-window counts. Evidence times describe evidence, not ingestion. Persist matched window boundaries, explanatory thresholds and template version. Indicator matches use their event time for bucket selection.

No arbitrary severity escalation in v1. Critical is reserved for a later separately defined rule. Ratios and severity are not attack probabilities. Reasons must distinguish rejected connections, absent responses, port diversity and indicator matches.

## Configuration and limits

Rules and indicator versions are immutable snapshots selected at run creation. Suppressions apply in the current processing transaction using their event-time validity interval; retain the exact matched suppression ID/version in each result. Changes do not retroactively rewrite existing alerts. The first creation of an episode evaluates validity using its latest contributing event time and freezes its decision. A null destination applies to any destination; if multiple immutable suppressions match, the lowest suppression ID is selected deterministically. Their validity is `[created_at_us, expires_at_us)`; analysts must see which time basis governs historical replay. Historical demo suppressions are created from scenario manifests through an operator-only workflow, with current audit creation time stored separately.

Start with at most one active replay, 100,000 retained active-window events per partition and 1,000 active sources per run. On exhaustion pause processing and report resource saturation; never silently sample exact counts. These limits can be revised after measurement. Alert evidence can be capped independently while counts remain exact.

## Development fixture expectations

The controlled PCAP produces 24 rejected different-port TCP records, three unanswered TCP records, one normal TCP record and 40 DNS records with 32 NXDOMAIN. It should exercise scan, failure and DNS rules after window flushing. That is a feasibility expectation, not measured detector accuracy. Known-indicator examples are fictional contract fixtures. Benign outages, authorized scanners and unseen captures remain Phase 2/4 evaluation work.

References: [pinned Zeek Conn::Info](https://docs.zeek.org/en/v8.0.10/scripts/base/protocols/conn/main.zeek.html), [connection logs](https://docs.zeek.org/en/v8.0.10/logs/conn.html), [DNS logs](https://docs.zeek.org/en/v8.0.10/logs/dns.html).
