# Product specification

TraceHawk helps an analyst investigate suspicious network activity from Zeek metadata. The initial product is a local, replay-driven network monitoring application. It is not an inline firewall, packet-capture appliance, or a claim of production threat coverage.

## Users and workflows

- Analyst: select a run, inspect alerts, follow evidence to a host, and record acknowledgement/resolution.
- Operator: start/cancel an allowlisted scenario, create a rule version, and manage scoped suppressions.
- Reviewer: reproduce a documented scenario and inspect architecture, metrics and limitations.

The primary journey is overview -> alert inbox -> alert evidence -> host activity -> disposition. Replay and operational health support the journey, rather than replace investigation.

## Release requirements

1. Every alert displays observed values, thresholds, rule version, source provenance and evidence references.
2. Every view shows the selected run and input mode. Synthetic/replayed traffic is visibly identified.
3. Unknown protocol fields stay unknown; missing login information cannot become brute-force evidence.
4. Acknowledgement/resolution is an analyst decision, independent of detector severity and suppression.
5. Suppressions retain findings, are scoped and expire; the inbox can reveal suppressed alerts.
6. The application reports degraded ingestion/processing instead of showing a misleading healthy badge.
7. Controls modify persistent state through authenticated APIs; screenshots cannot substitute for functioning workflows at release.

## Initial detectors

Vertical TCP scan; repeated failed TCP connections; DNS NXDOMAIN burst; exact IP/domain indicator match. Threshold definitions are in [detection-spec.md](detection-spec.md). ML is optional after the rule baseline. No LLM is required.

## Demo definition

A five-minute recording should show benign replay, a scan, an evidence investigation, DNS detection, suppression/disposition, and detector restart/backlog recovery. Preparation is explicit and replay is labeled. Phase 0 wireframes contain illustrative values only.

## Success measures

Usable investigation, reproducible setup, alert evidence completeness, scenario-level detection results and recovery correctness. Throughput and latency targets in PROJECT_PLAN.md are goals until measured, not current achievements.
