# Phase 1 backlog: one working investigation

Status: completed locally; see [Phase 1 implementation and evidence](../phase-1/README.md). The GitHub workflow is configured; remote CI execution remains unverified.

Goal: clean local startup -> controlled replay -> one port-scan alert -> supporting evidence in an authenticated console. Finish this path before adding other detectors or ML.

| Order | Work item | Acceptance |
|---|---|---|
| 1 | Service manifests, exact transitive locks, build images and Compose core | ARM64 build; versioned images; private Kafka/DB; loopback console; bounded resources; clean readiness |
| 2 | API-owned migrations: users/sessions, runs, events, partition state, alerts/evidence/outbox and audits | Fresh DB migration; uniqueness/FKs; rollback/recreate behavior documented |
| 3 | Go offline normalization using Phase 0 event contract | Actual fixture parity; Decimal-equivalent microsecond rounding; identity and Murmur2 vectors; missing values preserved; max line/event bounds |
| 4 | Ordered publisher and source checkpoints | Checkpoint only after prior acknowledgments; retries preserve IDs; cancellation state; no silent data drop |
| 5 | Durable single-consumer processing | Event dedup before counting; transaction commits events/state/offset/alert/outbox; seek from DB on assignment; visible errors |
| 6 | Port-scan rule with time windows and trusted end barriers | Exact boundaries/late policy; final windows flush; explicit rule snapshot; one deterministic alert per bucket |
| 7 | Authenticated API vertical slice | Login/session/logout, overview, alert list/detail, status, rule read and run lifecycle; role/origin/CSRF checks; OpenAPI parity |
| 8 | React console vertical slice | Login, overview, inbox, evidence investigation, replay status; real API values; empty/error/loading states |
| 9 | Setup/doctor/reset and targeted CI | Single documented startup; generated ignored credentials; reset only named TraceHawk resources; schema/build/unit/small integration checks |
| 10 | Phase 1 verification report and rehearsal | Clean install run, genuine PCAP-to-alert flow, benign no-scan case, replay/restart idempotence and evidence links |

## Critical tests

- Window boundary, duplicate event, timestamp fallback and invalid-control cases.
- Publish acknowledgment followed by collector crash before checkpoint.
- DB transaction rollback leaves no partial count/checkpoint/alert effect.
- Consumer restart with partial scan window preserves evidence/result.
- Anonymous/analyst cannot invoke operator replay/rule changes.
- Alert source text is escaped; evidence queries cannot cross scopes.
- Browser flow reads persisted alerts and changes status through the real API.

Phase 3 adds multi-consumer/rebalance/outage guarantees. Phase 1 should use their compatible state shape but cannot claim those outcomes before tests. No throughput or detection-accuracy resume claims until later reports exist.
