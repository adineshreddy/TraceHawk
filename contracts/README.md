# Contracts

JSON Schema draft 2020-12 is the canonical wire contract. IDs use `https://tracehawk.local/schemas/` as identifiers, not a network dependency. All schema validation is local. Objects reject unknown fields, versions are explicit, and timestamps are integer microseconds within JavaScript's safe integer range.

Schemas: event, replay control, alert, immutable rules, indicators, suppression and development scenario. `validation-cases.json` contains the shared Python/Go acceptance/rejection cases. Ground-truth labels are accepted only by scenario manifests, never by the runtime event envelope.

Schema validity does not establish trusted identity, authorization, correct timestamps or consistent evidence. The Python validator additionally exercises cross-field invariants (duration/time basis, publication ordering, alert intervals/suppression/evidence counts) and all actual normalized Zeek records. The Phase 1 collector and detector enforce schema, identity, source, time and publication checks during processing.

Event identity is SHA-256 of compact JSON `[scope_id, sensor_id, source_generation_id, log_kind, record_offset]`. Immutable source-generation IDs are created when logs are finalized; whole-file hash is suitable for the initial offline release. Tail/rotation identities need a persisted generation registry before live collection. Separate identical records at distinct offsets remain distinct; retries preserve the tuple.

`openapi.json` embeds canonical schemas for the implemented Phase 4 API (28 public operations). The validator checks those copies against their source files and validates OpenAPI structure. HTTP object authorization and role behavior remain implementation tests.

```sh
.venv/bin/python tools/validate_contracts.py
go -C tools/compatibility run ./cmd/contracts
```

`requirements-phase0.lock.txt` locks validator/generator dependencies for the host tooling. `requirements-runtime-probe.txt` pins principal application libraries and is an actual Linux ARM64 compatibility smoke input; the backend hash lock is in `services/backend/requirements.lock`. Go compatibility dependencies are locked in `tools/compatibility/go.mod` and go.sum. Frontend probe manifests/lock are stored beside them; application manifests and locks are under `services/collector` and `services/console`. Actual response validation and access-control tests are in `tools/verify_phase1.py` and `tools/verify_phase2.py`. Indicator and suppression wire schemas remain unchanged; Phase 2 run responses expose the selected indicator version, and replay requests optionally install scoped suppression templates before publishing.

Phase 3 adds local-operator operations, quarantine list and audited review endpoints. Outbound alert updates carry a stable `update_id` plus monotonic per-alert `revision`; consumers deduplicate and keep the greatest revision. Dead-letter messages carry a stable source-topic/partition/offset identity, bounded diagnostic metadata and a fingerprint, excluding raw payloads. See [Phase 3 delivery semantics](../docs/phase-3/README.md).

Phase 4 adds authenticated `GET /api/v1/evaluation` for the packaged synthetic research summary, accessible to both roles. It exposes measured limitations and the disabled offline model without workspace/account data. Canonical event/alert schemas are unchanged.
