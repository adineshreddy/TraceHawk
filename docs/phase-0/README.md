# Phase 0: completed specification and compatibility

This report records the Phase 0 milestone. Current application status and evidence are in [Phase 1](../phase-1/README.md).

Date: October 3, 2026. Workspace root: `/Users/dinesh/TraceHawk`.

## Completion evidence

| Gate | Result | Evidence |
|---|---|---|
| Local tools/resources | Go, Python, Node, Docker and Compose present; ARM64 host; local ports selected | [Preflight](../evidence/preflight.json) |
| Zeek PCAP feasibility | 137 offline packets -> 68 connection records and 40 DNS records | [Zeek probe](../evidence/zeek-probe.json) |
| Protocol behavior | 24 REJ, 3 S0, 1 SF TCP records; 32 NXDOMAIN, 8 NOERROR DNS records | [Controlled scenario](../../scenarios/phase0/manifest.json) |
| Missing field handling | Three unanswered records have no duration; normalized fallback is labeled | [Normalized records](../../scenarios/phase0/normalized-events.jsonl) |
| Python contracts | Seven schemas, 28 schema cases, five semantic negative cases and 108 normalized records pass | [Python result](../evidence/contracts-python.json) |
| Go contract parity | Same seven schemas and 28 cases pass with format assertions enabled | [Go result](../evidence/contracts-go.json) |
| API design | OpenAPI 3.1 structure and embedded schema parity validate | [OpenAPI result](../evidence/openapi.json) |
| Kafka/client compatibility | Kafka 4.3.0: actual Go record consumed by Python; Python produce acknowledged | [ARM64 runtime result](../evidence/runtime-probe.json) |
| Frontend compatibility | Minimal React/TSX bundle builds with selected React/Vite packages | [Build result](../evidence/frontend-probe.json) |
| Console workflow design | Seven screens navigate; desktop/mobile checks pass, no browser exceptions | [Wireframe result](../evidence/wireframes.json) |
| Architecture/security/semantics | Product, threat model, rule behavior and four ADRs defined | [Architecture](architecture.md), [detection spec](detection-spec.md), [decisions](../decisions/0001-local-telemetry.md) |

## What exists

Design documentation, schemas/examples, validator/probe tools, original controlled PCAP, real Zeek-derived development fixtures, a static console wireframe, version pins and recorded results. External reference projects informed design; none of their application implementation was copied.

What remains: actual service code, database migrations, authentication, detections, pipeline recovery tests, production console and performance/accuracy evaluation. Those are later phase gates. Docker image metadata and a minimal build do not prove that the full Compose/Kubernetes system will work.

## Reproduction

Create the isolated Python environment using the root README, then:

```sh
.venv/bin/python tools/generate_phase0_pcap.py
.venv/bin/python tools/probe_zeek.py
.venv/bin/python tools/normalize_phase0.py
.venv/bin/python tools/validate_contracts.py
go -C tools/compatibility run ./cmd/contracts
python3 tools/probe_runtime.py
```

PCAP generator never transmits packets. Zeek runs with no network and no capabilities. The runtime probe creates its own `tracehawk-phase0-kafka` container, uses loopback port 19092, and removes it in a finally block. If a previous interrupted run left that name, inspect it before removing it; the tool refuses to remove preexisting resources. Image downloads may consume disk/network time. No existing containers are stopped or reconfigured.

Zeek UIDs vary on regeneration. Stable capture bytes/protocol counts are expected, but log hashes and normalized IDs can change when a fresh Zeek output generation is created. Labels and expectations remain separate from detector inputs. This fixture is constructed to exercise known patterns and cannot establish accuracy.

Frontend reproduction:

```sh
python3 tools/probe_frontend.py
```

This restores locked probe packages into ignored `tmp/phase0`, builds a minimal TSX bundle and records the result. The same packages support the [wireframe browser check](wireframes.md). Actual Node 24 production-image builds are a Phase 1 check; the initial host build used Node 25.6.1.

## Phase 0 limitations carried forward

- Live capture/idle watermarks and multi-sensor observation overlap are deferred.
- Rules do not identify failed logins from failed TCP connections.
- One local Kafka broker cannot demonstrate broker high availability.
- Service-level semantic enforcement, ownership fencing, authentication and recovery are specified but not implemented.
- Top-level application pins are smoke-tested; deployment transitive locks and SBOM are later tasks.
- `kind` is missing locally and only required in Phase 5; no cluster was created or installation attempted.

Next: implement the bounded Phase 1 vertical slice using [the backlog](phase1-backlog.md).
