# Dependency and compatibility matrix

Checked October 3, 2026. Exact image digests and registry metadata are in [dependencies.json](dependencies.json). Prefer those immutable digests over the displayed tags.

## Executed probes

| Component | Selected version | Evidence / boundary |
|---|---|---|
| Zeek | 8.0.10 | Linux ARM64; actual offline PCAP processed |
| Kafka | 4.3.0 | Linux ARM64 broker; Go/Python messages exercised |
| Go / franz-go | 1.26.0 / v1.22.1 | Host ARM64 producer executed against broker |
| Python runtime | 3.13.16 | Linux ARM64 imports and Kafka consume/produce executed |
| Python host tooling | 3.14.2 | Contracts, normalization and capture generation executed |
| confluent-kafka / librdkafka | 2.15.1 / 2.15.1 | Actual ARM64 wheel and broker interaction |
| FastAPI / Pydantic | 0.142.2 / 2.13.5 | Imports and minimal model/application smoke |
| SQLAlchemy / Alembic / psycopg | 2.1.3 / 1.20.0 / 3.3.6 | Imports; SQLAlchemy SQLite query; PostgreSQL integration remains Phase 1 |
| PostgreSQL | 17.11-alpine | Existing native image; postgres --version checked; DB application not started |
| React / React DOM | 19.3.0 / 19.3.0 | Minimal Vite build on host Node 25.6.1 |
| Vite / TypeScript | 8.3.2 / 7.0.2 | TSX transpilation/build; compiler version checked |
| Playwright | 1.63.0 | Chromium desktop/mobile wireframe navigation |
| JSON Schema Python / Go | 4.26.0 / v6.0.3 | Same 28 cases; format validation enabled |
| OpenAPI validator | 0.9.0 | OpenAPI 3.1 structure and schema copy parity |
| Scapy | 2.8.0 | Development-only deterministic offline packet construction |

## Image support checked without application execution

| Component | Selection | Remaining check |
|---|---|---|
| Node build image | Node 24 bookworm-slim, digest pinned | Production container build in Phase 1 |
| Go build image | 1.26.0-bookworm, digest pinned | Collector build in Phase 1 |
| Prometheus | v3.13.3, locally present ARM64 digest | Metrics integration in Phase 3 |
| Grafana | 13.2.3, locally present ARM64 digest | Dashboard provisioning in Phase 3 |

Host: 16 GiB RAM, 10 CPUs; Docker allocation approximately 7.75 GiB. About 46 GiB host disk was available after image downloads at the recorded preflight. Recheck before Phase 1 rather than treating this as permanent. kind is absent and not needed until Phase 5.

## Principal license inventory

| Component | License |
|---|---|
| zeek | BSD-3-Clause |
| apache-kafka | Apache-2.0 |
| franz-go | BSD-3-Clause |
| confluent-kafka-python | Apache-2.0 |
| jsonschema-go | Apache-2.0 |
| jsonschema-python | MIT |
| scapy | GPL-2.0-only (development fixture generation) |
| fastapi | MIT |
| pydantic | MIT |
| sqlalchemy | MIT |
| alembic | MIT |
| psycopg | LGPL-3.0-only |
| react | MIT |
| react-dom | MIT |
| vite | MIT |
| typescript | Apache-2.0 |
| playwright | Apache-2.0 |
| prometheus | Apache-2.0 |
| grafana | AGPL-3.0-only |
| postgresql | PostgreSQL |

Packages are used as dependencies; no implementation code from the five example projects was copied. Keep applicable upstream notices when building/distributing images. The full transitive inventory/SBOM belongs with production locks.

## Pinning and reproduction

Python host tools use requirements-phase0.lock.txt; Go uses go.mod/go.sum; frontend probe uses the checked-in package lock. Runtime probe pins top-level libraries and verifies available ARM64 wheels; transitive deployment locks are created in Phase 1. Container images are recorded with exact digests in dependencies.json.

This macOS Python installation initially lacked a usable default CA configuration. System `/etc/ssl/cert.pem` worked with verification enabled; no insecure download flags were used.
