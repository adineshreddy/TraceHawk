# Initial threat model

Assets: session credentials, rule/indicator versions, alert/evidence integrity, processing checkpoints, demo manifests, and service availability. Actors: anonymous browser clients, authenticated analysts/operators, malformed telemetry producers, and failing infrastructure. Trusted components: packaged replay worker, locally controlled sensor/log files, broker assignments and database.

| Boundary / threat | Required control | Verification phase |
|---|---|---|
| Network names contain HTML/script | Escape text; no innerHTML or execution | 1/2 browser tests |
| Analyst accesses operator actions | Server-side role checks on every mutation | 1/2 negative API tests |
| Session theft / CSRF | Password hashes; bounded login; HttpOnly SameSite cookie; origin and CSRF checks; expiry | 1 |
| Replay request injects command/path | Allowlisted scenario ID; durable job; no arbitrary shell or path arguments | 1 |
| Record injects future time | Validate run bounds before watermark advancement | 1/2 |
| Record imitates completion control | Separate schema plus producer/run/epoch/offset validation | 1/3 |
| Duplicate/resubmitted record alters counts | Stable provenance identity and DB uniqueness before counting | 1/3 |
| Competing revoked consumer writes stale state | Fenced partition ownership and transactional checkpoints | 3 |
| Large event or high source cardinality | 64 KiB event limit, 1 MiB source line limit, bounded state; visible saturation | 1/3 |
| DB/broker outage creates silent gaps | Pause, retry, durable offsets, retention checks | 3 |
| Rule change silently rewrites evidence | Immutable rule snapshots and audit records | 2 |
| Private data leaks through logging/metrics | Metadata-only logs; no raw packet payload or unbounded label values | 1/3 |
| Local dependencies are exposed remotely | Loopback UI/monitoring, private DB/Kafka, no Docker socket in API | 1/5 |

Local HTTP session cookies cannot be Secure until TLS is configured. Remote hosting requires TLS, secure cookies, broker authentication/ACLs and an additional threat-model review. Kubernetes manifests must be tested rather than treated as security evidence by their presence.

No arbitrary PCAP upload, automatic blocking, untrusted model loading or remote administration in the initial release. Packaged PCAP processing still uses resource caps and a pinned parser image. Repository secrets and local password files are ignored.
