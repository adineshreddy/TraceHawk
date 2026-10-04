# API and console contract

[OpenAPI](../../contracts/openapi.json) is a validated Phase 1 design contract. It contains authentication, overview, alert list/detail/status, rule versions and replay-run endpoints. No API is running in Phase 0.

HTTP responses use bounded JSON objects and a common Error shape. Session cookie `tracehawk_session` is opaque and HttpOnly; the session endpoint returns a separate CSRF token. Mutations require `X-CSRF-Token` and same-origin validation; login uses origin checks and rate limiting. Authorization is checked server-side, including every scoped object read. Local analyst/operator accounts are generated during Phase 1 setup.

Alert list uses stable cursor pagination ordered by creation time and alert ID, limit 25/default and 100/max. Phase 2 adds validated filters for source, destination, detector, severity, status, suppression, time and run. Unknown resources return 404 without leaking another scope. Mutation reasons are audited. Resolve/acknowledge affects disposition only.

Operator start creates a durable Run and returns 202; IDs are allowlisted and one run can actively replay at a time. Worker transitions `queued -> preparing -> replaying -> finalizing -> completed`; cancellation and failure are explicit terminal states. API completion is not broker acknowledgment or detector completion. A run becomes completed only after all partition completions are applied and evidence is durable; alert-topic delivery may still be pending and is reported separately.

Readiness differentiates API reachability, DB access, broker availability, processing freshness and replay progress. Host evidence is not queried through Prometheus. Console uses two-second bounded polling, backs off on errors, and shows stale/degraded state rather than freezing an apparently healthy view.

Later Phase 2 endpoint families: `/hosts/{ip}/activity`, `/events`, `/suppressions`, `/indicators`, `/scenarios`; Phase 3 adds operational health and metrics. Their full schemas must be added before implementation. Authentication tests must also prove mutation denial to anonymous/incorrect-role users.

The wireframe shows all planned pages; it is explicitly an illustrative navigation prototype without backend behavior. It is not the production React app.
