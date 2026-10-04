# ADR 0004: Evidence-first console and honest evaluation

Status: Accepted.

Build React investigation pages alongside the Phase 1 vertical slice. Grafana remains operational tooling; the analyst console owns alerts, evidence, host activity, replay and disposition. Static Phase 0 wireframes are labeled examples.

Rule results retain features, thresholds, versions and source IDs. Exact counts remain separate from capped displayed evidence. Use deterministic five-minute buckets rather than unspecified incident correlation. Keep all suppressed findings and record analyst actions.

Separate feasibility fixtures from accuracy evaluation. The controlled development capture deliberately exercises configured patterns and cannot establish precision/recall. Add independent benign counterexamples and held-out scenarios before reporting quality. ML stays opt-in until comparative evaluation justifies it; an LLM is outside scope.

Consequence: project claims can be reproduced and defended. The UI must communicate ambiguity, lateness and truncation. A polished demo does not imply production readiness.
