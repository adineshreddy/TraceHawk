"""Extend the public contract with operator-only operational metadata."""

from pathlib import Path
import json, copy

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "contracts/openapi.json"
doc = json.loads(p.read_text())
string = {"type": "string"}
integer = {"type": "integer", "minimum": 0}
nullable = lambda s: {"anyOf": [s, {"type": "null"}]}
obj = lambda f: {
    "type": "object",
    "additionalProperties": False,
    "required": list(f),
    "properties": f,
}
arr = lambda s: {"type": "array", "items": s}
worker = obj(
    {
        "component": string,
        "status": string,
        "fresh": {"type": "boolean"},
        "details": {"type": "object"},
    }
)
partition = obj(
    {
        "partition": integer,
        "next_offset": integer,
        "ownership_epoch": integer,
        "owner_id": nullable(string),
        "broker_high": integer,
        "lag": integer,
        "fresh": nullable({"type": "boolean"}),
    }
)
queues = obj(
    {
        k: integer
        for k in [
            "pending_alert_updates",
            "pending_deadletters",
            "unreviewed_deadletters",
        ]
    }
)
deadletter = obj(
    {
        "partition": integer,
        "broker_offset": integer,
        "reason": string,
        "record_sha256": nullable(string),
        "record_bytes": nullable(integer),
        **{
            k: nullable({"type": "string", "format": "date-time"})
            for k in ["created_at", "delivered_at", "reviewed_at"]
        },
        "review_reason": nullable(string),
    }
)
for path, method, name, response, body in [
    (
        "/api/v1/operations",
        "get",
        "operations",
        obj(
            {
                "status": string,
                "workers": arr(worker),
                "partitions": arr(partition),
                "queues": queues,
            }
        ),
        None,
    ),
    (
        "/api/v1/deadletters",
        "get",
        "deadletters",
        obj({"items": arr(deadletter)}),
        None,
    ),
    (
        "/api/v1/deadletters/{partition}/{offset}/review",
        "post",
        "reviewDeadletter",
        obj({"status": {"const": "reviewed"}}),
        obj({"reason": {"type": "string", "minLength": 1, "maxLength": 500}}),
    ),
]:
    op = copy.deepcopy(doc["paths"]["/api/v1/runs/{run_id}"]["get"])
    op.update(
        operationId=name,
        description="Phase 3. Local-workspace operator access required; no quarantined payload bodies exposed.",
        parameters=[],
    )
    op["responses"]["200"]["content"]["application/json"]["schema"] = response
    if body:
        op["parameters"] = [
            {"name": k, "in": "path", "required": True, "schema": integer}
            for k in ["partition", "offset"]
        ] + [
            {"name": "X-CSRF-Token", "in": "header", "required": True, "schema": string}
        ]
        op["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": body}},
        }
    doc["paths"][path] = {method: op}
doc["info"]["version"] = "0.3.0"
p.write_text(json.dumps(doc, indent=2) + "\n")
