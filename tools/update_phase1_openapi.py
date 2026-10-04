"""Refresh the implemented Phase 1 surface while preserving canonical schemas."""

from pathlib import Path
import copy, json

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "contracts/openapi.json"
x = json.loads(p.read_text())
if 'phase2' in x['info']['version']:
    raise SystemExit('Historical Phase 1 generator will not overwrite Phase 2. Use tools/update_phase2_openapi.py.')
x["info"]["version"] = "1.0.0-phase1"
x["info"][
    "description"
] = "TraceHawk Phase 1 authenticated local replay and port-scan investigation API."
for route, methods in x["paths"].items():
    for verb, op in methods.items():
        op["description"] = "Implemented in Phase 1. " + (
            "Operator permission required."
            if route == "/api/v1/rules"
            or route.startswith("/api/v1/runs")
            and verb == "post"
            else (
                "Authenticated workspace access required."
                if route != "/api/v1/session/login"
                else "Same-origin local session login."
            )
        )
        for code in ("409", "413", "429"):
            op["responses"][code] = {
                "description": {
                    "409": "Conflict",
                    "413": "Body too large",
                    "429": "Rate limited",
                }[code],
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            }


def endpoint(operation, schema, parameters=None):
    op = copy.deepcopy(x["paths"]["/api/v1/runs/{run_id}"]["get"])
    op.update(
        operationId=operation,
        description="Implemented in Phase 1. Authenticated workspace access required.",
        parameters=parameters or [],
    )
    op["responses"]["200"]["content"]["application/json"]["schema"] = schema
    return op


ref = lambda name: {"$ref": "#/components/schemas/" + name}
obj = lambda props: {
    "type": "object",
    "additionalProperties": False,
    "required": list(props),
    "properties": props,
}
x["paths"]["/api/v1/runs"]["get"] = endpoint(
    "listRuns", obj({"items": {"type": "array", "maxItems": 50, "items": ref("Run")}})
)
x["paths"]["/api/v1/scenarios"] = {
    "get": endpoint(
        "listScenarios",
        obj(
            {
                "items": {
                    "type": "array",
                    "items": obj(
                        {
                            k: {"type": "string"}
                            for k in ("scenario_id", "label", "description")
                        }
                    ),
                }
            }
        ),
    )
}
x["components"]["schemas"]["Evidence"] = obj(
    {
        "items": {"type": "array", "maxItems": 200, "items": ref("Event")},
        "history": {
            "type": "array",
            "maxItems": 30,
            "items": obj(
                {
                    "actor": {"type": "string"},
                    "action": {"type": "string"},
                    "details": {"type": "object"},
                    "created_at": {"type": "string", "format": "date-time"},
                }
            ),
        },
    }
)
x["paths"]["/api/v1/alerts/{alert_id}/evidence"] = {
    "get": endpoint(
        "getAlertEvidence",
        ref("Evidence"),
        copy.deepcopy(x["paths"]["/api/v1/alerts/{alert_id}"]["get"]["parameters"]),
    )
}
x["paths"]["/api/v1/session/logout"]["post"]["responses"]["200"]["content"][
    "application/json"
]["schema"] = obj({"logged_out": {"const": True}})
for parameter in x["paths"]["/api/v1/alerts"]["get"]["parameters"]:
    if parameter["name"] == "cursor":
        parameter["schema"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
x["paths"]["/api/v1/alerts"]["get"][
    "description"
] += " Cursor uses ascending immutable alert IDs within the scope."
p.write_text(json.dumps(x, indent=2) + "\n")
