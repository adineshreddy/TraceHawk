"""Document the authenticated, packaged research summary."""

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def schema(value, key=""):
    if key in ("precision", "recall"):
        return {
            "anyOf": [{"type": "number", "minimum": 0, "maximum": 1}, {"type": "null"}]
        }
    if isinstance(value, dict):
        return {
            "type": "object",
            "additionalProperties": False,
            "required": list(value),
            "properties": {k: schema(v, k) for k, v in value.items()},
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "items": schema(value[0]) if value else {"type": "string"},
            "maxItems": 100,
        }
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer", "minimum": 0}
    if isinstance(value, float):
        return {"type": "number", "minimum": 0}
    if value is None:
        return {"type": ["string", "null"]}
    return {"type": "string", "maxLength": 1000}


p = ROOT / "contracts/openapi.json"
doc = json.loads(p.read_text())
op = copy.deepcopy(doc["paths"]["/api/v1/runs/{run_id}"]["get"])
op.update(
    operationId="evaluation",
    parameters=[],
    description="Authenticated read-only frozen synthetic evaluation summary. Accessible to operators and analysts; contains no workspace/account data. Capacity target failures and disabled offline model are explicit.",
)
op["responses"]["200"]["content"]["application/json"]["schema"] = schema(
    json.loads((ROOT / "evaluation/reports/summary.json").read_text())
)
doc["paths"]["/api/v1/evaluation"] = {"get": op}
doc["info"]["version"] = "0.4.0"
p.write_text(json.dumps(doc, indent=2) + "\n")
