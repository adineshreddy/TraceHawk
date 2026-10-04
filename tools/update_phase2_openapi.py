"""Document the implemented Phase 2 surface without changing canonical wire schemas."""

from pathlib import Path
import json, copy

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "contracts/openapi.json"
doc = json.loads(p.read_text())
schemas = doc["components"]["schemas"]
paths = doc["paths"]
ref = lambda name: {"$ref": "#/components/schemas/" + name}
obj = lambda fields: {
    "type": "object",
    "additionalProperties": False,
    "required": list(fields),
    "properties": fields,
}
arr = lambda schema, maximum=None: dict(
    type="array", items=schema, **({"maxItems": maximum} if maximum is not None else {})
)
string = {"type": "string"}
integer = {"type": "integer", "minimum": 0}
nullable = lambda schema: {"anyOf": [schema, {"type": "null"}]}


def parameter(name, where="query", required=True, schema=string):
    return {"name": name, "in": where, "required": required, "schema": schema}


def operation(name, response, params=None, method="get", body=None, code="200"):
    op = copy.deepcopy(paths["/api/v1/runs/{run_id}"]["get"])
    op.update(
        operationId=name,
        description="Implemented Phase 2. "
        + (
            "Operator permission required."
            if method == "post"
            else "Authenticated workspace access required."
        ),
        parameters=params or [],
    )
    op["responses"][code] = op["responses"].pop("200")
    op["responses"][code]["content"]["application/json"]["schema"] = response
    if method != "get":
        op["parameters"].append(parameter("X-CSRF-Token", "header"))
    if body:
        op["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": body}},
        }
    return op


schemas["Run"]["required"] = list(
    dict.fromkeys(schemas["Run"]["required"] + ["indicator_version"])
)
schemas["Run"]["properties"]["indicator_version"] = nullable(string)
schemas["SuppressionTemplate"] = obj(
    {
        "detector_id": copy.deepcopy(
            schemas["Suppression"]["properties"]["detector_id"]
        ),
        "source_ip": copy.deepcopy(schemas["Suppression"]["properties"]["source_ip"]),
        "destination_ip": copy.deepcopy(
            schemas["Suppression"]["properties"]["destination_ip"]
        ),
        "reason": copy.deepcopy(schemas["Suppression"]["properties"]["reason"]),
    }
)
schemas["RunRequest"]["properties"]["suppression_templates"] = arr(
    ref("SuppressionTemplate"), 20
)
schemas["SuppressionRequest"] = obj(
    {
        **schemas["SuppressionTemplate"]["properties"],
        "scope_id": string,
        "validity_mode": {"enum": ["scenario_interval", "from_now"]},
    }
)
schemas["TimelineBin"] = obj(
    {
        "start_us": integer,
        "event_count": integer,
        "failed_tcp": integer,
        "dns_nxdomain": integer,
    }
)
schemas["HostTimelineBin"] = obj({"start_us": integer, "event_count": integer})
schemas["EventEligibility"] = obj(
    {
        "event_id": string,
        "eligible_for_temporal_rules": {"type": "boolean"},
        "exclusion_reason": nullable(string),
    }
)
schemas["Evidence"]["properties"].update(
    {
        "timeline": arr(ref("TimelineBin")),
        "matched_windows": arr(
            obj(
                {
                    "window_start_us": integer,
                    "window_end_us": integer,
                    "observed": copy.deepcopy(
                        schemas["Alert"]["properties"]["observed"]
                    ),
                }
            )
        ),
        "indicator_matches": arr(
            obj(
                {
                    key: string
                    for key in ["event_id", "version", "kind", "value", "description"]
                }
            ),
            200,
        ),
        "suppression": nullable(ref("Suppression")),
        "event_eligibility": arr(ref("EventEligibility"), 200),
    }
)
schemas["Evidence"]["required"] = list(schemas["Evidence"]["properties"])
schemas["Host"] = obj(
    {
        "address": string,
        "event_count": integer,
        "outbound": integer,
        "inbound": integer,
        "alert_count": integer,
    }
)
schemas["HostDetail"] = obj(
    {
        "address": string,
        "scope_id": string,
        "event_count": integer,
        "first_event_time_us": integer,
        "last_event_time_us": integer,
        "coverage": obj(
            {
                key: integer
                for key in [
                    "tcp_classified",
                    "tcp_unknown",
                    "dns_completed",
                    "dns_unknown",
                    "late_events",
                ]
            }
        ),
        "alerts": arr(ref("Alert"), 100),
        "timeline": arr(ref("HostTimelineBin"), 1000),
    }
)
schemas["EventPage"] = obj(
    {
        "items": arr(
            obj(
                {
                    "event": ref("Event"),
                    "eligible_for_temporal_rules": {"type": "boolean"},
                    "exclusion_reason": nullable(string),
                }
            ),
            100,
        ),
        "next_cursor": nullable(string),
    }
)
paths["/api/v1/rules"]["get"] = operation(
    "listRuleVersions", obj({"items": arr(ref("Rules"), 100)})
)
paths["/api/v1/indicators"] = {
    "get": operation(
        "listIndicatorVersions", obj({"items": arr(ref("Indicators"), 100)})
    ),
    "post": operation(
        "createIndicatorVersion",
        ref("Indicators"),
        method="post",
        body=ref("Indicators"),
        code="201",
    ),
}
paths["/api/v1/indicators/{version}"] = {
    "get": operation(
        "getIndicatorVersion", ref("Indicators"), [parameter("version", "path")]
    )
}
paths["/api/v1/suppressions"] = {
    "get": operation(
        "listScopedSuppressions",
        obj(
            {
                "items": arr(
                    obj(
                        {
                            "suppression": ref("Suppression"),
                            "validity_mode": {
                                "enum": ["scenario_interval", "from_now"]
                            },
                            "audited_at": {"type": "string", "format": "date-time"},
                        }
                    ),
                    100,
                )
            }
        ),
        [parameter("scope_id")],
    ),
    "post": operation(
        "createScopedSuppression",
        ref("Suppression"),
        method="post",
        body=ref("SuppressionRequest"),
        code="201",
    ),
}
paths["/api/v1/hosts"] = {
    "get": operation(
        "listHosts",
        obj({"items": arr(ref("Host"), 100), "limit": {"const": 100}}),
        [parameter("scope_id")],
    )
}
paths["/api/v1/hosts/{host_ip}"] = {
    "get": operation(
        "getHost",
        ref("HostDetail"),
        [parameter("host_ip", "path"), parameter("scope_id")],
    )
}
paths["/api/v1/events"] = {
    "get": operation(
        "listEvents",
        ref("EventPage"),
        [
            parameter("scope_id"),
            parameter("host_ip", required=False),
            parameter(
                "cursor",
                required=False,
                schema={"type": "string", "pattern": "^[a-f0-9]{64}$"},
            ),
            parameter(
                "limit",
                required=False,
                schema={"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
            ),
        ],
    )
}
filters = [
    parameter(
        "detector_id",
        required=False,
        schema=schemas["Suppression"]["properties"]["detector_id"],
    ),
    parameter(
        "status", required=False, schema=schemas["Alert"]["properties"]["status"]
    ),
    parameter(
        "severity", required=False, schema=schemas["Alert"]["properties"]["severity"]
    ),
    parameter("suppressed", required=False, schema={"type": "boolean"}),
    parameter("source_ip", required=False),
]
paths["/api/v1/alerts"]["get"]["parameters"] = [
    p
    for p in paths["/api/v1/alerts"]["get"]["parameters"]
    if p["name"] not in {f["name"] for f in filters}
] + filters
for route, methods in paths.items():
    for method, op in methods.items():
        op["description"] = (
            "Operator permission required. "
            if (
                method == "post"
                and route not in ("/api/v1/session/login", "/api/v1/session/logout")
            )
            else "Workspace-scoped session authorization. "
        ) + "Implemented through Phase 2."
doc["info"].update(
    version="1.0.0-phase2",
    description="TraceHawk local replay, four explainable detectors and authenticated investigation API. Defaults include explicitly fictional indicators.",
)
p.write_text(json.dumps(doc, indent=2) + "\n")
