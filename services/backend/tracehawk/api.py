"""Authenticated local investigation API and durable replay coordination."""

from contextlib import asynccontextmanager
from pathlib import Path
import hashlib, hmac, json, os, secrets, ipaddress
from .detections import canonical_indicators
from .operations import snapshot, log
from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb
from .core import (
    ROOT,
    db,
    initialize,
    password_ok,
    password_hash,
    now_us,
    VALIDATORS,
    audit,
    health,
)

ORIGIN = os.getenv("PUBLIC_ORIGIN", "http://127.0.0.1:3100")
DUMMY = password_hash("invalid-user-dummy")


@asynccontextmanager
async def lifespan(app):
    initialize()
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def fail(code=400, message="Invalid request"):
    raise HTTPException(code, message)


@app.middleware("http")
async def limits(req, call_next):
    req.state.request_id = secrets.token_hex(8)

    def oversized():
        return JSONResponse(
            {
                "code": "INVALID_REQUEST",
                "message": "Body too large",
                "request_id": req.state.request_id,
            },
            status_code=413,
        )

    try:
        length = int(req.headers.get("content-length", "0") or 0)
    except ValueError:
        return await errors(req, HTTPException(400, "Invalid content length"))
    if length < 0:
        return await errors(req, HTTPException(400, "Invalid content length"))
    if length > 65536:
        return oversized()
    chunks = []
    size = 0
    async for chunk in req.stream():
        size += len(chunk)
        if size > 65536:
            return oversized()
        chunks.append(chunk)
    req._body = b"".join(chunks)
    try:
        r = await call_next(req)
    except Exception as error:
        log(
            "api",
            "request_unavailable",
            request_id=req.state.request_id,
            error_type=type(error).__name__,
        )
        return JSONResponse(
            {
                "code": "UNAVAILABLE",
                "message": "Request could not be completed",
                "request_id": req.state.request_id,
            },
            status_code=503,
        )
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Cache-Control"] = "no-store"
    return r


@app.exception_handler(HTTPException)
async def errors(req, exc):
    return JSONResponse(
        {
            "code": {
                400: "INVALID_REQUEST",
                401: "UNAUTHENTICATED",
                403: "FORBIDDEN",
                404: "NOT_FOUND",
                409: "CONFLICT",
                429: "RATE_LIMITED",
            }.get(exc.status_code, "UNAVAILABLE"),
            "message": str(exc.detail),
            "request_id": req.state.request_id,
        },
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def invalid(req, exc):
    return await errors(req, HTTPException(400, "Invalid request"))


@app.exception_handler(UniqueViolation)
async def conflict(req, exc):
    return await errors(
        req, HTTPException(409, "Resource already exists or replay is active")
    )


def user(req: Request):
    token = req.cookies.get("tracehawk_session", "")
    if len(token) > 128:
        fail(401, "Sign in required")
    with db() as c:
        u = c.execute(
            "SELECT u.*,s.csrf_token FROM sessions s JOIN users u USING(username) WHERE token_hash=%s AND expires_at>now()",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
    if not u:
        fail(401, "Sign in required")
    if req.method not in ("GET", "HEAD"):
        if req.headers.get("origin") != ORIGIN or not hmac.compare_digest(
            req.headers.get("x-csrf-token", ""), u["csrf_token"]
        ):
            fail(403, "Invalid origin or CSRF token")
    return u


def operator(u=Depends(user)):
    if u["role"] != "operator":
        fail(403, "Operator permission required")
    return u


def internal(req: Request):
    expected = os.environ["INTERNAL_TOKEN"]
    if not hmac.compare_digest(
        req.headers.get("authorization", ""), "Bearer " + expected
    ):
        fail(403, "Internal permission required")


def validate(name, body):
    try:
        VALIDATORS[name].validate(body)
    except Exception:
        fail(400, "Invalid " + name + " contract")


def run_view(r):
    return {
        "run_id": r["run_id"],
        "scope_id": r["scope_id"],
        "scenario_id": r["scenario_id"],
        "rule_version": r["rule_version"],
        "indicator_version": r["indicator_version"],
        "status": r["status"],
        "processed_records": r["next_index"],
        "total_records": r["total_records"],
        "error": r["error"],
    }


def scoped_run(c, run_id, u):
    r = c.execute(
        "SELECT * FROM runs WHERE run_id=%s AND workspace=%s", (run_id, u["workspace"])
    ).fetchone()
    if not r:
        fail(404, "Run not found")
    return r


def scoped_alert(c, alert_id, u, lock=False):
    r = c.execute(
        "SELECT a.* FROM alerts a JOIN runs r USING(run_id) WHERE alert_id=%s AND workspace=%s"
        + (" FOR UPDATE OF a" if lock else ""),
        (alert_id, u["workspace"]),
    ).fetchone()
    if not r:
        fail(404, "Alert not found")
    return r


def scenario_metadata(scenario):
    locations = {
        "phase0-controlled-network-v1": "scenarios/phase0",
        "benign-network-v1": "scenarios/phase1-benign",
    }
    if scenario not in locations:
        fail(400, "Unknown scenario")
    folder = ROOT / locations[scenario]
    m = json.loads((folder / "manifest.json").read_text())
    logs = {
        k: hashlib.sha256((folder / "zeek" / f"{k}.log").read_bytes()).hexdigest()
        for k in ("conn", "dns")
    }
    total = sum(
        len((folder / "zeek" / f"{k}.log").read_text().splitlines()) for k in logs
    )
    return {k: m[k] for k in ("time_start_us", "time_end_us")} | {
        "log_hashes": logs,
        "manifest_sha256": hashlib.sha256(
            (folder / "manifest.json").read_bytes()
        ).hexdigest(),
        "folder": locations[scenario],
        "total": total,
    }


@app.get("/health/live")
def live():
    return {"status": "live"}


@app.get("/health/ready")
def ready():
    with db() as c:
        c.execute("SELECT 1")
    return {"status": "ready"}


@app.post("/api/v1/session/login")
def login(req: Request, body: dict, response: Response):
    if req.headers.get("origin") != ORIGIN:
        fail(403, "Invalid origin")
    if set(body) != {"username", "password"} or not all(
        isinstance(v, str) and 0 < len(v) <= 256 for v in body.values()
    ):
        fail()
    identity = hashlib.sha256(
        (req.client.host + ":" + body["username"]).encode()
    ).hexdigest()
    with db() as c:
        c.execute(
            "INSERT INTO login_limits VALUES(%s,0,now()+interval '1 minute') ON CONFLICT DO NOTHING",
            (identity,),
        )
        limit = c.execute(
            "SELECT * FROM login_limits WHERE identity=%s FOR UPDATE", (identity,)
        ).fetchone()
        from datetime import datetime, timezone

        if limit["reset_at"] < datetime.now(timezone.utc):
            c.execute(
                "UPDATE login_limits SET failures=0,reset_at=now()+interval '1 minute' WHERE identity=%s",
                (identity,),
            )
            limit["failures"] = 0
        if limit["failures"] >= 6:
            fail(429, "Try again later")
        u = c.execute(
            "SELECT * FROM users WHERE username=%s", (body["username"],)
        ).fetchone()
        ok = password_ok(body["password"], u["password_hash"] if u else DUMMY)
        if not u or not ok:
            c.execute(
                "UPDATE login_limits SET failures=failures+1 WHERE identity=%s",
                (identity,),
            )
            c.commit()
            fail(401, "Invalid credentials")
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        c.execute(
            "INSERT INTO sessions VALUES(%s,%s,%s,now()+interval '4 hours')",
            (hashlib.sha256(token.encode()).hexdigest(), u["username"], csrf),
        )
        audit(c, u["username"], "login", {})
    response.set_cookie(
        "tracehawk_session", token, httponly=True, samesite="strict", max_age=14400
    )
    return {"username": u["username"], "role": u["role"], "csrf_token": csrf}


@app.get("/api/v1/session")
def session(u=Depends(user)):
    return {k: u[k] for k in ("username", "role", "csrf_token")}


@app.post("/api/v1/session/logout")
def logout(req: Request, response: Response, u=Depends(user)):
    with db() as c:
        c.execute(
            "DELETE FROM sessions WHERE token_hash=%s",
            (hashlib.sha256(req.cookies["tracehawk_session"].encode()).hexdigest(),),
        )
    response.delete_cookie("tracehawk_session")
    return {"logged_out": True}


@app.get("/api/v1/scenarios")
def scenarios(u=Depends(user)):
    return {
        "items": [
            {
                "scenario_id": "phase0-controlled-network-v1",
                "label": "Controlled scan + DNS traffic",
                "description": "Original offline PCAP. Phase 1 detects the 24-port scan; DNS detection is planned.",
            },
            {
                "scenario_id": "benign-network-v1",
                "label": "Benign network baseline",
                "description": "Successful DNS responses and one normal TCP connection; expected no port-scan alerts.",
            },
        ]
    }


@app.get("/api/v1/runs")
def runs(u=Depends(user)):
    with db() as c:
        return {
            "items": [
                run_view(r)
                for r in c.execute(
                    "SELECT * FROM runs WHERE workspace=%s ORDER BY created_at DESC LIMIT 50",
                    (u["workspace"],),
                )
            ]
        }


@app.post("/api/v1/runs", status_code=202)
def start(body: dict, u=Depends(operator)):
    if (
        not {"scenario_id", "rule_version", "playback_speed"} <= set(body)
        or not set(body)
        <= {"scenario_id", "rule_version", "playback_speed", "suppression_templates"}
        or type(body["playback_speed"]) is not int
        or body["playback_speed"] not in (1, 5, 10)
    ):
        fail()
    if not all(
        isinstance(body[k], str) and 1 <= len(body[k]) <= 128
        for k in ("scenario_id", "rule_version")
    ):
        fail()
    meta = scenario_metadata(body["scenario_id"])
    rid = secrets.token_hex(12)
    with db() as c:
        rule = c.execute(
            "SELECT body FROM rule_versions WHERE version=%s", (body["rule_version"],)
        ).fetchone()
        if not rule:
            fail(400, "Unknown rule version")
        indicator_version = (
            rule["body"]["known_indicator"]["indicator_version"]
            if rule["body"]["known_indicator"]["enabled"]
            else None
        )
        if (
            indicator_version
            and not c.execute(
                "SELECT 1 FROM indicator_versions WHERE version=%s",
                (indicator_version,),
            ).fetchone()
        ):
            fail(400, "Unknown indicator snapshot")
        templates = body.get("suppression_templates", [])
        if not isinstance(templates, list) or len(templates) > 20:
            fail(400, "Invalid suppression templates")
        r = c.execute(
            "INSERT INTO runs(run_id,scope_id,workspace,scenario_id,rule_version,status,speed,metadata,total_records) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
            (
                rid,
                rid,
                u["workspace"],
                body["scenario_id"],
                body["rule_version"],
                "queued",
                body["playback_speed"],
                Jsonb(meta),
                meta["total"],
            ),
        ).fetchone()
        c.execute(
            "UPDATE runs SET indicator_version=%s WHERE run_id=%s",
            (indicator_version, rid),
        )
        r["indicator_version"] = indicator_version
        for template in templates:
            if not isinstance(template, dict) or set(template) != {
                "detector_id",
                "source_ip",
                "destination_ip",
                "reason",
            }:
                fail(400, "Invalid suppression template")
            insert_suppression(
                c,
                r,
                (
                    template | {"scope_id": rid, "validity_mode": "scenario_interval"}
                    if isinstance(template, dict)
                    else {}
                ),
                u,
            )
        for p in range(3):
            c.execute(
                "INSERT INTO run_partitions(run_id,partition) VALUES(%s,%s)", (rid, p)
            )
        audit(
            c, u["username"], "replay_start", {"scenario_id": body["scenario_id"]}, rid
        )
    return run_view(r)


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: str, u=Depends(user)):
    with db() as c:
        return run_view(scoped_run(c, run_id, u))


@app.post("/api/v1/runs/{run_id}/cancel", status_code=202)
def cancel(run_id: str, u=Depends(operator)):
    with db() as c:
        r = scoped_run(c, run_id, u)
        if r["status"] in ("completed", "cancelled", "failed"):
            return run_view(r)
        r = c.execute(
            "UPDATE runs SET status='cancelled' WHERE run_id=%s AND status IN ('queued','preparing','replaying','finalizing') RETURNING *",
            (run_id,),
        ).fetchone()
        if r is None:
            return run_view(scoped_run(c, run_id, u))
        audit(c, u["username"], "replay_cancel", {}, run_id)
    return run_view(r)


@app.get("/api/v1/overview")
def overview(scope_id: str, u=Depends(user)):
    with db() as c:
        r = c.execute(
            "SELECT * FROM runs WHERE scope_id=%s AND workspace=%s",
            (scope_id, u["workspace"]),
        ).fetchone()
        if not r:
            fail(404, "Scope not found")
        count = c.execute(
            "SELECT count(*) n FROM events WHERE run_id=%s", (r["run_id"],)
        ).fetchone()["n"]
        alerts = c.execute(
            "SELECT count(*) n FROM alerts WHERE run_id=%s AND body->>'status'='open' AND body->>'suppressed'='false'",
            (r["run_id"],),
        ).fetchone()["n"]
        suppressed = c.execute(
            "SELECT count(*) n FROM alerts WHERE run_id=%s AND body->>'suppressed'='true'",
            (r["run_id"],),
        ).fetchone()["n"]
        healthy = (
            c.execute(
                "SELECT count(*) n FROM component_health WHERE component IN ('collector','detector') AND status='ready' AND updated_at>now()-interval '15 seconds'"
            ).fetchone()["n"]
            == 2
        )
    return {
        "scope_id": scope_id,
        "run_id": r["run_id"],
        "input_mode": "controlled_pcap",
        "event_count": count,
        "open_alert_count": alerts,
        "suppressed_alert_count": suppressed,
        "pipeline_status": "ready" if healthy else "degraded",
    }


@app.get("/api/v1/alerts")
def alerts(
    scope_id: str,
    cursor: str | None = None,
    limit: int = 25,
    detector_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    suppressed: bool | None = None,
    source_ip: str | None = None,
    u=Depends(user),
):
    if not 1 <= limit <= 100 or (
        cursor
        and (len(cursor) != 64 or any(x not in "0123456789abcdef" for x in cursor))
    ):
        fail()
    filters = []
    params = []
    for key, value, allowed in [
        (
            "detector_id",
            detector_id,
            (
                "vertical_tcp_scan",
                "failed_tcp_connections",
                "dns_nxdomain_burst",
                "known_indicator",
            ),
        ),
        ("status", status, ("open", "acknowledged", "resolved")),
        ("severity", severity, ("low", "medium", "high", "critical")),
    ]:
        if value is not None:
            if value not in allowed:
                fail(400, "Invalid alert filter")
            filters.append("body->>'" + key + "'=%s")
            params.append(value)
    if suppressed is not None:
        filters.append("body->>'suppressed'=%s")
        params.append(str(suppressed).lower())
    if source_ip is not None:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            fail(400, "Invalid source address")
        filters.append("body->>'source_ip'=%s")
        params.append(source_ip)
    with db() as c:
        r = c.execute(
            "SELECT run_id FROM runs WHERE scope_id=%s AND workspace=%s",
            (scope_id, u["workspace"]),
        ).fetchone()
        if not r:
            fail(404, "Scope not found")
        rows = c.execute(
            "SELECT body FROM alerts WHERE run_id=%s AND alert_id>%s"
            + (" AND " + " AND ".join(filters) if filters else "")
            + " ORDER BY alert_id LIMIT %s",
            (r["run_id"], cursor or "", *params, limit + 1),
        ).fetchall()
    return {
        "items": [r["body"] for r in rows[:limit]],
        "next_cursor": (
            rows[limit - 1]["body"]["alert_id"] if len(rows) > limit else None
        ),
    }


@app.get("/api/v1/alerts/{alert_id}")
def alert(alert_id: str, u=Depends(user)):
    with db() as c:
        return scoped_alert(c, alert_id, u)["body"]


@app.get("/api/v1/alerts/{alert_id}/evidence")
def evidence(alert_id: str, u=Depends(user)):
    with db() as c:
        a = scoped_alert(c, alert_id, u)
        rows = c.execute(
            "SELECT e.body,e.eligible,x.reason FROM alert_evidence ae JOIN events e USING(event_id) LEFT JOIN event_exclusions x USING(event_id) WHERE ae.alert_id=%s ORDER BY e.event_time_us,e.event_id LIMIT 200",
            (alert_id,),
        ).fetchall()
        history = c.execute(
            "SELECT actor,action,details,created_at FROM audit_events WHERE run_id=%s AND (details->>'alert_id'=%s OR action IN ('replay_start','replay_cancel') OR details->>'suppression_id'=%s) ORDER BY id DESC LIMIT 30",
            (a["run_id"], alert_id, a["body"]["suppression_id"]),
        ).fetchall()
        windows = c.execute(
            "SELECT window_start_us,window_end_us,observed FROM alert_windows WHERE alert_id=%s ORDER BY window_end_us",
            (alert_id,),
        ).fetchall()
        timeline = c.execute(
            "SELECT (event_time_us/10000000)*10000000 start_us,count(*) event_count,count(*) FILTER(WHERE e.body->'connection'->>'state' IN ('S0','REJ')) failed_tcp,count(*) FILTER(WHERE (e.body->'dns'->>'rcode')::numeric=3) dns_nxdomain FROM alert_evidence a JOIN events e USING(event_id) WHERE alert_id=%s GROUP BY start_us ORDER BY start_us",
            (alert_id,),
        ).fetchall()
        matches = c.execute(
            "SELECT m.* FROM indicator_matches m JOIN alert_evidence a USING(event_id) WHERE alert_id=%s ORDER BY event_id LIMIT 200",
            (alert_id,),
        ).fetchall()
        suppression = c.execute(
            "SELECT body FROM suppressions WHERE suppression_id=%s",
            (a["body"]["suppression_id"],),
        ).fetchone()
    return {
        "items": [r["body"] for r in rows],
        "history": [dict(r, created_at=r["created_at"].isoformat()) for r in history],
        "timeline": timeline,
        "event_eligibility": [
            {
                "event_id": r["body"]["event_id"],
                "eligible_for_temporal_rules": r["eligible"],
                "exclusion_reason": r["reason"],
            }
            for r in rows
        ],
        "matched_windows": windows,
        "indicator_matches": matches,
        "suppression": suppression["body"] if suppression else None,
    }


@app.patch("/api/v1/alerts/{alert_id}/status")
def status(alert_id: str, body: dict, u=Depends(user)):
    if (
        set(body) != {"status", "reason"}
        or body["status"] not in ("open", "acknowledged", "resolved")
        or not isinstance(body["reason"], str)
        or not 1 <= len(body["reason"]) <= 512
    ):
        fail()
    with db() as c:
        a = scoped_alert(c, alert_id, u, lock=True)
        b = a["body"]
        b.update(status=body["status"], updated_at_us=now_us())
        revision = c.execute(
            "UPDATE alerts SET body=%s,revision=revision+1 WHERE alert_id=%s RETURNING revision",
            (Jsonb(b), alert_id),
        ).fetchone()["revision"]
        from .core import digest

        c.execute(
            "INSERT INTO outbox VALUES(%s,%s,%s,NULL)",
            (
                digest([alert_id, revision]),
                alert_id,
                Jsonb({"alert_id": alert_id, "revision": revision, "alert": b}),
            ),
        )
        audit(
            c,
            u["username"],
            "alert_status",
            {"alert_id": alert_id, **body},
            a["run_id"],
        )
    return b


@app.get("/api/v1/rules/{version}")
def rule(version: str, u=Depends(user)):
    with db() as c:
        r = c.execute(
            "SELECT body FROM rule_versions WHERE version=%s", (version,)
        ).fetchone()
    if not r:
        fail(404, "Rule not found")
    return r["body"]


@app.post("/api/v1/rules", status_code=201)
def create_rule(body: dict, u=Depends(operator)):
    validate("rules", body)
    with db() as c:
        if (
            body["known_indicator"]["enabled"]
            and not c.execute(
                "SELECT 1 FROM indicator_versions WHERE version=%s",
                (body["known_indicator"]["indicator_version"],),
            ).fetchone()
        ):
            fail(400, "Unknown indicator snapshot")
        c.execute(
            "INSERT INTO rule_versions VALUES(%s,%s,%s,now())",
            (body["version"], Jsonb(body), u["username"]),
        )
        audit(c, u["username"], "rule_create", {"version": body["version"]})
    return body


@app.post("/internal/jobs/claim", dependencies=[Depends(internal)])
def claim():
    with db() as c:
        health(c, "collector")
        pending = c.execute(
            "SELECT count(*) n FROM outbox WHERE delivered_at IS NULL"
        ).fetchone()["n"]
        covered = c.execute(
            "SELECT count(*) n FROM partition_checkpoints WHERE owner_id IS NOT NULL AND owner_seen_at>now()-interval '15 seconds'"
        ).fetchone()["n"]
        if pending >= 1000 or covered != 3:
            health(c, "collector", "paused", {"reason": "downstream_backpressure"})
            return Response(status_code=204, headers={"X-TraceHawk-State": "paused"})
        r = c.execute(
            "SELECT * FROM runs WHERE status IN ('queued','preparing','replaying','finalizing') AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1"
        ).fetchone()
        if not r:
            return Response(status_code=204)
        r = c.execute(
            "UPDATE runs SET status='replaying',generation=generation+1,lease_until=now()+interval '30 seconds' WHERE run_id=%s RETURNING *",
            (r["run_id"],),
        ).fetchone()
    return r


@app.post("/internal/jobs/{run_id}/checkpoint", dependencies=[Depends(internal)])
def checkpoint(run_id: str, body: dict):
    if set(body) != {"generation", "next_index", "source_offsets", "finish", "error"}:
        fail()
    if (
        type(body["generation"]) is not int
        or type(body["next_index"]) is not int
        or type(body["finish"]) is not bool
        or type(body["error"]) is not bool
        or not isinstance(body["source_offsets"], list)
        or len(body["source_offsets"]) != 3
    ):
        fail()
    if any(
        x is not None and (type(x) is not int or x < 0) for x in body["source_offsets"]
    ):
        fail()
    with db() as c:
        r = c.execute(
            "SELECT * FROM runs WHERE run_id=%s FOR UPDATE", (run_id,)
        ).fetchone()
        if (
            not r
            or r["generation"] != body["generation"]
            or r["status"] in ("cancelled", "failed")
        ):
            fail(409, "Replay lease lost")
        if not r["next_index"] <= body["next_index"] <= r["total_records"]:
            fail()
        if body["finish"] and body["next_index"] != r["total_records"]:
            fail()
        if any(
            old is not None and (new is None or new < old)
            for old, new in zip(r["source_offsets"], body["source_offsets"])
        ):
            fail()
        health(c, "collector")
        state = (
            "failed"
            if body["error"]
            else ("finalizing" if body["finish"] else "replaying")
        )
        if r["status"] == "completed":
            state = "completed"
        c.execute(
            "UPDATE runs SET next_index=%s,source_offsets=%s,status=%s,lease_until=now()+interval '30 seconds',error=%s WHERE run_id=%s",
            (
                body["next_index"],
                Jsonb(body["source_offsets"]),
                state,
                (
                    Jsonb(
                        {
                            "code": "REPLAY_FAILED",
                            "message": "Source or publishing failed",
                            "request_id": run_id,
                        }
                    )
                    if body["error"]
                    else None
                ),
                run_id,
            ),
        )
    return {"status": state}


# Phase 2 investigation/configuration endpoints.
def scoped_scope(c, scope_id, u):
    r = c.execute(
        "SELECT * FROM runs WHERE scope_id=%s AND workspace=%s",
        (scope_id, u["workspace"]),
    ).fetchone()
    if not r:
        fail(404, "Scope not found")
    return r


def address(value):
    if not isinstance(value, str):
        fail(400, "IP address must be a string")
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        fail(400, "Invalid IP address")


def insert_suppression(c, run, body, u):
    if set(body) != {
        "scope_id",
        "detector_id",
        "source_ip",
        "destination_ip",
        "reason",
        "validity_mode",
    }:
        fail(400, "Invalid suppression request")
    if body["scope_id"] != run["scope_id"] or body["validity_mode"] not in (
        "scenario_interval",
        "from_now",
    ):
        fail(400, "Invalid suppression scope or time basis")
    if body["validity_mode"] == "scenario_interval":
        start = run["metadata"]["time_start_us"]
        end = run["metadata"]["time_end_us"] + 1
    else:
        start = now_us()
        end = start + 3600_000_000
    if not isinstance(body["reason"], str) or not body["reason"].strip():
        fail(400, "Suppression reason required")
    suppression = {
        "schema_version": "1.0",
        "suppression_id": secrets.token_hex(16),
        "scope_id": run["scope_id"],
        "detector_id": body["detector_id"],
        "source_ip": address(body["source_ip"]),
        "destination_ip": (
            address(body["destination_ip"])
            if body["destination_ip"] is not None
            else None
        ),
        "reason": body["reason"],
        "created_by": u["username"],
        "created_at_us": start,
        "expires_at_us": end,
    }
    validate("suppression", suppression)
    c.execute(
        "INSERT INTO suppressions(suppression_id,scope_id,body,validity_mode) VALUES(%s,%s,%s,%s)",
        (
            suppression["suppression_id"],
            run["scope_id"],
            Jsonb(suppression),
            body["validity_mode"],
        ),
    )
    audit(
        c,
        u["username"],
        "suppression_create",
        {
            "suppression_id": suppression["suppression_id"],
            "validity_mode": body["validity_mode"],
            "reason": body["reason"],
            "valid_from_us": start,
            "valid_until_us": end,
        },
        run["run_id"],
    )
    return suppression


@app.get("/api/v1/rules")
def rule_versions(u=Depends(user)):
    with db() as c:
        return {
            "items": [
                r["body"]
                for r in c.execute(
                    "SELECT body FROM rule_versions ORDER BY created_at DESC,version LIMIT 100"
                )
            ]
        }


@app.get("/api/v1/indicators")
def indicator_versions(u=Depends(user)):
    with db() as c:
        return {
            "items": [
                r["body"]
                for r in c.execute(
                    "SELECT body FROM indicator_versions ORDER BY created_at DESC,version LIMIT 100"
                )
            ]
        }


@app.get("/api/v1/indicators/{version}")
def get_indicators(version: str, u=Depends(user)):
    with db() as c:
        r = c.execute(
            "SELECT body FROM indicator_versions WHERE version=%s", (version,)
        ).fetchone()
    if not r:
        fail(404, "Indicator version not found")
    return r["body"]


@app.post("/api/v1/indicators", status_code=201)
def create_indicators(body: dict, u=Depends(operator)):
    validate("indicators", body)
    try:
        body = canonical_indicators(body)
    except ValueError:
        fail(400, "Invalid or duplicate indicator")
    with db() as c:
        c.execute(
            "INSERT INTO indicator_versions(version,body,created_by) VALUES(%s,%s,%s)",
            (body["version"], Jsonb(body), u["username"]),
        )
        audit(c, u["username"], "indicator_create", {"version": body["version"]})
    return body


@app.get("/api/v1/suppressions")
def list_suppressions(scope_id: str, u=Depends(user)):
    with db() as c:
        scoped_scope(c, scope_id, u)
        rows = c.execute(
            "SELECT body,validity_mode,audited_at FROM suppressions WHERE scope_id=%s ORDER BY audited_at DESC,suppression_id LIMIT 100",
            (scope_id,),
        ).fetchall()
    return {
        "items": [
            {
                "suppression": r["body"],
                "validity_mode": r["validity_mode"],
                "audited_at": r["audited_at"].isoformat(),
            }
            for r in rows
        ]
    }


@app.post("/api/v1/suppressions", status_code=201)
def create_suppression(body: dict, u=Depends(operator)):
    if not isinstance(body.get("scope_id"), str):
        fail(400, "Scope required")
    with db() as c:
        return insert_suppression(c, scoped_scope(c, body["scope_id"], u), body, u)


@app.get("/api/v1/hosts")
def hosts(scope_id: str, u=Depends(user)):
    with db() as c:
        run = scoped_scope(c, scope_id, u)
        rows = c.execute(
            "WITH activity AS (SELECT event_id,source_ip ip,'outbound' role FROM events WHERE run_id=%s UNION ALL SELECT event_id,destination_ip,'inbound' FROM events WHERE run_id=%s) SELECT host(ip) address,count(DISTINCT event_id) event_count,count(*) FILTER(WHERE role='outbound') outbound,count(*) FILTER(WHERE role='inbound') inbound FROM activity GROUP BY ip ORDER BY count(DISTINCT event_id) DESC,ip LIMIT 100",
            (run["run_id"], run["run_id"]),
        ).fetchall()
        for row in rows:
            row["alert_count"] = c.execute(
                "SELECT count(*) n FROM alerts WHERE run_id=%s AND (body->>'source_ip'=%s OR body->>'destination_ip'=%s)",
                (run["run_id"], row["address"], row["address"]),
            ).fetchone()["n"]
    return {"items": rows, "limit": 100}


@app.get("/api/v1/hosts/{host_ip}")
def host_detail(host_ip: str, scope_id: str, u=Depends(user)):
    ip = address(host_ip)
    with db() as c:
        run = scoped_scope(c, scope_id, u)
        summary = c.execute(
            "SELECT count(*) event_count,min(event_time_us) first_event_time_us,max(event_time_us) last_event_time_us,count(*) FILTER(WHERE event_kind='connection' AND protocol='tcp' AND body->'connection'->>'state' IS NOT NULL AND body->'connection'->>'state'<>'OTH') tcp_classified,count(*) FILTER(WHERE event_kind='connection' AND protocol='tcp' AND (body->'connection'->>'state' IS NULL OR body->'connection'->>'state'='OTH')) tcp_unknown,count(*) FILTER(WHERE event_kind='dns' AND body->'dns'->>'rcode' IS NOT NULL) dns_completed,count(*) FILTER(WHERE event_kind='dns' AND body->'dns'->>'rcode' IS NULL) dns_unknown,count(*) FILTER(WHERE NOT eligible) late_events FROM events WHERE run_id=%s AND (source_ip=%s::inet OR destination_ip=%s::inet)",
            (run["run_id"], ip, ip),
        ).fetchone()
        if summary["event_count"] == 0:
            fail(404, "Host not found")
        alerts = c.execute(
            "SELECT body FROM alerts WHERE run_id=%s AND (body->>'source_ip'=%s OR body->>'destination_ip'=%s) ORDER BY alert_id LIMIT 100",
            (run["run_id"], ip, ip),
        ).fetchall()
        coverage = {
            k: summary[k]
            for k in (
                "tcp_classified",
                "tcp_unknown",
                "dns_completed",
                "dns_unknown",
                "late_events",
            )
        }
        timeline = c.execute(
            "SELECT (event_time_us/10000000)*10000000 start_us,count(*) event_count FROM events WHERE run_id=%s AND (source_ip=%s::inet OR destination_ip=%s::inet) GROUP BY start_us ORDER BY start_us LIMIT 1000",
            (run["run_id"], ip, ip),
        ).fetchall()
    return {
        "address": ip,
        "scope_id": scope_id,
        "event_count": summary["event_count"],
        "first_event_time_us": summary["first_event_time_us"],
        "last_event_time_us": summary["last_event_time_us"],
        "coverage": coverage,
        "alerts": [r["body"] for r in alerts],
        "timeline": timeline,
    }


@app.get("/api/v1/events")
def events(
    scope_id: str,
    host_ip: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
    u=Depends(user),
):
    if not 1 <= limit <= 100 or (
        cursor
        and (len(cursor) != 64 or any(ch not in "0123456789abcdef" for ch in cursor))
    ):
        fail(400, "Invalid event pagination")
    with db() as c:
        run = scoped_scope(c, scope_id, u)
        filters = ["e.run_id=%s"]
        params = [run["run_id"]]
        if host_ip is not None:
            ip = address(host_ip)
            filters.append("(e.source_ip=%s::inet OR e.destination_ip=%s::inet)")
            params.extend([ip, ip])
        if cursor:
            after = c.execute(
                "SELECT event_time_us FROM events WHERE event_id=%s AND run_id=%s",
                (cursor, run["run_id"]),
            ).fetchone()
            if not after:
                fail(400, "Cursor does not belong to scope")
            filters.append("(e.event_time_us,e.event_id)>(%s,%s)")
            params.extend([after["event_time_us"], cursor])
        rows = c.execute(
            "SELECT e.body,e.eligible,x.reason FROM events e LEFT JOIN event_exclusions x USING(event_id) WHERE "
            + " AND ".join(filters)
            + " ORDER BY e.event_time_us,e.event_id LIMIT %s",
            (*params, limit + 1),
        ).fetchall()
    return {
        "items": [
            {
                "event": r["body"],
                "eligible_for_temporal_rules": r["eligible"],
                "exclusion_reason": r["reason"],
            }
            for r in rows[:limit]
        ],
        "next_cursor": (
            rows[limit - 1]["body"]["event_id"] if len(rows) > limit else None
        ),
    }


@app.get("/api/v1/operations")
def operations(u=Depends(operator)):
    if u["workspace"] != "local":
        fail(403, "Local operations permission required")
    with db() as c:
        return snapshot(c)


@app.get("/api/v1/deadletters")
def deadletters(u=Depends(operator)):
    if u["workspace"] != "local":
        fail(403, "Local operations permission required")
    with db() as c:
        return {
            "items": c.execute(
                "SELECT partition,broker_offset,reason,record_sha256,record_bytes,created_at,delivered_at,reviewed_at,review_reason FROM deadletters ORDER BY created_at DESC,partition,broker_offset LIMIT 100"
            ).fetchall()
        }


@app.post("/api/v1/deadletters/{partition}/{offset}/review")
def review_deadletter(partition: int, offset: int, body: dict, u=Depends(operator)):
    if u["workspace"] != "local":
        fail(403, "Local operations permission required")
    if (
        set(body) != {"reason"}
        or not isinstance(body["reason"], str)
        or not 1 <= len(body["reason"].strip()) <= 500
    ):
        fail()
    with db() as c:
        row = c.execute(
            "UPDATE deadletters SET reviewed_at=now(),review_reason=%s WHERE partition=%s AND broker_offset=%s AND reviewed_at IS NULL RETURNING partition",
            (body["reason"].strip(), partition, offset),
        ).fetchone()
        if not row:
            fail(404, "Unreviewed record not found")
        audit(
            c,
            u["username"],
            "deadletter.review",
            {
                "partition": partition,
                "offset": offset,
                "reason": body["reason"].strip(),
            },
        )
    return {"status": "reviewed"}


@app.get("/api/v1/evaluation")
def evaluation(u=Depends(user)):
    # Packaged synthetic research summary, with no workspace or account data.
    return json.loads((ROOT / "evaluation/reports/summary.json").read_text())
