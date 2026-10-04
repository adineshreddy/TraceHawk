"""Shared contracts, database access and security primitives."""

from pathlib import Path
import hashlib, hmac, json, os, secrets, time
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(os.getenv("APP_ROOT", "/app"))
VALIDATORS = {
    p.stem: Draft202012Validator(
        json.loads(p.read_text()), format_checker=FormatChecker()
    )
    for p in (ROOT / "contracts/schemas").glob("*.json")
}


def now_us():
    return time.time_ns() // 1000


def db():
    return psycopg.connect(
        host=os.getenv("DB_HOST", "postgres"),
        dbname="tracehawk",
        user="tracehawk",
        password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=3,
        options="-c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=10000",
        row_factory=dict_row,
    )


def digest(value):
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return (
        salt
        + ":"
        + hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), 300000
        ).hex()
    )


def password_ok(password, value):
    return hmac.compare_digest(password_hash(password, value.split(":")[0]), value)


def health(c, component, status="ready", details=None):
    c.execute(
        "INSERT INTO component_health(component,status,details) VALUES(%s,%s,%s) ON CONFLICT(component) DO UPDATE SET status=excluded.status,details=excluded.details,updated_at=now()",
        (component, status, Jsonb(details or {})),
    )


def audit(c, actor, action, details, run_id=None):
    c.execute(
        "INSERT INTO audit_events(run_id,actor,action,details) VALUES(%s,%s,%s,%s)",
        (run_id, actor, action, Jsonb(details)),
    )


def initialize():
    with db() as c:
        c.execute("SELECT pg_advisory_xact_lock(841101)")
        c.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, checksum text NOT NULL)"
        )
        for p in sorted((ROOT / "migrations").glob("*.sql")):
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            old = c.execute(
                "SELECT checksum FROM schema_migrations WHERE version=%s", (p.name,)
            ).fetchone()
            if old:
                if old["checksum"] != sha:
                    raise RuntimeError("Migration checksum changed")
            else:
                c.execute(p.read_text())
                c.execute("INSERT INTO schema_migrations VALUES(%s,%s)", (p.name, sha))
        for user, role in [("operator", "operator"), ("analyst", "analyst")]:
            c.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
                (user, password_hash(os.environ[role.upper() + "_PASSWORD"]), role),
            )
        indicators = json.loads(
            (ROOT / "contracts/examples/phase2-indicators.json").read_text()
        )
        VALIDATORS["indicators"].validate(indicators)
        c.execute(
            "INSERT INTO indicator_versions(version,body,created_by) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
            (indicators["version"], Jsonb(indicators), "setup"),
        )
        for filename in ("phase1-rules.json", "phase2-rules.json"):
            rules = json.loads((ROOT / "contracts/examples" / filename).read_text())
            VALIDATORS["rules"].validate(rules)
            c.execute(
                "INSERT INTO rule_versions(version,body,created_by) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
                (rules["version"], Jsonb(rules), "setup"),
            )


def validate_event(e, run):
    VALIDATORS["event"].validate(e)
    p = e["provenance"]
    meta = run["metadata"]
    if e["scope_id"] != run["scope_id"] or e["run_id"] != run["run_id"]:
        raise ValueError("scope mismatch")
    if (
        p["source_generation_id"] != meta["log_hashes"].get(p["log_kind"])
        or p["capture_id"] != run["scenario_id"]
    ):
        raise ValueError("source mismatch")
    if e["event_id"] != digest(
        [
            e["scope_id"],
            e["sensor_id"],
            p["source_generation_id"],
            p["log_kind"],
            p["record_offset"],
        ]
    ):
        raise ValueError("identity mismatch")
    start = e["original_timestamp_us"]
    duration = e["connection"]["duration_us"] if e["connection"] else None
    expected = start + (duration or 0) if e["event_kind"] == "connection" else start
    basis = (
        ("original_start_fallback" if duration is None else "connection_activity_end")
        if e["connection"]
        else "dns_transaction_start"
    )
    if e["event_time_us"] != expected or e["time_basis"] != basis:
        raise ValueError("time mismatch")
    if not (
        meta["time_start_us"] <= start <= e["event_time_us"] <= meta["time_end_us"]
    ):
        raise ValueError("outside capture bounds")
    if e["published_at_us"] < e["ingested_at_us"]:
        raise ValueError("publication order")
