"""Window queries and persisted explainable alerts. No labels or external feed inputs."""

import ipaddress
from decimal import Decimal
from psycopg.types.json import Jsonb
from .core import VALIDATORS, digest, now_us

WINDOW = 60_000_000
BUCKET = 300_000_000


def scan_groups(c, run_id, partition, end, threshold):
    return c.execute(
        "SELECT host(source_ip) source,host(destination_ip) destination,count(DISTINCT destination_port) n,array_agg(event_id ORDER BY event_time_us,event_id) ids FROM events WHERE run_id=%s AND partition=%s AND eligible AND event_time_us>=%s AND event_time_us<%s AND event_kind='connection' AND protocol='tcp' AND body->'connection'->>'state' IS NOT NULL GROUP BY source_ip,destination_ip HAVING count(DISTINCT destination_port)>=%s",
        (run_id, partition, end - WINDOW, end, threshold),
    ).fetchall()


def temporal_matches(c, run, partition, end, rules):
    params = (run["run_id"], partition, end - WINDOW, end)
    if rules["vertical_tcp_scan"]["enabled"]:
        for g in scan_groups(
            c, *params[:2], end, rules["vertical_tcp_scan"]["min_distinct_ports"]
        ):
            yield "vertical_tcp_scan", g, {"distinct_ports": g["n"]}, {
                "min_distinct_ports": rules["vertical_tcp_scan"]["min_distinct_ports"],
                "window_seconds": 60,
            }
    if rules["failed_tcp_connections"]["enabled"]:
        cfg = rules["failed_tcp_connections"]
        groups = c.execute(
            "SELECT host(source_ip) source,host(destination_ip) destination,count(*) n,count(*) FILTER(WHERE body->'connection'->>'state'=ANY(%s)) failures,array_agg(event_id ORDER BY event_time_us,event_id) ids FROM events WHERE run_id=%s AND partition=%s AND eligible AND event_time_us>=%s AND event_time_us<%s AND event_kind='connection' AND protocol='tcp' AND body->'connection'->>'state' IS NOT NULL AND body->'connection'->>'state'<>'OTH' GROUP BY source_ip,destination_ip",
            (cfg["failure_states"], *params),
        ).fetchall()
        for g in groups:
            if g["n"] >= cfg["min_attempts"] and Decimal(g["failures"]) / Decimal(
                g["n"]
            ) >= Decimal(str(cfg["min_failure_ratio"])):
                yield "failed_tcp_connections", g, {
                    "attempts": g["n"],
                    "failure_ratio": g["failures"] / g["n"],
                }, {
                    "min_attempts": cfg["min_attempts"],
                    "min_failure_ratio": cfg["min_failure_ratio"],
                    "failure_states": ",".join(cfg["failure_states"]),
                    "window_seconds": 60,
                }
    if rules["dns_nxdomain_burst"]["enabled"]:
        cfg = rules["dns_nxdomain_burst"]
        groups = c.execute(
            "SELECT host(source_ip) source,NULL::text destination,count(*) n,count(*) FILTER(WHERE (body->'dns'->>'rcode')::numeric=3) nx,array_agg(event_id ORDER BY event_time_us,event_id) ids FROM events WHERE run_id=%s AND partition=%s AND eligible AND event_time_us>=%s AND event_time_us<%s AND event_kind='dns' AND body->'dns'->>'rcode' IS NOT NULL GROUP BY source_ip",
            params,
        ).fetchall()
        for g in groups:
            if g["n"] >= cfg["min_responses"] and Decimal(g["nx"]) / Decimal(
                g["n"]
            ) >= Decimal(str(cfg["min_nxdomain_ratio"])):
                yield "dns_nxdomain_burst", g, {
                    "completed_responses": g["n"],
                    "nxdomain_ratio": g["nx"] / g["n"],
                }, {
                    "min_responses": cfg["min_responses"],
                    "min_nxdomain_ratio": cfg["min_nxdomain_ratio"],
                    "window_seconds": 60,
                }


def explanation(detector, observed, thresholds):
    if detector == "vertical_tcp_scan":
        return f"{observed['distinct_ports']} distinct destination ports observed; threshold is {thresholds['min_distinct_ports']} in 60 seconds. Possible scanning; not proof of exploitation."
    if detector == "failed_tcp_connections":
        return f"Peak qualifying windows: {observed['attempts']} classified TCP attempts; failure ratio up to {observed['failure_ratio']:.0%}. Thresholds: {thresholds['min_attempts']} attempts and {thresholds['min_failure_ratio']:.0%}. S0/REJ describe absent responses or rejected connections, not failed authentication. Peaks may belong to different windows; inspect window measurements."
    if detector == "dns_nxdomain_burst":
        return f"Peak qualifying windows: {observed['completed_responses']} completed DNS responses; NXDOMAIN ratio up to {observed['nxdomain_ratio']:.0%}. Thresholds: {thresholds['min_responses']} responses and {thresholds['min_nxdomain_ratio']:.0%}. Missing response codes are excluded; DNS errors alone do not prove an attack. Peaks may belong to different windows."
    return f"{int(observed['indicator_matches'])} event(s) exactly matched the snapshotted indicator list. The default list is fictional development data, not threat intelligence. No suffix matching or DNS resolution occurs."


def persist_alert(c, run, rules, detector, g, end, observed, thresholds, temporal=True):
    aid = digest(
        [
            run["scope_id"],
            run["rule_version"],
            detector,
            g["source"],
            g["destination"],
            end // BUCKET * BUCKET,
        ]
    )
    old = c.execute(
        "SELECT * FROM alerts WHERE alert_id=%s FOR UPDATE", (aid,)
    ).fetchone()
    stamp = now_us()
    if old:
        body = old["body"]
        body["observed"] = {
            k: max(body["observed"].get(k, 0), v) for k, v in observed.items()
        }
        body.update(
            updated_at_us=stamp,
            window_start_us=(
                end - WINDOW if temporal else min(body["window_start_us"], end)
            ),
            window_end_us=max(body["window_end_us"], end if temporal else end + 1),
        )
    else:
        anchor = c.execute(
            "SELECT max(event_time_us) t FROM events WHERE event_id=ANY(%s)",
            (g["ids"],),
        ).fetchone()["t"]
        suppression = c.execute(
            "SELECT body FROM suppressions WHERE scope_id=%s AND body->>'detector_id'=%s AND body->>'source_ip'=%s AND (body->>'destination_ip' IS NULL OR body->>'destination_ip'=%s) AND (body->>'created_at_us')::bigint<=%s AND (body->>'expires_at_us')::bigint>%s ORDER BY suppression_id LIMIT 1",
            (run["scope_id"], detector, g["source"], g["destination"], anchor, anchor),
        ).fetchone()
        body = {
            "schema_version": "1.0",
            "alert_id": aid,
            "scope_id": run["scope_id"],
            "run_id": run["run_id"],
            "detector_id": detector,
            "rule_version": run["rule_version"],
            "indicator_version": (
                run.get("indicator_version") if detector == "known_indicator" else None
            ),
            "severity": rules[detector]["severity"],
            "status": "open",
            "suppressed": bool(suppression),
            "suppression_id": (
                suppression["body"]["suppression_id"] if suppression else None
            ),
            "source_ip": g["source"],
            "destination_ip": g["destination"],
            "first_event_time_us": 0,
            "last_event_time_us": 0,
            "window_start_us": end - WINDOW if temporal else end,
            "window_end_us": end if temporal else end + 1,
            "episode_bucket_start_us": end // BUCKET * BUCKET,
            "created_at_us": stamp,
            "updated_at_us": stamp,
            "explanation": "",
            "explanation_version": "explain-v2",
            "observed": observed,
            "thresholds": thresholds,
            "evidence_event_ids": [],
            "evidence_total_count": 0,
            "evidence_truncated": False,
        }
        c.execute(
            "INSERT INTO alerts(alert_id,run_id,body) VALUES(%s,%s,%s)",
            (aid, run["run_id"], Jsonb(body)),
        )
    for eid in g["ids"]:
        c.execute(
            "INSERT INTO alert_evidence VALUES(%s,%s) ON CONFLICT DO NOTHING",
            (aid, eid),
        )
    evidence = c.execute(
        "SELECT e.event_id,e.event_time_us FROM alert_evidence a JOIN events e USING(event_id) WHERE a.alert_id=%s ORDER BY e.event_time_us,e.event_id",
        (aid,),
    ).fetchall()
    body.update(
        first_event_time_us=evidence[0]["event_time_us"],
        last_event_time_us=evidence[-1]["event_time_us"],
        evidence_event_ids=[e["event_id"] for e in evidence[:200]],
        evidence_total_count=len(evidence),
        evidence_truncated=len(evidence) > 200,
    )
    if not temporal:
        body["observed"]["indicator_matches"] = len(evidence)
    body["explanation"] = explanation(detector, body["observed"], thresholds)
    # A programming/DB defect must roll back, rather than quarantine a valid input.
    try:
        VALIDATORS["alert"].validate(body)
    except Exception as error:
        raise RuntimeError("Generated alert violates contract") from error
    if temporal:
        c.execute(
            "INSERT INTO alert_windows VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (aid, end, end - WINDOW, Jsonb(observed)),
        )
    revision = c.execute(
        "UPDATE alerts SET body=%s,revision=revision+1 WHERE alert_id=%s RETURNING revision",
        (Jsonb(body), aid),
    ).fetchone()["revision"]
    c.execute(
        "INSERT INTO outbox VALUES(%s,%s,%s,NULL)",
        (
            digest([aid, revision]),
            aid,
            Jsonb({"alert_id": aid, "revision": revision, "alert": body}),
        ),
    )
    return aid


def match_indicator(c, run, rules, event):
    if not rules["known_indicator"]["enabled"]:
        return
    version = run["indicator_version"]
    indicators = c.execute(
        "SELECT body FROM indicator_versions WHERE version=%s", (version,)
    ).fetchone()["body"]
    kind = "ip" if event["event_kind"] == "connection" else "domain"
    value = event["destination_ip"] if kind == "ip" else event["dns"]["query"]
    for entry in indicators["entries"]:
        if entry["kind"] == kind and entry["value"] == value:
            c.execute(
                "INSERT INTO indicator_matches VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (event["event_id"], version, kind, value, entry["description"]),
            )
            persist_alert(
                c,
                run,
                rules,
                "known_indicator",
                {
                    "source": event["source_ip"],
                    "destination": event["destination_ip"] if kind == "ip" else None,
                    "ids": [event["event_id"]],
                },
                event["event_time_us"],
                {"indicator_matches": 1},
                {"match_policy": "exact"},
                temporal=False,
            )


def canonical_indicators(body):
    VALIDATORS["indicators"].validate(body)
    seen = set()
    for entry in body["entries"]:
        if entry["kind"] == "ip":
            entry["value"] = str(ipaddress.ip_address(entry["value"]))
        else:
            entry["value"] = entry["value"].lower().removesuffix(".")
            labels = entry["value"].split(".")
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or any(
                    ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for ch in label
                )
                for label in labels
            ):
                raise ValueError("Invalid exact domain")
        key = (entry["kind"], entry["value"])
        if key in seen:
            raise ValueError("Duplicate indicator")
        seen.add(key)
    return body
