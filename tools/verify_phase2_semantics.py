"""Production query/time/suppression tests; synthetic rows remain inside a rolled-back transaction."""

import copy, json, uuid
from psycopg.types.json import Jsonb
from tracehawk.core import db, digest, ROOT
from tracehawk.detector import apply, STEP, WINDOW
from tracehawk.detections import temporal_matches, persist_alert, match_indicator

BASE = 1791028800000000


class Finished(Exception):
    pass


def main():
    c = db()
    checks = []
    try:
        with c.transaction():
            checkpoints = c.execute(
                "SELECT * FROM partition_checkpoints ORDER BY partition FOR UPDATE"
            ).fetchall()
            offset = checkpoints[0]["next_offset"]
            epoch = checkpoints[0]["ownership_epoch"]
            original = c.execute(
                "SELECT * FROM runs WHERE rule_version='phase2-rules-v1' AND scenario_id='phase0-controlled-network-v1' AND status='completed' LIMIT 1"
            ).fetchone()
            assert original, "Run Phase 2 integration first"
            conn = json.loads(
                (ROOT / "scenarios/phase0/normalized-events.jsonl")
                .read_text()
                .splitlines()[0]
            )
            dns = next(
                json.loads(x)
                for x in (ROOT / "scenarios/phase0/normalized-events.jsonl")
                .read_text()
                .splitlines()
                if json.loads(x)["event_kind"] == "dns"
            )
            baseline = c.execute(
                "SELECT body FROM rule_versions WHERE version='phase2-rules-v1'"
            ).fetchone()["body"]

            def run(cfg=None):
                cfg = copy.deepcopy(cfg or baseline)
                version = "semantics-" + uuid.uuid4().hex
                cfg["version"] = version
                c.execute(
                    "INSERT INTO rule_versions(version,body,created_by) VALUES(%s,%s,%s)",
                    (version, Jsonb(cfg), "test"),
                )
                rid = "semantics-" + uuid.uuid4().hex
                meta = copy.deepcopy(original["metadata"])
                meta.update(time_start_us=BASE, time_end_us=BASE + 400_000_000)
                r = c.execute(
                    "INSERT INTO runs(run_id,scope_id,workspace,scenario_id,rule_version,status,speed,metadata,total_records,generation,indicator_version) VALUES(%s,%s,'isolated-semantics',%s,%s,'completed',10,%s,100,1,%s) RETURNING *",
                    (
                        rid,
                        rid,
                        original["scenario_id"],
                        version,
                        Jsonb(meta),
                        original["indicator_version"],
                    ),
                ).fetchone()
                for p in range(3):
                    c.execute(
                        "INSERT INTO run_partitions(run_id,partition) VALUES(%s,%s)",
                        (rid, p),
                    )
                return r, cfg

            serial = 0

            def event(
                r,
                t,
                port=80,
                state="REJ",
                kind="connection",
                rcode=3,
                query="host0.example.test",
                source="192.0.2.10",
            ):
                nonlocal serial
                serial += 1
                e = copy.deepcopy(conn if kind == "connection" else dns)
                e.update(
                    run_id=r["run_id"],
                    scope_id=r["scope_id"],
                    event_time_us=t,
                    original_timestamp_us=t,
                    source_ip=source,
                    destination_port=port,
                )
                e["provenance"]["record_offset"] = serial
                e["event_id"] = digest(
                    [
                        r["scope_id"],
                        e["sensor_id"],
                        e["provenance"]["source_generation_id"],
                        e["provenance"]["log_kind"],
                        serial,
                    ]
                )
                if kind == "connection":
                    e["connection"].update(duration_us=0, state=state)
                    e["time_basis"] = "connection_activity_end"
                else:
                    e["dns"].update(
                        rcode=rcode,
                        rcode_name=(
                            "NXDOMAIN"
                            if rcode == 3
                            else "NOERROR" if rcode == 0 else None
                        ),
                        query=query,
                    )
                return e

            def store(r, e, eligible=True):
                c.execute(
                    "INSERT INTO events VALUES(%s,%s,0,0,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        e["event_id"],
                        r["run_id"],
                        e["event_time_us"],
                        e["source_ip"],
                        e["destination_ip"],
                        e["destination_port"],
                        e["event_kind"],
                        e["protocol"],
                        eligible,
                        Jsonb(e),
                    ),
                )

            # Inclusive sample thresholds; missing state, OTH, UDP and other sources cannot inflate denominators.
            r, cfg = run()
            end = BASE + 60_000_000
            for i in range(20):
                store(
                    r,
                    event(r, BASE + i * 1_000_000, 9000 + i, "REJ" if i < 16 else "SF"),
                )
            for state in (None, "OTH"):
                store(r, event(r, BASE + 2_000_000, 9100, state))
            udp = event(r, BASE + 2_000_000, 9101)
            udp["protocol"] = "udp"
            store(r, udp)
            store(r, event(r, BASE + 2_000_000, 9102, source="192.0.2.11"))
            for i in range(30):
                store(
                    r,
                    event(
                        r,
                        BASE + i * 1_000_000,
                        53,
                        kind="dns",
                        rcode=3.0 if i == 0 else 3 if i < 18 else 0,
                        source="192.0.2.30",
                    ),
                )
            store(
                r,
                event(
                    r, BASE + 2_000_000, 53, kind="dns", rcode=None, source="192.0.2.30"
                ),
            )
            matches = {
                name: (g, o, t) for name, g, o, t in temporal_matches(c, r, 0, end, cfg)
            }
            assert matches["failed_tcp_connections"][1] == {
                "attempts": 20,
                "failure_ratio": 0.8,
            }, matches
            assert matches["dns_nxdomain_burst"][1] == {
                "completed_responses": 30,
                "nxdomain_ratio": 0.6,
            }, matches
            assert (
                matches["vertical_tcp_scan"][1]["distinct_ports"] == 21
            )  # recognized OTH remains scan-eligible; null state excluded
            # Move one known failure to successful, and one NXDOMAIN response to successful: both fall below ratio.
            c.execute(
                "UPDATE events SET body=jsonb_set(body,'{connection,state}','\"SF\"'::jsonb) WHERE event_id=(SELECT event_id FROM events WHERE run_id=%s AND body->'connection'->>'state'='REJ' AND protocol='tcp' AND source_ip='192.0.2.10' ORDER BY event_id LIMIT 1)",
                (r["run_id"],),
            )
            c.execute(
                "UPDATE events SET body=jsonb_set(body,'{dns,rcode}','0'::jsonb) WHERE event_id=(SELECT event_id FROM events WHERE run_id=%s AND event_kind='dns' AND body->'dns'->>'rcode'='3' ORDER BY event_id LIMIT 1)",
                (r["run_id"],),
            )
            below = {name for name, *_ in temporal_matches(c, r, 0, end, cfg)}
            assert (
                "failed_tcp_connections" not in below
                and "dns_nxdomain_burst" not in below
            )
            cfg["failed_tcp_connections"]["min_attempts"] = 21
            cfg["dns_nxdomain_burst"]["min_responses"] = 31
            cfg["failed_tcp_connections"]["min_failure_ratio"] = 0
            cfg["dns_nxdomain_burst"]["min_nxdomain_ratio"] = 0
            below = {name for name, *_ in temporal_matches(c, r, 0, end, cfg)}
            assert (
                "failed_tcp_connections" not in below
                and "dns_nxdomain_burst" not in below
            )
            checks.append(
                "exact and below count/ratio thresholds, numeric DNS code 3.0; null/OTH/UDP excluded from classified denominators"
            )
            # On-time reordering must preserve earlier unfinalized windows across a five-minute episode boundary.
            cfg = copy.deepcopy(baseline)
            cfg["vertical_tcp_scan"]["min_distinct_ports"] = 2
            for name in (
                "failed_tcp_connections",
                "dns_nxdomain_burst",
                "known_indicator",
            ):
                cfg[name]["enabled"] = False
            results = []
            for times in ([286, 287, 315], [315, 287, 286]):
                rr, rcfg = run(cfg)
                for t in times:
                    e = event(rr, BASE + t * 1_000_000, 9000 + t)
                    apply(c, 0, offset, json.dumps(e).encode(), epoch)
                    offset += 1
                control = {
                    "schema_version": "1.0",
                    "control_kind": "replay_partition_complete",
                    "run_id": rr["run_id"],
                    "scope_id": rr["scope_id"],
                    "producer_generation": 1,
                    "partition": 0,
                    "last_data_offset": offset - 1,
                    "final_watermark_us": BASE + 460_000_000,
                    "manifest_sha256": rr["metadata"]["manifest_sha256"],
                }
                apply(c, 0, offset, json.dumps(control).encode(), epoch)
                offset += 1
                alerts = c.execute(
                    "SELECT body FROM alerts WHERE run_id=%s ORDER BY body->>'episode_bucket_start_us'",
                    (rr["run_id"],),
                ).fetchall()
                windows = c.execute(
                    "SELECT window_end_us,observed FROM alert_windows w JOIN alerts a USING(alert_id) WHERE run_id=%s ORDER BY window_end_us",
                    (rr["run_id"],),
                ).fetchall()
                results.append(
                    (
                        [
                            (
                                a["body"]["episode_bucket_start_us"],
                                a["body"]["observed"],
                                a["body"]["evidence_total_count"],
                            )
                            for a in alerts
                        ],
                        windows,
                    )
                )
                before = c.execute(
                    "SELECT sum(revision) total FROM alerts WHERE run_id=%s",
                    (rr["run_id"],),
                ).fetchone()["total"]
                apply(c, 0, offset, json.dumps(control).encode(), epoch)
                offset += 1
                assert (
                    c.execute(
                        "SELECT sum(revision) total FROM alerts WHERE run_id=%s",
                        (rr["run_id"],),
                    ).fetchone()["total"]
                    == before
                )
            assert results[0] == results[1] and len(results[0][0]) == 2, results
            checks.append(
                "ordered/on-time reordered events yield identical bucket metrics, evidence counts and windows; completion idempotent"
            )
            # Too-late temporal events still receive exact point-in-time indicator matching.
            rr, rcfg = run()
            first = event(rr, BASE + 100_000_000)
            apply(c, 0, offset, json.dumps(first).encode(), epoch)
            offset += 1
            late = event(rr, BASE + 70_000_000, 9001, source="192.0.2.11")
            apply(c, 0, offset, json.dumps(late).encode(), epoch)
            offset += 1
            assert not c.execute(
                "SELECT eligible FROM events WHERE event_id=%s", (late["event_id"],)
            ).fetchone()["eligible"]
            assert (
                c.execute(
                    "SELECT reason FROM event_exclusions WHERE event_id=%s",
                    (late["event_id"],),
                ).fetchone()["reason"]
                == "at_or_before_watermark"
            )
            assert c.execute(
                "SELECT 1 FROM indicator_matches WHERE event_id=%s", (late["event_id"],)
            ).fetchone()
            checks.append(
                "watermark equality retained with exclusion reason; indicator matching still applies"
            )
            # Exact domain matching: no suffix/subdomain or unknown-response inference.
            rr, rcfg = run()
            for query, want in [
                ("host0.example.test", True),
                ("www.host0.example.test", False),
                ("host0.example.test.evil", False),
            ]:
                e = event(rr, BASE + 1_000_000, 53, kind="dns", rcode=None, query=query)
                store(rr, e)
                match_indicator(c, rr, rcfg, e)
                assert (
                    bool(
                        c.execute(
                            "SELECT 1 FROM indicator_matches WHERE event_id=%s",
                            (e["event_id"],),
                        ).fetchone()
                    )
                    == want
                )
            checks.append(
                "exact DNS matching without suffix expansion; null response remains unknown"
            )
            # Event-time validity is inclusive start / exclusive expiry; audit creation time is separate.
            for instant, want in [
                (BASE - 1, False),
                (BASE, True),
                (BASE + 9, True),
                (BASE + 10, False),
            ]:
                rr, rcfg = run()
                e = event(rr, max(instant, BASE))
                e["event_time_us"] = instant
                store(rr, e)
                sup = {
                    "schema_version": "1.0",
                    "suppression_id": uuid.uuid4().hex,
                    "scope_id": rr["scope_id"],
                    "detector_id": "vertical_tcp_scan",
                    "source_ip": e["source_ip"],
                    "destination_ip": e["destination_ip"],
                    "reason": "Synthetic boundary test",
                    "created_by": "operator",
                    "created_at_us": BASE,
                    "expires_at_us": BASE + 10,
                }
                c.execute(
                    "INSERT INTO suppressions(suppression_id,scope_id,body,validity_mode) VALUES(%s,%s,%s,%s)",
                    (
                        sup["suppression_id"],
                        rr["scope_id"],
                        Jsonb(sup),
                        "scenario_interval",
                    ),
                )
                aid = persist_alert(
                    c,
                    rr,
                    rcfg,
                    "vertical_tcp_scan",
                    {
                        "source": e["source_ip"],
                        "destination": e["destination_ip"],
                        "ids": [e["event_id"]],
                    },
                    BASE + STEP,
                    {"distinct_ports": 20},
                    {"min_distinct_ports": 20, "window_seconds": 60},
                )
                assert (
                    c.execute(
                        "SELECT body FROM alerts WHERE alert_id=%s", (aid,)
                    ).fetchone()["body"]["suppressed"]
                    == want
                )
            checks.append(
                "suppression validity [start,expiry), same-scope exact source/destination; decision uses contributing event time"
            )
            rr, rcfg = run()
            evidence_ids = []
            for i in range(201):
                e = event(rr, BASE + 1_000_000 + i, 8000 + i)
                store(rr, e)
                evidence_ids.append(e["event_id"])
            aid = persist_alert(
                c,
                rr,
                rcfg,
                "known_indicator",
                {
                    "source": "192.0.2.10",
                    "destination": "192.0.2.20",
                    "ids": evidence_ids,
                },
                BASE + 2_000_000,
                {"indicator_matches": 201},
                {"match_policy": "exact"},
                temporal=False,
            )
            capped = c.execute(
                "SELECT body FROM alerts WHERE alert_id=%s", (aid,)
            ).fetchone()["body"]
            assert (
                len(capped["evidence_event_ids"]) == 200
                and capped["evidence_total_count"] == 201
                and capped["evidence_truncated"]
            )
            assert capped["observed"]["indicator_matches"] == 201
            assert (
                c.execute(
                    "SELECT count(*) n FROM alert_evidence WHERE alert_id=%s", (aid,)
                ).fetchone()["n"]
                == 201
            )
            checks.append(
                "201 unique contributing events retain exact totals while alert evidence IDs cap at 200"
            )
            raise Finished()
    except Finished:
        pass
    finally:
        c.close()
    print(
        json.dumps(
            {
                "status": "passed",
                "checks": checks,
                "test_data": "synthetic records and checkpoint changes rolled back",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
