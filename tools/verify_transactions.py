"""Database transaction invariants against the running backend (private container)."""

import copy, json, uuid
from psycopg.types.json import Jsonb
from tracehawk.core import db, digest
from tracehawk.detector import apply, scan_groups


def main():
    c = db()
    # Lock partitions only for this short transaction; all test mutations roll back.
    try:
        with c.transaction():
            cps = c.execute(
                "SELECT * FROM partition_checkpoints ORDER BY partition FOR UPDATE"
            ).fetchall()
            existing = c.execute(
                "SELECT e.body FROM events e JOIN runs r USING(run_id) WHERE r.status='completed' AND e.body->>'source_ip'='192.0.2.10' LIMIT 1"
            ).fetchone()["body"]
            original = c.execute(
                "SELECT * FROM runs WHERE run_id=%s", (existing["run_id"],)
            ).fetchone()
            runid = "test-" + uuid.uuid4().hex
            scope = runid
            c.execute(
                "INSERT INTO runs(run_id,scope_id,workspace,scenario_id,rule_version,status,speed,metadata,total_records,generation) VALUES(%s,%s,'transaction-test',%s,%s,'completed',10,%s,108,1)",
                (
                    runid,
                    scope,
                    original["scenario_id"],
                    original["rule_version"],
                    Jsonb(original["metadata"]),
                ),
            )
            for p in range(3):
                c.execute(
                    "INSERT INTO run_partitions(run_id,partition) VALUES(%s,%s)",
                    (runid, p),
                )
            event = copy.deepcopy(existing)
            event.update(run_id=runid, scope_id=scope)
            prov = event["provenance"]
            event["event_id"] = digest(
                [
                    scope,
                    event["sensor_id"],
                    prov["source_generation_id"],
                    prov["log_kind"],
                    prov["record_offset"],
                ]
            )
            part = cps[0]["partition"]
            offset = cps[0]["next_offset"]
            epoch = cps[0]["ownership_epoch"]
            before = dict(
                c.execute(
                    "SELECT * FROM run_partitions WHERE run_id=%s AND partition=%s",
                    (runid, part),
                ).fetchone()
            )
            try:
                with c.transaction():
                    apply(
                        c, part, offset, json.dumps(event).encode(), epoch, fault=True
                    )
            except RuntimeError as error:
                assert str(error) == "Injected transaction rollback"
            else:
                raise AssertionError("Fault did not execute")
            assert (
                c.execute(
                    "SELECT next_offset FROM partition_checkpoints WHERE partition=%s",
                    (part,),
                ).fetchone()["next_offset"]
                == offset
            )
            assert (
                c.execute(
                    "SELECT count(*) n FROM events WHERE run_id=%s", (runid,)
                ).fetchone()["n"]
                == 0
            )
            assert (
                dict(
                    c.execute(
                        "SELECT * FROM run_partitions WHERE run_id=%s AND partition=%s",
                        (runid, part),
                    ).fetchone()
                )
                == before
            )
            assert (
                c.execute(
                    "SELECT count(*) n FROM event_processing_receipts WHERE run_id=%s",
                    (runid,),
                ).fetchone()["n"]
                == 0
            )
            apply(c, part, offset, json.dumps(event).encode(), epoch)
            # Re-delivery at a NEW broker offset still has a stable logical event identity.
            apply(c, part, offset + 1, json.dumps(event).encode(), epoch)
            assert (
                c.execute(
                    "SELECT count(*) n FROM events WHERE run_id=%s", (runid,)
                ).fetchone()["n"]
                == 1
            )

            assert (
                c.execute(
                    "SELECT count(*) n FROM event_processing_receipts WHERE run_id=%s",
                    (runid,),
                ).fetchone()["n"]
                == 1
            )

            # Exercise the production SQL query, including exact boundaries and missing state.
            class BoundaryDone(Exception):
                pass

            try:
                with c.transaction():
                    end = event["event_time_us"] + 60_000_000
                    c.execute("DELETE FROM events WHERE run_id=%s", (runid,))
                    for number, (t, port, state, protocol, source) in enumerate(
                        [
                            (end - 60_000_000, 80, "REJ", "tcp", "192.0.2.10"),
                            (end - 1, 81, "REJ", "tcp", "192.0.2.10"),
                            (end - 2, 81, "REJ", "tcp", "192.0.2.10"),
                            (end, 82, "REJ", "tcp", "192.0.2.10"),
                            (end - 60_000_001, 83, "REJ", "tcp", "192.0.2.10"),
                            (end - 1, 84, None, "tcp", "192.0.2.10"),
                            (end - 1, 85, "REJ", "udp", "192.0.2.10"),
                            (end - 1, 86, "REJ", "tcp", "192.0.2.11"),
                        ]
                    ):
                        body = copy.deepcopy(event)
                        body["connection"]["state"] = state
                        c.execute(
                            "INSERT INTO events VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true,%s)",
                            (
                                digest(["boundary", number]),
                                runid,
                                part,
                                number,
                                t,
                                source,
                                "192.0.2.20",
                                port,
                                "connection",
                                protocol,
                                Jsonb(body),
                            ),
                        )
                    groups = scan_groups(c, runid, part, end, 2)
                    assert (
                        len(groups) == 1
                        and groups[0]["n"] == 2
                        and len(groups[0]["ids"]) == 3
                    ), groups
                    raise BoundaryDone()
            except BoundaryDone:
                pass
            late = copy.deepcopy(event)
            late["event_id"] = digest(
                [
                    scope,
                    event["sensor_id"],
                    prov["source_generation_id"],
                    prov["log_kind"],
                    prov["record_offset"] + 1,
                ]
            )
            late["provenance"]["record_offset"] += 1
            c.execute(
                "UPDATE run_partitions SET watermark_us=%s WHERE run_id=%s AND partition=%s",
                (late["event_time_us"], runid, part),
            )
            apply(c, part, offset + 2, json.dumps(late).encode(), epoch)
            assert not c.execute(
                "SELECT eligible FROM events WHERE event_id=%s", (late["event_id"],)
            ).fetchone()["eligible"]
            control = {
                "schema_version": "1.0",
                "control_kind": "replay_partition_complete",
                "run_id": runid,
                "scope_id": scope,
                "producer_generation": 999,
                "partition": part,
                "last_data_offset": offset + 2,
                "final_watermark_us": 0,
                "manifest_sha256": original["metadata"]["manifest_sha256"],
            }
            apply(c, part, offset + 3, json.dumps(control).encode(), epoch)
            assert (
                c.execute(
                    "SELECT completed_generation FROM run_partitions WHERE run_id=%s AND partition=%s",
                    (runid, part),
                ).fetchone()["completed_generation"]
                is None
            )
            assert (
                c.execute(
                    "SELECT count(*) n FROM deadletters WHERE partition=%s AND broker_offset=%s",
                    (part, offset + 3),
                ).fetchone()["n"]
                == 1
            )
            # Flush a qualifying scan then inject rollback: alert, evidence, outbox and offset stay absent.
            for port in range(20):
                e = copy.deepcopy(event)
                e["destination_port"] = 9000 + port
                e["provenance"]["record_offset"] = 100000 + port
                e["event_id"] = digest(
                    [
                        scope,
                        e["sensor_id"],
                        prov["source_generation_id"],
                        prov["log_kind"],
                        100000 + port,
                    ]
                )
                apply(c, part, offset + 4 + port, json.dumps(e).encode(), epoch)
            c.execute("UPDATE events SET eligible=true WHERE run_id=%s", (runid,))
            control.update(
                producer_generation=1,
                last_data_offset=offset + 23,
                final_watermark_us=(original["metadata"]["time_end_us"] + 9999999)
                // 10000000
                * 10000000
                + 60000000,
            )
            checkpoint = c.execute(
                "SELECT next_offset FROM partition_checkpoints WHERE partition=%s",
                (part,),
            ).fetchone()["next_offset"]
            try:
                with c.transaction():
                    apply(
                        c,
                        part,
                        offset + 24,
                        json.dumps(control).encode(),
                        epoch,
                        fault=True,
                    )
            except RuntimeError:
                pass
            else:
                raise AssertionError("Finalization rollback did not execute")
            assert (
                c.execute(
                    "SELECT count(*) n FROM alerts WHERE run_id=%s", (runid,)
                ).fetchone()["n"]
                == 0
            )
            assert (
                c.execute(
                    "SELECT count(*) n FROM outbox o JOIN alerts a USING(alert_id) WHERE run_id=%s",
                    (runid,),
                ).fetchone()["n"]
                == 0
            )
            assert (
                c.execute(
                    "SELECT next_offset FROM partition_checkpoints WHERE partition=%s",
                    (part,),
                ).fetchone()["next_offset"]
                == checkpoint
            )
            apply(c, part, offset + 24, json.dumps(control).encode(), epoch)
            assert (
                c.execute(
                    "SELECT count(*) n FROM alerts WHERE run_id=%s", (runid,)
                ).fetchone()["n"]
                == 1
            )
            assert (
                c.execute(
                    "SELECT count(*) n FROM outbox o JOIN alerts a USING(alert_id) WHERE run_id=%s",
                    (runid,),
                ).fetchone()["n"]
                > 0
            )
            # This deliberate exception rolls back ALL test records/checkpoint changes.
            raise RuntimeError("Cleanup test transaction")
    except RuntimeError as error:
        assert str(error) == "Cleanup test transaction", error
    finally:
        c.close()
    print(
        json.dumps(
            {
                "status": "passed",
                "checks": [
                    "production SQL boundaries, distinct ports, protocol, null state and source grouping",
                    "event/state/checkpoint rollback",
                    "duplicate identity at new offset",
                    "measurement receipt rolls back and deduplicates with event",
                    "event at watermark excluded",
                    "invalid completion quarantined",
                    "alert/evidence/outbox/checkpoint finalization rollback",
                ],
                "test_data": "rolled back",
            }
        )
    )


if __name__ == "__main__":
    main()
