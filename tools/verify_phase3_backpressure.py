"""Exercise the real admission gate with saturated outbox rows, then roll back."""

import json, uuid
from contextlib import contextmanager
from psycopg.types.json import Jsonb
from tracehawk.core import db
from tracehawk import api

c = db()
try:
    with c.transaction():
        # Hold checkpoint locks briefly to keep the worker ownership view stable.
        c.execute(
            "SELECT * FROM partition_checkpoints ORDER BY partition FOR UPDATE"
        ).fetchall()
        original = c.execute(
            "SELECT * FROM runs WHERE status='completed' LIMIT 1"
        ).fetchone()
        a = c.execute("SELECT * FROM alerts LIMIT 1").fetchone()
        assert original and a
        run = "backpressure-" + uuid.uuid4().hex
        c.execute(
            "INSERT INTO runs(run_id,scope_id,workspace,scenario_id,rule_version,status,speed,metadata,total_records) VALUES(%s,%s,'test',%s,%s,'queued',10,%s,108)",
            (
                run,
                run,
                original["scenario_id"],
                original["rule_version"],
                Jsonb(original["metadata"]),
            ),
        )
        for i in range(1000):
            c.execute(
                "INSERT INTO outbox(update_id,alert_id,body) VALUES(%s,%s,%s)",
                (
                    run + "-" + str(i),
                    a["alert_id"],
                    Jsonb(
                        {"alert_id": a["alert_id"], "revision": i, "alert": a["body"]}
                    ),
                ),
            )

        @contextmanager
        def connection():
            yield c

        api.db = connection
        assert api.claim().status_code == 204
        assert c.execute(
            "SELECT generation,status FROM runs WHERE run_id=%s", (run,)
        ).fetchone() == {"generation": 0, "status": "queued"}
        h = c.execute(
            "SELECT status,details FROM component_health WHERE component='collector'"
        ).fetchone()
        assert h == {
            "status": "paused",
            "details": {"reason": "downstream_backpressure"},
        }
        raise ValueError("rollback")
except ValueError as e:
    assert str(e) == "rollback"
finally:
    c.close()
print(
    json.dumps(
        {
            "status": "passed",
            "checks": [
                "1000 pending updates prevent a source lease",
                "collector reports paused admission",
                "all saturation test rows rolled back",
            ],
        },
        indent=2,
    )
)
