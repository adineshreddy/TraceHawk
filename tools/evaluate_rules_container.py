"""Production detector evaluation; all input/state changes roll back per capture."""

from pathlib import Path
import json, hashlib
from psycopg.types.json import Jsonb
from tracehawk.core import db, initialize, digest
from tracehawk.detector import apply, STEP, WINDOW
from tracehawk.api import insert_suppression
from evaluation_common import partition, match_episodes

initialize()
corpus = Path("/corpus")
inputs = Path("/inputs")
freeze = json.loads((corpus / "freeze.json").read_text())
results = []
for name in freeze["captures"]:
    m = json.loads((corpus / name / "manifest.json").read_text())
    labels = json.loads((corpus / name / "labels.json").read_text())
    rows = [
        json.loads(s) for s in (inputs / (name + ".jsonl")).read_text().splitlines()
    ]
    meta = {k: m[k] for k in ("time_start_us", "time_end_us", "log_hashes")}
    meta["manifest_sha256"] = hashlib.sha256(
        (corpus / name / "manifest.json").read_bytes()
    ).hexdigest()
    c = db()
    try:
        with c.transaction():
            c.execute(
                "INSERT INTO runs(run_id,scope_id,workspace,scenario_id,rule_version,status,speed,metadata,total_records,generation,indicator_version) VALUES(%s,%s,'evaluation',%s,'phase2-rules-v1','completed',10,%s,%s,1,'phase2-fictional-v1')",
                (name, name, name, Jsonb(meta), len(rows)),
            )
            run = c.execute("SELECT * FROM runs WHERE run_id=%s", (name,)).fetchone()
            for p in range(3):
                c.execute(
                    "INSERT INTO run_partitions(run_id,partition) VALUES(%s,%s)",
                    (name, p),
                )
            for policy in labels["policies"]:
                insert_suppression(
                    c,
                    run,
                    policy | {"scope_id": name, "validity_mode": "scenario_interval"},
                    {"username": "evaluation"},
                )
            offsets = [0] * 3
            for e in rows:
                p = partition(name, e["source_ip"])
                apply(c, p, offsets[p], json.dumps(e).encode(), 0)
                offsets[p] += 1
            for p in range(3):
                last = offsets[p] - 1 if offsets[p] else None
                control = {
                    "schema_version": "1.0",
                    "control_kind": "replay_partition_complete",
                    "run_id": name,
                    "scope_id": name,
                    "partition": p,
                    "producer_generation": 1,
                    "manifest_sha256": meta["manifest_sha256"],
                    "last_data_offset": last,
                    "final_watermark_us": (m["time_end_us"] + STEP - 1) // STEP * STEP
                    + WINDOW,
                }
                apply(c, p, offsets[p], json.dumps(control).encode(), 0)
            assert (
                c.execute("SELECT count(*) n FROM deadletters").fetchone()["n"] == 0
            ), name
            assert c.execute(
                "SELECT count(*) n FROM events WHERE run_id=%s", (name,)
            ).fetchone()["n"] == len(rows)
            alerts = [
                {
                    k: v
                    for k, v in a["body"].items()
                    if k not in ("created_at_us", "updated_at_us", "suppression_id")
                }
                for a in c.execute(
                    "SELECT body FROM alerts WHERE run_id=%s ORDER BY alert_id", (name,)
                ).fetchall()
            ]
            results.append(
                {
                    "capture": name,
                    "split": m["split"],
                    "context": labels["context"],
                    "events": len(rows),
                    "labels": labels["episodes"],
                    "suppressed": [a for a in alerts if a["suppressed"]],
                    "predictions": [a for a in alerts if not a["suppressed"]],
                    "observed_host_hours": m["observed_host_hours"],
                    "benign_explanation": labels["benign_explanation"],
                }
            )
            raise ValueError("rollback")
    except ValueError as e:
        assert str(e) == "rollback"
    finally:
        c.close()
held = [r for r in results if r["split"] == "held-out"]
families = [
    "vertical_tcp_scan",
    "failed_tcp_connections",
    "dns_nxdomain_burst",
    "known_indicator",
    "horizontal_scan",
]
summary = {}
for family in families:
    aggregate = {"tp": 0, "fp": 0, "fn": 0}
    misses = []
    fps = []
    for r in held:
        ps = [p for p in r["predictions"] if p["detector_id"] == family]
        ts = [t for t in r["labels"] if t["detector_id"] == family]
        scores = match_episodes(ps, ts)
        for k in aggregate:
            aggregate[k] += scores[k]
        if scores["fn"]:
            misses.append(r["capture"])
        if scores["fp"]:
            fps.append(r["capture"])
    tp, fp, fn = (aggregate[k] for k in ("tp", "fp", "fn"))
    summary[family] = aggregate | {
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "missed_captures": misses,
        "false_positive_captures": fps,
        "implemented": family != "horizontal_scan",
    }
benign = [r for r in held if not r["labels"]]
hours = sum(r["observed_host_hours"] for r in benign)
count = sum(len(r["predictions"]) for r in benign)
print(
    json.dumps(
        {
            "status": "passed",
            "corpus_version": freeze["version"],
            "production_rules": "phase2-rules-v1",
            "per_family": summary,
            "benign_exposure": {
                "host_hours": hours,
                "actionable_alerts": count,
                "alerts_per_host_hour": count / hours,
            },
            "suppressed_alerts": sum(len(r["suppressed"]) for r in held),
            "captures": results,
            "scope": "Synthetic capture sensitivity and counterexamples, not production accuracy.",
        },
        indent=2,
    )
)
