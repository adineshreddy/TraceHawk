"""Crash after Kafka ACK and before source checkpoint; then recover the same run."""

from pathlib import Path
import json, os, subprocess, time
from verify_phase1 import ROOT, client, start, verify, wait


def main():
    env = dict(os.environ, FAULT_AFTER_ACK="1")
    # Ensure the one-shot marker is clear without resetting replay/DB/Kafka data.
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "from tracehawk.core import db; c=db(); assert not c.execute(\"SELECT 1 FROM runs WHERE status IN ('queued','preparing','replaying','finalizing')\").fetchone()",
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "tracehawk_collector_state:/state",
            "--entrypoint",
            "python",
            "tracehawk-backend:phase4",
            "-c",
            "from pathlib import Path; Path('/state/fault-used').unlink(missing_ok=True)",
        ],
        cwd=ROOT,
        check=True,
    )
    try:
        subprocess.run(
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "collector",
            ],
            cwd=ROOT,
            env=env,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        c = client()
        run = start(c)
        deadline = time.monotonic() + 15
        observed = None
        while time.monotonic() < deadline:
            progress = c.get("/api/v1/runs/" + run["run_id"]).json()
            overview = c.get(
                "/api/v1/overview", params={"scope_id": run["scope_id"]}
            ).json()
            if overview["event_count"] == 1 and progress["processed_records"] == 0:
                observed = {"persisted_events_after_ack": 1, "source_checkpoint": 0}
                break
            time.sleep(0.2)
        assert observed is not None, (progress, overview)
        alerts = verify(c, run)
        report = {
            "status": "passed",
            "run_id": run["run_id"],
            "crash_point": "Kafka acknowledged record before source checkpoint",
            **observed,
            "final_unique_events": 108,
            "alerts": len(alerts),
            "evidence": alerts[0]["evidence_total_count"],
        }
        (ROOT / "docs/phase-1/collector-recovery.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps(report, indent=2))
    finally:
        subprocess.run(
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "collector",
            ],
            cwd=ROOT,
            env=dict(os.environ, FAULT_AFTER_ACK="0"),
            check=True,
            stdout=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    main()
