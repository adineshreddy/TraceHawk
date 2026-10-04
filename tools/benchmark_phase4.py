"""Repeated one/two-worker trials and a bounded engineering-target attempt."""

from pathlib import Path
import json, os, platform, subprocess, threading, time

ROOT = Path(__file__).resolve().parents[1]


def compose(*args):
    subprocess.run(
        ["docker", "compose", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def trial(config, crash=False):
    code = (ROOT / "tools/benchmark_workload.py").read_text()
    snapshots = []
    done = threading.Event()

    def resources():
        while not done.is_set():
            r = subprocess.run(
                ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
            )
            rows = [json.loads(s) for s in r.stdout.splitlines() if s.strip()]
            snapshots.append(
                {
                    "elapsed_s": time.monotonic() - started,
                    "services": [
                        {k: r[k] for k in ["Name", "CPUPerc", "MemUsage"]}
                        for r in rows
                        if r["Name"].startswith("tracehawk-")
                    ],
                }
            )
            done.wait(2)

    def fault():
        if done.wait(3):
            return
        compose("kill", "-s", "SIGKILL", "detector")
        done.wait(3)
        compose("start", "detector")

    started = time.monotonic()
    thread = threading.Thread(target=resources)
    thread.start()
    fault_thread = threading.Thread(target=fault) if crash else None
    if fault_thread:
        fault_thread.start()
    try:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "-e",
                "BENCH_CONFIG=" + json.dumps(config),
                "-e",
                "PYTHONPATH=/app:/tools",
                "api",
                "python",
                "-",
            ],
            cwd=ROOT,
            input='import sys;sys.path.insert(0,"/tmp/phase4-tools")\n' + code,
            text=True,
            capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr[-2500:])
        report = json.loads(result.stdout)
        report["resources"] = snapshots
        report["injected_fault"] = (
            "SIGKILL detector at t≈3s; start after ≈3s" if crash else None
        )
        return report
    finally:
        done.set()
        thread.join()
        if fault_thread:
            fault_thread.join()


def hardware():
    result = {
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }
    if platform.system() == "Darwin":
        result["hardware"] = {}
        for key, field in [
            ("hw.model", "model"),
            ("machdep.cpu.brand_string", "cpu"),
            ("hw.memsize", "physical_memory_bytes"),
        ]:
            value = subprocess.check_output(["sysctl", "-n", key], text=True).strip()
            result["hardware"][field] = int(value) if field.endswith("bytes") else value
    info = json.loads(
        subprocess.check_output(["docker", "info", "--format", "{{json .}}"], text=True)
    )
    result["docker"] = {
        k: info[k] for k in ["NCPU", "MemTotal", "ServerVersion", "Architecture"]
    }
    return result


def main():
    # Copy only pure routing helper; no credentials or labels into the runtime.
    subprocess.run(
        ["docker", "compose", "exec", "-T", "api", "mkdir", "-p", "/tmp/phase4-tools"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "compose",
            "cp",
            "tools/evaluation_common.py",
            "api:/tmp/phase4-tools/evaluation_common.py",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    reports = []
    try:
        for workers in (1, 2):
            (
                compose("stop", "detector-b")
                if workers == 1
                else compose("start", "detector-b")
            )
            time.sleep(8)
            for hosts in (1, 32):
                for repeat in range(2):
                    config = {
                        "rate": 40,
                        "seconds": 12,
                        "hosts": hosts,
                        "pattern": "benign",
                        "workers": workers,
                        "repeat": repeat,
                        "seed": 7,
                    }
                    report = trial(config)
                    reports.append(report)
                    (ROOT / "tmp/benchmark-progress.json").write_text(
                        json.dumps(reports)
                    )
                    print(
                        json.dumps(
                            {
                                "workers": workers,
                                "hosts": hosts,
                                "repeat": repeat,
                                "durable_events_per_s": report[
                                    "durable_events_per_s_including_drain"
                                ],
                                "p95_observed_s": report[
                                    "ingestion_to_durable_observation"
                                ]["p95_s"],
                            }
                        ),
                        flush=True,
                    )
        cfg = {
            "rate": 40,
            "seconds": 12,
            "hosts": 4,
            "pattern": "scan",
            "workers": 2,
            "seed": 17,
        }
        reference = trial(cfg)
        recovered = trial(cfg, True)
        assert (
            reference["content_sha256"] == recovered["content_sha256"]
            and reference["alert_effects"] == recovered["alert_effects"]
        )
        assert reference["unique_persisted"] == recovered["unique_persisted"] == 480
        reports.extend([reference, recovered])
        (ROOT / "tmp/benchmark-progress.json").write_text(json.dumps(reports))
        print("Loaded scan recovery parity passed.", flush=True)
        target = trial(
            {
                "rate": 500,
                "seconds": 600,
                "hosts": 32,
                "pattern": "benign",
                "workers": 2,
                "seed": 31,
                "max_backlog": 3000,
            }
        )
        reports.append(target)
        calibration = trial(
            {
                "rate": 20,
                "seconds": 3,
                "hosts": 8,
                "pattern": "benign",
                "workers": 2,
                "seed": 71,
                "profile": "disk-calibration",
            }
        )
        reports.append(calibration)
        report = {
            "status": "passed",
            "disk_calibration": {
                "before_bytes": calibration["database_bytes_before"],
                "after_bytes": calibration["database_bytes_after"],
                "delta_bytes": calibration["database_bytes_after"]
                - calibration["database_bytes_before"],
                "events": calibration["unique_persisted"],
                "note": "Whole database growth over one short calibration; includes background health writes. Not per-event storage cost.",
            },
            "host": hardware(),
            "scope": "Real Kafka/PostgreSQL detector pipeline; synthetic generator bypasses Go source replay and HTTP admission; bounded inputs; monitoring on. Short trials are not sustained-capacity estimates.",
            "engineering_target": {
                "rate": 500,
                "seconds": 600,
                "completed": target["target_completed"],
                "early_stop_reason": target["early_stop_reason"],
                "actually_published_s": target["publication_s"],
            },
            "recovery_final_effect_parity": True,
            "trials": reports,
        }
        (ROOT / "evaluation/reports/benchmark.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps({k: v for k, v in report.items() if k != "trials"}, indent=2))
    finally:
        compose("start", "detector", "detector-b")


if __name__ == "__main__":
    main()
