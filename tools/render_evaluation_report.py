"""Derive human-readable and bounded API summaries only from measured artifacts."""

from pathlib import Path
import hashlib, json, statistics

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "evaluation/reports"


def main():
    rules = json.loads((REPORTS / "rules.json").read_text())
    ml = json.loads((REPORTS / "ml.json").read_text())
    bench = json.loads((REPORTS / "benchmark.json").read_text())
    assert all(r["status"] == "passed" for r in (rules, ml, bench))
    short = [
        r
        for r in bench["trials"]
        if r["config"]["pattern"] == "benign" and r["config"]["rate"] == 40
    ]
    trials = []
    for workers in (1, 2):
        for hosts in (1, 32):
            rs = [
                r
                for r in short
                if r["config"]["workers"] == workers and r["config"]["hosts"] == hosts
            ]
            assert len(rs) == 2
            trials.append(
                {
                    "workers": workers,
                    "sources": hosts,
                    "repeats": 2,
                    "offered_events_per_s": 40,
                    "duration_s": 12,
                    "mean_durable_events_per_s": statistics.mean(
                        r["durable_events_per_s_including_drain"] for r in rs
                    ),
                    "max_p95_durable_observation_s": max(
                        r["ingestion_to_durable_observation"]["p95_s"] for r in rs
                    ),
                    "events_per_trial": 480,
                }
            )
    source_hashes = {
        name: hashlib.sha256((REPORTS / (name + ".json")).read_bytes()).hexdigest()
        for name in ("rules", "ml", "benchmark")
    }
    summary = {
        "version": "evaluation-v1",
        "scope": "Frozen synthetic sensitivity/counterexample corpus; not representative real-world accuracy.",
        "captures": 28,
        "held_out_captures": 12,
        "held_out_host_hours": rules["benign_exposure"]["host_hours"],
        "benign_alerts": rules["benign_exposure"]["actionable_alerts"],
        "suppressed_alerts": rules["suppressed_alerts"],
        "rules": [{"family": name, **row} for name, row in rules["per_family"].items()],
        "model": {
            k: ml[k]
            for k in (
                "default_enabled",
                "train_windows",
                "validation_windows",
                "held_out_windows",
                "source_episode_metrics",
                "new_true_positive_captures",
                "recommendation",
            )
        },
        "short_trials": trials,
        "engineering_target": bench["engineering_target"],
        "recovery_final_effect_parity": bench["recovery_final_effect_parity"],
        "source_report_sha256": source_hashes,
    }
    (REPORTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [
        "# TraceHawk evaluation v1",
        "",
        summary["scope"],
        "",
        "Inputs: 28 pinned-Zeek captures; 12 held out. Production phase2-rules-v1 unchanged. Matching was frozen before evaluation; labels never enter canonical events.",
        "",
        "## Held-out rule episodes",
        "",
        "| Family | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    fmt = lambda x: "—" if x is None else f"{x:.1%}"
    for r in summary["rules"]:
        lines.append(
            f"| {r['family']}{' (unsupported)' if not r['implemented'] else ''} | {r['tp']} | {r['fp']} | {r['fn']} | {fmt(r['precision'])} | {fmt(r['recall'])} |"
        )
    lines += [
        "",
        "The fast scan, rejected-attempt episode, DNS burst and two fictional exact-indicator episodes were detected. The low-rate vertical scan was missed. Horizontal scanning is outside the implemented rule families. Legitimate outage retries and stale/typo DNS bursts each caused an actionable alert. An explicit pre-replay authorization suppressed one scan finding while preserving its evidence.",
        "",
        f"The six held-out benign sources have **{summary['held_out_host_hours']:.2f} declared laboratory host-hours** and **{summary['benign_alerts']} actionable alerts**, yielding {rules['benign_exposure']['alerts_per_host_hour']:.1f} alerts/host-hour within these synthetic intervals. This tiny constructed exposure is not a production false-positive-rate estimate.",
        "",
        "## Optional ML experiment",
        "",
        "Isolation Forest uses 50 benign training windows, 30 development-validation windows and 60 held-out windows. Its strict cutoff is selected only from validation benign windows. Features do not contain labels, IP addresses or capture names. Missing denominators have explicit flags.",
        "",
        f"Exported JSON score parity error: {ml['artifact_score_parity_max_abs_error']:.3g}; artifact SHA-256: `{ml['artifact_sha256']}`.",
        "",
        "| Source-episode method | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, r in ml["source_episode_metrics"].items():
        lines.append(
            f"| {name} | {r['tp']} | {r['fp']} | {r['fn']} | {fmt(r['precision'])} | {fmt(r['recall'])} |"
        )
    lines += [
        "",
        "The generic source-episode comparison includes horizontal scanning, collapses indicator/other families from the same source/bucket, and applies the same explicit authorization policy. It differs from the per-family table. The model adds no new true positives; the union reproduces the rules results. **The model remains offline and is not enabled in the application.** A score is neither an attack probability nor a detector-family attribution.",
        "",
        "## Measured short load trials",
        "",
        "Real Kafka/PostgreSQL consumers, default rules, monitoring on; 480 synthetic events per trial, 40 events/s offered for 12 seconds, two repeats per configuration. The direct generator bypasses Go source replay and API admission. A two-second warm-up is excluded from latency samples; rate denominators include publication and drain.",
        "",
        "| Workers | Sources | Mean durable events/s incl. drain | Maximum observed p95 (s) |",
        "|---:|---:|---:|---:|",
    ]
    for r in trials:
        lines.append(
            f"| {r['workers']} | {r['sources']} | {r['mean_durable_events_per_s']:.2f} | {r['max_p95_durable_observation_s']:.3f} |"
        )
    target = summary["engineering_target"]
    lines += [
        "",
        f"The 500 events/s × 600 seconds engineering attempt {'completed' if target['completed'] else 'failed early'} after {target['actually_published_s']:.2f} seconds of publication. Reason: {target['early_stop_reason'] or 'none'}. **The ten-minute sustained-capacity target is not established.** See benchmark.json for acknowledged/persisted counts, the observed peak backlog (which can exceed the sampled stopping threshold), drain time and overloaded latency.",
        "",
        "Durable-observation latency is an upper bound measured by committed receipt polling and includes roughly 0.5 seconds of observer delay plus query scheduling. Database insertion clocks are lower bounds, not commit timestamps. No packet-capture availability or Go normalization throughput is inferred. Hardware/resource samples and full publication/backlog/drain curves are in benchmark.json.",
        "",
        "## Recovery and limits",
        "",
        "A loaded 480-event scan workload was repeated with a detector SIGKILL/restart. The persisted time/source/destination/port projection and alert metrics/evidence counts match the uninterrupted reference. Every acknowledged event was uniquely persisted. This supplements Phase 3 database/broker/rebalance tests; it does not demonstrate high availability or unlimited retention.",
        "",
        "UI visibility measurements are in docs/phase-4/browser.json. Short trial rates and tiny synthetic precision/recall fractions must not become broad production claims. Frozen data and original generator are included; Zeek-generated UIDs are frozen outputs, not guaranteed to repeat byte-for-byte when reprocessing PCAPs.",
        "",
        "Regenerate with the commands in docs/phase-4/README.md.",
    ]
    (REPORTS / "REPORT.md").write_text("\n".join(lines) + "\n")
    print(
        json.dumps(
            {
                "status": "passed",
                "summary_source_reports": source_hashes,
                "short_configurations": len(trials),
            }
        )
    )


if __name__ == "__main__":
    main()
