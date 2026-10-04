"""Render concise results directly from the frozen experiment's JSON report."""

import json
from prepare_ml_v2 import EXPERIMENT


def main():
    report = json.loads((EXPERIMENT / "report.json").read_text())
    lines = [
        "# ML v2 results",
        "",
        "Result: no demonstrated held-out incremental coverage from either retrained model. ML remains offline.",
        "",
        f"{report['captures']} fresh synthetic captures; {report['events']:,} canonical events; 200 benign training windows, 100 validation windows and 110 held-out windows. Source addresses are disjoint across splits. V1 files are preserved.",
        "",
        "| Detector on the same v2 held-out source episodes | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    def row(name, m):
        percent = lambda v: "undefined" if v is None else f"{100*v:.1f}%"
        lines.append(
            f"| {name} | {m['tp']} | {m['fp']} | {m['fn']} | {percent(m['precision'])} | {percent(m['recall'])} |"
        )

    row(
        "Production rules",
        report["models"]["temporal-v2"]["source_episode_metrics"]["rules"],
    )
    for name, m in report["models"].items():
        row(name, m["source_episode_metrics"]["ml"])
        row("Rules + " + name, m["source_episode_metrics"]["combined"])
    lines += [
        "",
        "These are five-minute source episodes, not per-family detections or production accuracy. Authorized scanning is policy-excluded. There are 11 suspicious source episodes; the indicator capture contains two rule-family labels but is one source episode.",
        "",
        "## Validation threshold tradeoff",
        "",
        "| Model | Allowed benign false-positive captures | Threshold | Validation TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name in ("retrained-baseline", "temporal-v2"):
        model = report["models"][name]
        for budget in (1, 2, 4):
            chosen = max(
                (r for r in model["validation_tradeoff"] if r["fp"] <= budget),
                key=lambda r: (r["f1"], -r["fp"], r["threshold"]),
            )
            lines.append(
                f"| {name} | {budget} | {chosen['threshold']:.6f} | {chosen['tp']} | {chosen['fp']} | {chosen['fn']} |"
            )
    lines += [
        "",
        "Only the predeclared budget of one benign false-positive capture was selected. Other rows summarize validation scores; they were not chosen or tested as alternative held-out thresholds. The baseline selected the no-alert cutoff. The temporal model caught one of ten validation episodes at its selected cutoff, then none of eleven held-out episodes. Lowering the cutoff after seeing holdout would invalidate this experiment.",
        "",
        "## What changed, and why it still failed",
        "",
        "- Training increased from 50 to 200 minute windows; empty training windows decreased from 18 to zero. Normal traffic now includes multiple services/destinations, rejected connections, maintenance outages, busy DNS and stale DNS.",
        "- The retrained models actually split on failure ratio (unlike v1). The temporal model also uses causal three-minute port/destination diversity, failure count, five-second burst count, and interarrival mean/variation. JSON scoring matches sklearn within floating-point tolerance.",
        "- Benign outages and denied connections, and stale DNS and malicious NXDOMAIN bursts, deliberately overlap statistically. These telemetry features cannot reliably determine authorization or intent.",
        "- The temporal validation curve improves if two benign false-positive captures are allowed, but that violates the selected budget. Its conservative selected cutoff did not transfer to the fresh held-out cases.",
        "- Normal training still covers a narrow synthetic range (three-minute TCP ports 3–4, destinations 2–4). Tree thresholds are learned within that range; an unseen count of 20 does not automatically imply a calibrated attack score. More features alone did not establish usable separation.",
        "- The original v1 artifact finds one additional held-out slow-scan episode on this new corpus, while adding two new benign false-positive episodes. This is a different corpus from v1, and does not rewrite the original v1 result.",
        "",
        "## Decision",
        "",
        report["recommendation"],
        "",
        "A next experiment should use independently sourced, license-reviewed network telemetry and labeled development examples, and compare a supervised classifier or context-aware detector against rules. Include benign network discovery and explicit authorization context. Freeze a third protocol and reserve a genuinely new test split; this v2 holdout is now consumed. Do not claim that those changes will necessarily improve detection.",
        "",
        "See [protocol](PROTOCOL.md), [full model scores and diagnostics](report.json), [production rule results](rules.json), and [scikit-learn's anomaly-detection documentation](https://scikit-learn.org/1.9/modules/outlier_detection.html). Scores are not probabilities or attack-family classifications.",
        "",
    ]
    (EXPERIMENT / "REPORT.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
