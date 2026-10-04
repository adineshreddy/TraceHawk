"""Frozen v2 ablation with validation-only cutoff and safe JSON artifacts."""

from pathlib import Path
import hashlib, json, sys
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from prepare_ml_v2 import verify_prepared, ROOT, CORPUS, EXPERIMENT, OUTPUT
from evaluate_ml import score_json, metrics

sys.path.insert(0, str(ROOT / "evaluation"))
import features, features_v2


from ml_selection import choose_threshold


def export(model, fields, cutoff, train, x, freeze):
    artifact = dict(
        schema_version="2.0",
        algorithm="isolation_forest",
        seed=41,
        features=fields,
        preprocessing="none; input converted to float32",
        max_samples=int(model.max_samples_),
        threshold=cutoff,
        threshold_comparison="strict greater than",
        sklearn_version=sklearn.__version__,
        training_captures=sorted({r["capture"] for r in train}),
        training_matrix_sha256=hashlib.sha256(x.tobytes()).hexdigest(),
        corpus_freeze_sha256=hashlib.sha256(
            (EXPERIMENT / "freeze.json").read_bytes()
        ).hexdigest(),
        protocol_sha256=freeze["protocol_sha256"],
        trees=[],
    )
    for estimator in model.estimators_:
        t = estimator.tree_
        artifact["trees"].append(
            dict(
                left=t.children_left.tolist(),
                right=t.children_right.tolist(),
                feature=t.feature.tolist(),
                threshold=t.threshold.tolist(),
                samples=t.n_node_samples.tolist(),
            )
        )
    return artifact


def main():
    freeze = verify_prepared()
    manifests = {
        n: json.loads((CORPUS / n / "manifest.json").read_text())
        for n in freeze["captures"]
    }
    labels = {
        n: json.loads((CORPUS / n / "labels.json").read_text())
        for n in freeze["captures"]
    }
    events = {
        n: [json.loads(s) for s in (OUTPUT / (n + ".jsonl")).read_text().splitlines()]
        for n in freeze["captures"]
    }
    sources = {
        split: {m["source_ip"] for m in manifests.values() if m["split"] == split}
        for split in ("development-train", "development-validation", "held-out")
    }
    assert all(not sources[a] & sources[b] for a in sources for b in sources if a != b)
    assert len(set().union(*sources.values())) == len(manifests)
    assert all(
        not labels[n]["episodes"]
        for n, m in manifests.items()
        if m["split"] == "development-train"
    )
    key = lambda r: (r["capture"], r["source_ip"], r["bucket_start_us"])
    truth = {split: set() for split in sources}
    excluded = set()
    for name, m in manifests.items():
        identity = (name, m["source_ip"], m["time_start_us"] // 300000000 * 300000000)
        if labels[name]["episodes"]:
            truth[m["split"]].add(identity)
        if labels[name]["policies"]:
            excluded.add(identity)
    rules = set()
    rule_report = json.loads((EXPERIMENT / "rules.json").read_text())
    for capture in rule_report["captures"]:
        if capture["split"] == "held-out":
            for a in capture["predictions"]:
                rules.add(
                    (
                        capture["capture"],
                        a["source_ip"],
                        a["first_event_time_us"] // 300000000 * 300000000,
                    )
                )
    rules -= excluded
    outputs = {}
    for modelname, module in [
        ("original-v1", features),
        ("retrained-baseline", features),
        ("temporal-v2", features_v2),
    ]:
        rows = [
            r for name, m in manifests.items() for r in module.extract(events[name], m)
        ]
        splits = {
            s: [r for r in rows if manifests[r["capture"]]["split"] == s]
            for s in sources
        }
        train, val, held = (splits[s] for s in sources)
        x = np.asarray([r["values"] for r in train], dtype=np.float32)
        allx = np.asarray([r["values"] for r in rows], dtype=np.float32)
        if modelname == "original-v1":
            artifact = json.loads(
                (ROOT / "evaluation/model/isolation-forest-v1.json").read_text()
            )
            scores = np.asarray([score_json(artifact, r["values"]) for r in rows])
            chosen = dict(
                threshold=artifact["threshold"],
                selection="unchanged v1 validation cutoff",
            )
            tradeoff = []
            parity = None
        else:
            model = IsolationForest(
                n_estimators=128,
                max_samples=min(256, len(x)),
                contamination="auto",
                random_state=41,
                n_jobs=1,
            ).fit(x)
            # Threshold is fixed here before any held-out scoring.
            valscores = -model.score_samples(
                np.asarray([r["values"] for r in val], dtype=np.float32)
            )
            chosen, tradeoff = choose_threshold(
                valscores,
                [key(r) for r in val],
                truth["development-validation"],
                excluded,
            )
            artifact = export(
                model, module.FEATURES, chosen["threshold"], train, x, freeze
            )
            path = EXPERIMENT / (modelname + ".json")
            path.write_text(json.dumps(artifact, separators=(",", ":")) + "\n")
            artifact = json.loads(path.read_text())
            expected = -model.score_samples(allx)
            scores = np.asarray([score_json(artifact, r["values"]) for r in rows])
            parity = float(np.max(np.abs(expected - scores)))
            assert np.allclose(expected, scores, atol=1e-10, rtol=1e-8)
        scoremap = {
            (r["capture"], r["window_start_us"]): float(s) for r, s in zip(rows, scores)
        }
        cutoff = chosen["threshold"]
        predicted = {
            key(r)
            for r in held
            if scoremap[(r["capture"], r["window_start_us"])] > cutoff
        } - excluded
        combined = rules | predicted
        actual = truth["held-out"] - excluded
        decisions = []
        window_truth, window_pred = set(), set()
        for r in held:
            windowkey = (r["capture"], r["window_start_us"])
            policy = key(r) in excluded
            suspicious = any(
                e["start_us"] < r["window_start_us"] + 60000000
                and e["end_us"] >= r["window_start_us"]
                for e in labels[r["capture"]]["episodes"]
            )
            score = scoremap[windowkey]
            if suspicious and not policy:
                window_truth.add(windowkey)
            if score > cutoff and not policy:
                window_pred.add(windowkey)
            decisions.append(
                r
                | dict(
                    score=score,
                    flagged=score > cutoff,
                    policy_excluded=policy,
                    truth_window=suspicious,
                )
            )
        split_counts = {
            f: sum(tree["feature"].count(i) for tree in artifact["trees"])
            for i, f in enumerate(module.FEATURES)
        }
        outputs[modelname] = dict(
            threshold_selection=chosen,
            validation_tradeoff=tradeoff,
            artifact_sha256=hashlib.sha256(
                (
                    ROOT / "evaluation/model/isolation-forest-v1.json"
                    if modelname == "original-v1"
                    else EXPERIMENT / (modelname + ".json")
                ).read_bytes()
            ).hexdigest(),
            artifact_score_parity_max_abs_error=parity,
            train_windows=50 if modelname == "original-v1" else len(train),
            validation_windows=len(val),
            held_out_windows=len(held),
            training_empty_windows=(
                18
                if modelname == "original-v1"
                else sum(r["values"][0] == 0 and r["values"][4] == 0 for r in train)
            ),
            training_feature_ranges=(
                None
                if modelname == "original-v1"
                else {
                    f: [float(x[:, i].min()), float(x[:, i].max())]
                    for i, f in enumerate(module.FEATURES)
                }
            ),
            tree_feature_split_counts=split_counts,
            held_out_window_metrics=metrics(window_pred, window_truth),
            source_episode_metrics={
                "rules": metrics(rules, actual),
                "ml": metrics(predicted, actual),
                "combined": metrics(combined, actual),
            },
            new_true_positive_captures=sorted(
                k[0] for k in (predicted & actual) - rules
            ),
            new_false_positive_captures=sorted(
                k[0] for k in predicted - actual - rules
            ),
            missed_captures=sorted(k[0] for k in actual - predicted),
            false_positive_captures=sorted(k[0] for k in predicted - actual),
            held_out_scores=decisions,
        )
    report = dict(
        status="passed",
        default_enabled=False,
        corpus_version=freeze["version"],
        captures=len(manifests),
        events=sum(len(e) for e in events.values()),
        models=outputs,
        source_sha256={
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [
                Path(__file__),
                ROOT / "evaluation/features.py",
                ROOT / "evaluation/features_v2.py",
                ROOT / "evaluation/ml_selection.py",
                ROOT / "tools/prepare_ml_v2.py",
                ROOT / "tools/evaluate_rules_container.py",
                EXPERIMENT / "freeze.json",
            ]
        },
        recommendation="Keep offline. Synthetic ablation only; representative external validation is required before runtime promotion.",
        limitations=[
            "Authored synthetic inputs; shared generator families across splits; v1 failures informed v2 design.",
            "Outage/denied and stale-DNS/attack contexts intentionally overlap statistically; intent is not observable from these features.",
            "Fictional indicator identity remains a rule responsibility; scores do not imply severity or attack family.",
            "Threshold permits one validation false-positive capture, not a production false-positive guarantee.",
        ],
    )
    (EXPERIMENT / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: {
                    "metrics": v["source_episode_metrics"],
                    "new_tp": v["new_true_positive_captures"],
                    "new_fp": v["new_false_positive_captures"],
                }
                for k, v in outputs.items()
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
