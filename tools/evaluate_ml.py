"""Offline Isolation Forest experiment; verified JSON artifact, no pickle load."""

from pathlib import Path
import hashlib, json, math, sys
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation"))
from features import FEATURES, extract
from prepare_evaluation import verify


def average_path(n):
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2 * (math.log(n - 1) + np.euler_gamma) - 2 * (n - 1) / n


def score_json(artifact, x):
    x = np.asarray(x, dtype=np.float32)
    depths = []
    for tree in artifact["trees"]:
        node = 0
        depth = 0
        while tree["left"][node] != -1:
            node = (
                tree["left"][node]
                if x[tree["feature"][node]] <= tree["threshold"][node]
                else tree["right"][node]
            )
            depth += 1
        depths.append(depth + average_path(tree["samples"][node]))
    return float(
        2 ** (-sum(depths) / (len(depths) * average_path(artifact["max_samples"])))
    )


def metrics(pred, truth):
    tp = len(pred & truth)
    fp = len(pred - truth)
    fn = len(truth - pred)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def main():
    freeze = verify()
    rows = []
    manifests = {}
    labels = {}
    for name in freeze["captures"]:
        m = json.loads(
            (ROOT / "evaluation/corpus" / name / "manifest.json").read_text()
        )
        manifests[name] = m
        labels[name] = json.loads(
            (ROOT / "evaluation/corpus" / name / "labels.json").read_text()
        )
        e = [
            json.loads(s)
            for s in (ROOT / "tmp/evaluation" / (name + ".jsonl"))
            .read_text()
            .splitlines()
        ]
        rows.extend(extract(e, m))
    train = [r for r in rows if manifests[r["capture"]]["split"] == "development-train"]
    val = [
        r for r in rows if manifests[r["capture"]]["split"] == "development-validation"
    ]
    held = [r for r in rows if manifests[r["capture"]]["split"] == "held-out"]
    assert all(not labels[r["capture"]]["episodes"] for r in train)
    assert (
        len(
            {manifests[r["capture"]]["source_ip"] for r in train}
            & {manifests[r["capture"]]["source_ip"] for r in val + held}
        )
        == 0
    )
    x = np.array([r["values"] for r in train], dtype=np.float32)
    # Isolation Forest does not require scaling; avoid preprocessing fitted on held-out data.
    model = IsolationForest(
        n_estimators=128,
        max_samples=min(64, len(x)),
        contamination="auto",
        random_state=41,
        n_jobs=1,
    ).fit(x)
    scores = -model.score_samples(
        np.asarray([r["values"] for r in val], dtype=np.float32)
    )
    benign_scores = [
        s for r, s in zip(val, scores) if not labels[r["capture"]]["episodes"]
    ]
    cutoff = float(max(benign_scores))
    artifact = {
        "schema_version": "1.0",
        "algorithm": "isolation_forest",
        "seed": 41,
        "features": FEATURES,
        "preprocessing": "none; input converted to float32",
        "max_samples": int(model.max_samples_),
        "threshold": cutoff,
        "threshold_comparison": "strict greater than",
        "training_split": "development-train benign captures only",
        "training_captures": [
            n for n, m in manifests.items() if m["split"] == "development-train"
        ],
        "training_matrix_sha256": hashlib.sha256(x.tobytes()).hexdigest(),
        "corpus_freeze_sha256": hashlib.sha256(
            (ROOT / "evaluation/corpus/freeze.json").read_bytes()
        ).hexdigest(),
        "protocol_sha256": freeze["protocol_sha256"],
        "sklearn_version": sklearn.__version__,
        "trees": [],
    }
    for estimator in model.estimators_:
        t = estimator.tree_
        artifact["trees"].append(
            {
                "left": t.children_left.tolist(),
                "right": t.children_right.tolist(),
                "feature": t.feature.tolist(),
                "threshold": t.threshold.tolist(),
                "samples": t.n_node_samples.tolist(),
            }
        )
    modelpath = ROOT / "evaluation/model/isolation-forest-v1.json"
    modelpath.write_text(json.dumps(artifact, separators=(",", ":")) + "\n")
    sha = hashlib.sha256(modelpath.read_bytes()).hexdigest()
    (ROOT / "evaluation/model/manifest.json").write_text(
        json.dumps(
            {
                "artifact": modelpath.name,
                "sha256": sha,
                "state": "offline experimental; not loaded by runtime detectors",
            },
            indent=2,
        )
        + "\n"
    )
    loaded = json.loads(modelpath.read_text())
    assert hashlib.sha256(modelpath.read_bytes()).hexdigest() == sha
    allrows = train + val + held
    expected = -model.score_samples(
        np.asarray([r["values"] for r in allrows], dtype=np.float32)
    )
    actual = np.asarray([score_json(loaded, r["values"]) for r in allrows])
    assert np.allclose(expected, actual, atol=1e-10, rtol=1e-8), float(
        np.max(np.abs(expected - actual))
    )
    held_scores = [score_json(loaded, r["values"]) for r in held]
    source_id = lambda r: (r["capture"], r["source_ip"], r["bucket_start_us"])
    excluded = {
        (
            name,
            p["source_ip"],
            manifests[name]["time_start_us"] // 300000000 * 300000000,
        )
        for name, label in labels.items()
        for p in label["policies"]
    }
    ml = {source_id(r) for r, s in zip(held, held_scores) if s > cutoff} - excluded
    truth = set()
    for name, label in labels.items():
        if manifests[name]["split"] != "held-out":
            continue
        for e in label["episodes"]:
            for bucket in range(
                e["start_us"] // 300000000 * 300000000,
                e["end_us"] // 300000000 * 300000000 + 1,
                300000000,
            ):
                truth.add((name, e["source_ip"], bucket))
    rule_report = json.loads((ROOT / "evaluation/reports/rules.json").read_text())
    rules = set()
    for capture in rule_report["captures"]:
        if capture["split"] != "held-out":
            continue
        for a in capture["predictions"]:
            rules.add(
                (
                    capture["capture"],
                    a["source_ip"],
                    a["first_event_time_us"] // 300000000 * 300000000,
                )
            )
    combined = rules | ml
    results = {
        "rules": metrics(rules, truth),
        "ml": metrics(ml, truth),
        "combined": metrics(combined, truth),
    }
    useful = (len(truth - rules) > len(truth - combined)) and len(
        combined - truth
    ) <= len(rules - truth)
    output = {
        "status": "passed",
        "artifact_sha256": sha,
        "artifact_score_parity_max_abs_error": float(np.max(np.abs(expected - actual))),
        "train_windows": len(train),
        "validation_windows": len(val),
        "held_out_windows": len(held),
        "threshold": cutoff,
        "validation_benign_window_false_positives": int(
            sum(
                s > cutoff
                for r, s in zip(val, scores)
                if not labels[r["capture"]]["episodes"]
            )
        ),
        "source_episode_metrics": results,
        "new_true_positive_captures": sorted({r[0] for r in (ml & truth) - rules}),
        "new_false_positive_captures": sorted({r[0] for r in ml - truth - rules}),
        "missed_captures": {
            k: sorted({r[0] for r in truth - p})
            for k, p in [("rules", rules), ("ml", ml), ("combined", combined)]
        },
        "recommendation": (
            "keep offline; insufficient representative evidence for production promotion"
            if not useful
            else "synthetic incremental coverage observed; keep opt-in pending representative validation"
        ),
        "default_enabled": False,
        "features": FEATURES,
        "held_out_scores": [
            r
            | {
                "score": s,
                "flagged": s > cutoff,
                "policy_excluded": source_id(r) in excluded,
            }
            for r, s in zip(held, held_scores)
        ],
        "scope": "Generic suspicious-source episodes, including unsupported horizontal scan. Anomaly scores are not probabilities or family attribution.",
    }
    (ROOT / "evaluation/reports/ml.json").write_text(
        json.dumps(output, indent=2) + "\n"
    )
    print(
        json.dumps(
            {k: v for k, v in output.items() if k != "held_out_scores"}, indent=2
        )
    )


if __name__ == "__main__":
    main()
