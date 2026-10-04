"""Validation-only threshold selection, with an explicit episode FP budget."""


def choose_threshold(scores, identities, truth, excluded):
    tradeoff = []
    for cutoff in sorted(set(map(float, scores)) | {1.0}):
        predicted = {key for key, s in zip(identities, scores) if s > cutoff} - excluded
        tp = len(predicted & truth)
        fp = len(predicted - truth)
        fn = len(truth - predicted)
        m = dict(
            tp=tp,
            fp=fp,
            fn=fn,
            precision=tp / (tp + fp) if tp + fp else None,
            recall=tp / (tp + fn) if tp + fn else None,
        )
        denominator = 2 * m["tp"] + m["fp"] + m["fn"]
        tradeoff.append(
            dict(
                threshold=cutoff,
                **m,
                f1=2 * m["tp"] / denominator if denominator else 0
            )
        )
    eligible = [m for m in tradeoff if m["fp"] <= 1]
    chosen = max(eligible, key=lambda m: (m["f1"], -m["fp"], m["threshold"]))
    return chosen, tradeoff
