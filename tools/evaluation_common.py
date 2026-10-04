"""Episode matching and routing independent from ground-truth selection."""

import json


def partition(scope, ip):
    data = json.dumps([scope, ip], separators=(",", ":")).encode()
    h = 0x9747B28C ^ len(data)
    m = 0x5BD1E995
    while len(data) >= 4:
        k = int.from_bytes(data[:4], "little")
        k = k * m & 0xFFFFFFFF
        k ^= k >> 24
        k = k * m & 0xFFFFFFFF
        h = (h * m & 0xFFFFFFFF) ^ k
        data = data[4:]
    if data:
        h ^= int.from_bytes(data, "little")
        h = h * m & 0xFFFFFFFF
    h ^= h >> 13
    h = h * m & 0xFFFFFFFF
    h ^= h >> 15
    return (h & 0x7FFFFFFF) % 3


def match_episodes(predictions, truth, tolerance=10000000):
    """Maximum bipartite matching; never greedily reuse a labeled episode."""
    edges = {
        i: [
            j
            for j, t in enumerate(truth)
            if all(p[k] == t[k] for k in ("detector_id", "source_ip", "destination_ip"))
            and p["first_event_time_us"] <= t["end_us"] + tolerance
            and p["last_event_time_us"] >= t["start_us"] - tolerance
        ]
        for i, p in enumerate(predictions)
    }
    matched = {}

    def assign(i, seen):
        for j in edges[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in matched or assign(matched[j], seen):
                matched[j] = i
                return True
        return False

    for i in range(len(predictions)):
        assign(i, set())
    tp = len(matched)
    fp = len(predictions) - tp
    fn = len(truth) - tp
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_indices": [
            i for i in range(len(predictions)) if i not in matched.values()
        ],
        "missed_truth_indices": [j for j in range(len(truth)) if j not in matched],
    }
