"""Causal trailing history; never include future events or identity in X."""

import math
from features import FEATURES as BASE_FEATURES, extract as base_extract, STEP

FEATURES = BASE_FEATURES + [
    "tcp_ports_180s",
    "destinations_180s",
    "failed_tcp_180s",
    "max_connections_5s_180s",
    "mean_tcp_gap_seconds_180s",
    "tcp_gap_cv_180s",
]


def extract(events, manifest):
    output = base_extract(events, manifest)
    tcp = [
        e
        for e in events
        if e["source_ip"] == manifest["source_ip"]
        and e["event_kind"] == "connection"
        and e["protocol"] == "tcp"
    ]
    for row in output:
        end = row["window_start_us"] + STEP
        history = [e for e in tcp if end - 3 * STEP <= e["event_time_us"] < end]
        times = sorted(e["event_time_us"] for e in history)
        gaps = [(b - a) / 1e6 for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps) if gaps else 0
        cv = (
            math.sqrt(sum((v - mean) ** 2 for v in gaps) / len(gaps)) / mean
            if mean
            else 0
        )
        bins = {}
        for t in times:
            key = t // 5000000
            bins[key] = bins.get(key, 0) + 1
        row["values"] += [
            len({e["destination_port"] for e in history}),
            len({e["destination_ip"] for e in history}),
            sum(e["connection"]["state"] in ("S0", "REJ") for e in history),
            max(bins.values(), default=0),
            mean,
            cv,
        ]
    return output
