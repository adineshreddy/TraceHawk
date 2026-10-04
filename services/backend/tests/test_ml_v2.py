"""Causality, identity exclusion and validation cutoff safety contracts."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "evaluation"))
from features_v2 import extract, FEATURES
from ml_selection import choose_threshold


def event(time, port, src="192.0.2.1"):
    return dict(
        source_ip=src,
        destination_ip="198.51.100.1",
        destination_port=port,
        event_time_us=time,
        event_kind="connection",
        protocol="tcp",
        connection=dict(state="REJ", orig_bytes=0),
    )


def test_temporal_history_is_causal_and_expires():
    m = dict(
        source_ip="192.0.2.1", scenario_id="a", time_start_us=0, time_end_us=300000000
    )
    before = extract([event(59000000, 443)], m)
    after = extract(
        [event(59000000, 443), event(60000000, 22), event(240000000, 80)], m
    )
    assert after[0]["values"] == before[0]["values"]
    assert after[1]["values"][FEATURES.index("tcp_ports_180s")] == 2
    assert after[3]["values"][FEATURES.index("tcp_ports_180s")] == 1
    assert after[4]["values"][FEATURES.index("tcp_ports_180s")] == 1
    # Renaming identity changes metadata, never numerical features.
    renamed = extract(
        [event(59000000, 443, "203.0.113.9")],
        m | dict(source_ip="203.0.113.9", scenario_id="b"),
    )
    assert [r["values"] for r in renamed] == [r["values"] for r in before]


def test_threshold_false_positive_budget_and_no_alert_candidate():
    keys = [("attack",), ("benign1",), ("benign2",)]
    chosen, tradeoff = choose_threshold([0.9, 0.8, 0.7], keys, {keys[0]}, set())
    assert chosen["threshold"] == 0.8 and chosen["tp"] == 1 and chosen["fp"] == 0
    assert any(r["threshold"] == 1.0 and r["tp"] == 0 for r in tradeoff)
    chosen, _ = choose_threshold([0.5, 0.9, 0.8], keys, {keys[0]}, set())
    assert chosen["fp"] <= 1
    assert chosen["threshold"] == 1.0  # Cannot reach attack within FP budget.
    chosen, _ = choose_threshold([0.9, 0.99, 0.7], keys, {keys[0]}, {keys[1]})
    assert chosen["fp"] == 0 and chosen["tp"] == 1
