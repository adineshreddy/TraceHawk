"""Matching contracts and feature semantics; not detector implementation copies."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "evaluation"))
from evaluation_common import match_episodes
from features import extract


def test_matching_maximum_not_greedy():
    base = {
        "detector_id": "dns_nxdomain_burst",
        "source_ip": "192.0.2.1",
        "destination_ip": None,
    }
    labels = [
        base | {"start_us": 0, "end_us": 20},
        base | {"start_us": 30, "end_us": 40},
    ]
    predictions = [
        base | {"first_event_time_us": 10, "last_event_time_us": 35},
        base | {"first_event_time_us": 0, "last_event_time_us": 5},
    ]
    r = match_episodes(predictions, labels, tolerance=0)
    assert (r["tp"], r["fp"], r["fn"]) == (2, 0, 0)
    assert match_episodes(predictions + [predictions[0]], labels, 0)["fp"] == 1


def test_matching_identity_time_and_undefined_precision():
    label = {
        "detector_id": "known_indicator",
        "source_ip": "192.0.2.1",
        "destination_ip": None,
        "start_us": 100,
        "end_us": 200,
    }
    wrong = {
        "detector_id": "known_indicator",
        "source_ip": "192.0.2.2",
        "destination_ip": None,
        "first_event_time_us": 100,
        "last_event_time_us": 200,
    }
    assert match_episodes([wrong], [label], 0)["tp"] == 0
    assert match_episodes([], [])["precision"] is None


def test_missing_ratios_and_half_open_feature_windows():
    e = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "destination_port": 443,
        "event_time_us": 60000000,
        "event_kind": "connection",
        "protocol": "tcp",
        "connection": {"state": None, "orig_bytes": None},
    }
    rows = extract(
        [e],
        {
            "source_ip": "192.0.2.1",
            "scenario_id": "test",
            "time_start_us": 0,
            "time_end_us": 120000000,
        },
    )
    assert rows[0]["values"] == [0, 0, 0, 0, 0, 0, 0, 1, 1]
    assert rows[1]["values"] == [1, 1, 0, 0, 0, 0, 0, 1, 1]
