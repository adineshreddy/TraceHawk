from tracehawk.detector import window_end, STEP
from tracehawk.core import password_hash, password_ok, digest


def test_cadence():
    assert window_end(STEP) == 2 * STEP
    assert window_end(STEP - 1) == STEP


def test_passwords():
    hashed = password_hash("local-test-only")
    assert password_ok("local-test-only", hashed)
    assert not password_ok("wrong", hashed)
    assert hashed != password_hash("local-test-only")


def test_identity_scope():
    assert digest(["a", "b"]) != digest(["b", "a"])


def test_event_contract_semantics():
    import copy, json
    from tracehawk.core import ROOT, validate_event

    e = json.loads(
        (ROOT / "scenarios/phase0/normalized-events.jsonl").read_text().splitlines()[0]
    )
    meta = json.loads((ROOT / "scenarios/phase0/manifest.json").read_text())
    run = {
        "scope_id": e["scope_id"],
        "run_id": e["run_id"],
        "scenario_id": e["provenance"]["capture_id"],
        "metadata": {
            "log_hashes": {"conn": e["provenance"]["source_generation_id"]},
            "time_start_us": meta["time_start_us"],
            "time_end_us": meta["time_end_us"],
        },
    }
    validate_event(e, run)
    import pytest

    for field, value in [
        ("event_time_us", e["event_time_us"] + 1),
        ("scope_id", "wrong"),
        ("event_id", "f" * 64),
        ("published_at_us", 0),
    ]:
        bad = copy.deepcopy(e)
        bad[field] = value
        with pytest.raises(ValueError):
            validate_event(bad, run)
