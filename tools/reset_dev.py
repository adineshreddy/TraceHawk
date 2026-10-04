"""Explicitly reset only this named Compose project's data; preserve credentials."""

from pathlib import Path
import argparse, subprocess

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--confirm-tracehawk-data-reset", action="store_true")
a = p.parse_args()
if not a.confirm_tracehawk_data_reset:
    raise SystemExit(
        "Reset deletes TraceHawk local replay/alert data. Pass --confirm-tracehawk-data-reset explicitly."
    )
subprocess.run(
    [
        "docker",
        "compose",
        "--project-name",
        "tracehawk",
        "down",
        "--volumes",
        "--remove-orphans",
    ],
    cwd=ROOT,
    check=True,
)
