"""One-command non-destructive local demo startup with readiness checks."""

from pathlib import Path
import subprocess, sys

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    for args in (
        [sys.executable, "tools/setup_dev.py"],
        ["docker", "compose", "up", "-d", "--build", "--wait", "--wait-timeout", "180"],
        [sys.executable, "tools/doctor.py"],
    ):
        subprocess.run(args, cwd=ROOT, check=True)
    print(
        "Demo ready. Open http://127.0.0.1:3100; operator password is in private tmp/credentials.json."
    )
