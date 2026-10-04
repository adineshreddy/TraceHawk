"""Read-only checks for local TraceHawk readiness, including worker freshness."""

from pathlib import Path
import subprocess, urllib.request, json

ROOT = Path(__file__).resolve().parents[1]


def main():
    assert (ROOT / ".env").exists(), "Run tools/setup_dev.py"
    subprocess.run(["docker", "compose", "ps"], cwd=ROOT, check=True)
    with urllib.request.urlopen(
        "http://127.0.0.1:3100/health/live", timeout=5
    ) as response:
        assert response.status == 200
    with urllib.request.urlopen(
        "http://127.0.0.1:3101/api/health", timeout=5
    ) as response:
        assert json.load(response)["database"] == "ok"
    result = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "import json; from tracehawk.core import db; from tracehawk.operations import snapshot; c=db(); state=snapshot(c); print(json.dumps(state)); assert state['status']=='ready'",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout.strip())
    print(
        "Console and workers ready: http://127.0.0.1:3100. Grafana ready: http://127.0.0.1:3101. Kafka, PostgreSQL and Prometheus have no public ports."
    )


if __name__ == "__main__":
    main()
