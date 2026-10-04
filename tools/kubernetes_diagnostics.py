"""Bounded local cluster diagnostics; never request Secret contents."""

import subprocess
from kubernetes import KUBECONFIG, ROOT, owned

if __name__ == "__main__" and owned():
    commands = [
        ["get", "pods", "-A", "-o", "wide"],
        ["-n", "tracehawk", "get", "events", "--sort-by=.metadata.creationTimestamp"],
        ["-n", "tracehawk", "describe", "pods"],
        ["-n", "tracehawk", "logs", "statefulset/kafka", "--tail=80"],
        ["-n", "tracehawk", "logs", "statefulset/postgres", "--tail=40"],
        ["-n", "tracehawk", "logs", "job/topics", "--tail=40"],
    ]
    for args in commands:
        print("Diagnostic:", " ".join(args), flush=True)
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(KUBECONFIG), *args],
            cwd=ROOT,
            check=False,
            timeout=20,
            capture_output=True,
            text=True,
        )
        print((result.stdout + result.stderr)[-40000:], flush=True)
