"""Browser rehearsal via a temporary loopback-only Kubernetes forward."""

import subprocess, platform
from verify_kubernetes import Forward, ROOT

with Forward():
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *(
                ["--network", "host", "-e", "DIRECT_KUBERNETES_FORWARD=1"]
                if platform.system() == "Linux"
                else ["--add-host", "host.docker.internal:host-gateway"]
            ),
            "--ipc=host",
            "--memory=768m",
            "-v",
            str(ROOT) + ":/workspace",
            "-w",
            "/workspace/services/console",
            "mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27",
            "node",
            "e2e-phase5.cjs",
        ],
        cwd=ROOT,
        check=True,
    )
