# Demo and portfolio release

Start from the repository root:

```sh
python3 tools/demo.py
```

Prerequisites: Docker Engine/Desktop with Compose v2, a running daemon, Python 3.10+ for the standard-library setup scripts, available loopback ports 3100/3101, and internet access for the first image/build download. Local testing used macOS ARM64 with a Docker VM assigned approximately 7.75 GiB RAM. The stack has explicit per-service limits; allocate roughly 4 GiB available Docker memory for the demo. Do not run the dedicated Kubernetes demo alongside Compose on a constrained laptop.

Open http://127.0.0.1:3100 and sign in as `operator` using the generated password in private `tmp/credentials.json`. The startup command preserves credentials and existing data. For a fresh demonstration, start a new replay from the Replay page; each run has isolated source/window state.

1. Choose **Controlled scan + DNS traffic**, **phase2-rules-v1**, and **10×**. Start replay and wait for **completed**. Expect **108 events and six actionable alerts**.
2. Open Alerts, select `dns_nxdomain_burst`, then open the finding. Expect **40 supporting events**, matching windows and timeline. Enter a reason and acknowledge the finding; follow source `192.0.2.30` to the host timeline.
3. Start a fresh controlled replay with **Authorize the lab scanner** checked. Expect **five actionable alerts and one suppressed finding**. Filter suppressed findings and inspect the scan: **24 supporting connections remain**.
4. Run **Benign network baseline** under the same rule snapshot. Expect **17 events and zero alerts**.
5. Open Operations for the two workers and partition checkpoints. Grafana is http://127.0.0.1:3101/d/tracehawk-operations with the same initial operator password. Open Evaluation for documented misses, false positives and the failed load target.

[Five-minute narration script](demo-script.md) · [Implemented architecture](architecture.md) · [Project resume bullets](resume-bullets.md) · [Recorded screen walkthrough](tracehawk-demo.webm) · [Two consecutive rehearsal results](rehearsals.json)

The video is silent and captured from real running services; authentication occurs before recording. It is a compact screen walkthrough, with a separate five-minute narration script. It does not demonstrate live packet capture or cloud deployment. The UI Evaluation page displays the frozen v1 evaluation; the [separate ML v2 report](../../evaluation/experiments/ml-v2/REPORT.md) documents the follow-up experiment.

To stop the local demo without deleting data:

```sh
docker compose --project-name tracehawk down
```

For an intentional complete laboratory data reset, the existing helper deletes only this named Compose project's volumes and preserves credentials:

```sh
python3 tools/reset_dev.py --confirm-tracehawk-data-reset
python3 tools/demo.py
```

Do not use a reset during an investigation you want to retain. Compose reset does not delete the separately retained Kubernetes data. [Kubernetes runbook](../phase-5/README.md) covers that deployment's lifecycle and limits. [Operations/recovery guide](../phase-3/README.md) covers readiness, quarantine, outbox behavior and outages. For browser rehearsals, install console dependencies with `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm --prefix services/console ci --ignore-scripts`, then run `tools/verify_browser.sh phase6` against the healthy stack. The automated rehearsal starts fresh scopes and writes screenshots, evidence and a recording; it does not erase database history.
