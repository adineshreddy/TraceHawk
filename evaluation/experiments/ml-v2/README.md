# Reproduce the second ML experiment

This experiment is complete. Read [results](REPORT.md) for the measured outcome and [protocol](PROTOCOL.md) for the frozen design. The runtime detector and Evaluation page continue using the existing v1 release; neither retrained model is enabled or packaged into the application. Phase 6 remains the next presentation phase.

From the project root with the existing virtual environment and healthy TraceHawk Compose network:

```sh
.venv/bin/python -m pip install --require-hashes -r evaluation/requirements.lock
.venv/bin/python tools/prepare_ml_v2.py
.venv/bin/python tools/run_ml_v2_rules.py
.venv/bin/python tools/evaluate_ml_v2.py
.venv/bin/python tools/render_ml_v2_report.py
APP_ROOT="$PWD" PYTHONPATH=services/backend .venv/bin/python -m pytest services/backend/tests -q
go -C services/collector test ./...
```

Preparation validates both corpus freezes, v2 protocol/generator hashes, normalized hashes and Go partition routing. Labels never enter the normalizer. The production SQL evaluator runs in its own disposable PostgreSQL container, rolls back every capture and removes its container/private environment file on exit. It does not insert into the running application's database. Re-run outputs are deterministic on the tested macOS ARM64 Python 3.14.2 / sklearn 1.9.1 environment; CI is configured but not yet executed remotely. Scores may differ slightly across platforms; JSON scorer parity is checked numerically.

The original v2 generator is kept byte-for-byte because its source hash is frozen. Running it again refuses to overwrite the frozen corpus. The checked-in original PCAP and pinned Zeek logs are the reproducible evaluation inputs; Zeek UIDs need not be identical if PCAPs are independently reprocessed. Other incidental Zeek logs are outside the freeze.

`report.json` includes selected cutoffs, every validation cutoff, every held-out window, feature ranges, tree split counts, safe JSON artifact hashes and source hashes. `retrained-baseline.json` and `temporal-v2.json` contain tree arrays, never pickle. The original model is read from its unchanged v1 artifact. Validation false-positive budgets apply to complete source episodes, not individual minute windows. Window truth requires overlap with labeled attack intervals, so benign background minutes in attack captures are not automatically labeled suspicious.

The v2 holdout is consumed. Further tuning needs another protocol and fresh test data. No real-world detection rate, default model promotion or new capacity claim follows from this experiment.
