"""Verify the freeze and normalize with the actual Go collector, never labels."""

from evaluation_common import partition
from pathlib import Path
import json, hashlib, subprocess

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evaluation/corpus"


def verify():
    freeze = json.loads((CORPUS / "freeze.json").read_text())
    assert (
        hashlib.sha256((ROOT / "evaluation/PROTOCOL.md").read_bytes()).hexdigest()
        == freeze["protocol_sha256"]
    ), "Protocol changed after freeze"
    for relative, sha in freeze["files"].items():
        assert (
            hashlib.sha256((CORPUS / relative).read_bytes()).hexdigest() == sha
        ), f"Frozen corpus changed: {relative}"
    return freeze


def main():
    freeze = verify()
    out = ROOT / "tmp/evaluation"
    out.mkdir(exist_ok=True)
    subprocess.run(
        [
            "go",
            "-C",
            str(ROOT / "services/collector"),
            "build",
            "-o",
            str(ROOT / "tmp/evaluation-collector"),
            ".",
        ],
        check=True,
    )
    hashes = {}
    for name in freeze["captures"]:
        m = json.loads((CORPUS / name / "manifest.json").read_text())
        # Only source provenance, scope and time bounds reach the normalizer.
        meta = {k: m[k] for k in ["folder", "time_end_us", "log_hashes"]}
        job = {
            "run_id": name,
            "scope_id": name,
            "scenario_id": name,
            "generation": 1,
            "next_index": 0,
            "speed": 10,
            "source_offsets": [None] * 3,
            "metadata": meta,
        }
        jobpath = out / (name + ".job.json")
        jobpath.write_text(json.dumps(job))
        target = out / (name + ".jsonl")
        subprocess.run(
            [
                str(ROOT / "tmp/evaluation-collector"),
                "--normalize-evaluation",
                str(jobpath),
                str(target),
            ],
            check=True,
            env=__import__("os").environ | {"APP_ROOT": str(ROOT)},
        )
        assert len(target.read_text().splitlines()) == m["total"]
        routing = json.loads(Path(str(target) + ".partitions.json").read_text())
        assert all(partition(name, source) == p for source, p in routing.items())
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    (ROOT / "evaluation/normalized-hashes.json").write_text(
        json.dumps(hashes, indent=2) + "\n"
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "captures": len(hashes),
                "normalizer": "production Go normalization, offline mode",
                "labels_in_job": False,
            }
        )
    )


if __name__ == "__main__":
    main()
