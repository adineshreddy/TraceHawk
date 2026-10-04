"""Verify v2 freeze and normalize with the unchanged offline Go entrypoint."""

from pathlib import Path
import hashlib, json, os, subprocess
from evaluation_common import partition
from prepare_evaluation import verify as verify_v1

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "evaluation/experiments/ml-v2"
CORPUS = ROOT / "evaluation/corpus"
OUTPUT = ROOT / "tmp/ml-v2"


def verify():
    verify_v1()
    freeze = json.loads((EXPERIMENT / "freeze.json").read_text())
    assert (
        hashlib.sha256((EXPERIMENT / "PROTOCOL.md").read_bytes()).hexdigest()
        == freeze["protocol_sha256"]
    )
    assert (
        hashlib.sha256(
            (ROOT / "tools/generate_ml_v2_corpus.py").read_bytes()
        ).hexdigest()
        == freeze["generator_sha256"]
    )
    for name, sha in freeze["files"].items():
        assert hashlib.sha256((CORPUS / name).read_bytes()).hexdigest() == sha, name
    return freeze


def verify_prepared():
    freeze = verify()
    hashes = json.loads((EXPERIMENT / "normalized-hashes.json").read_text())
    assert set(hashes) == set(freeze["captures"])
    for name, sha in hashes.items():
        assert (
            hashlib.sha256((OUTPUT / (name + ".jsonl")).read_bytes()).hexdigest() == sha
        )
    for relative, sha in freeze["files"].items():
        assert (
            hashlib.sha256((OUTPUT / "corpus" / relative).read_bytes()).hexdigest()
            == sha
        )
    assert json.loads((OUTPUT / "corpus/freeze.json").read_text()) == freeze
    return freeze


def main():
    freeze = verify()
    OUTPUT.mkdir(parents=True, exist_ok=True)
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
        meta = {k: m[k] for k in ["folder", "time_end_us", "log_hashes"]}
        job = dict(
            run_id=name,
            scope_id=name,
            scenario_id=name,
            generation=1,
            next_index=0,
            speed=10,
            source_offsets=[None] * 3,
            metadata=meta,
        )
        jobpath = OUTPUT / (name + ".job.json")
        jobpath.write_text(json.dumps(job))
        target = OUTPUT / (name + ".jsonl")
        subprocess.run(
            [
                str(ROOT / "tmp/evaluation-collector"),
                "--normalize-evaluation",
                str(jobpath),
                str(target),
            ],
            check=True,
            env=os.environ | {"APP_ROOT": str(ROOT)},
        )
        assert len(target.read_text().splitlines()) == m["total"]
        routing = json.loads(Path(str(target) + ".partitions.json").read_text())
        assert all(partition(name, source) == p for source, p in routing.items())
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    path = EXPERIMENT / "normalized-hashes.json"
    if path.exists():
        assert json.loads(path.read_text()) == hashes, "Normalized output changed"
    else:
        path.write_text(json.dumps(hashes, indent=2) + "\n")
    # Container mount contains only v2 inputs and its own freeze; links stay local.
    staged = OUTPUT / "corpus"
    staged.mkdir(exist_ok=True)
    for name in freeze["captures"]:
        target = staged / name
        # Copy rather than symlink: container bind mount cannot follow host paths.
        import shutil

        shutil.copytree(CORPUS / name, target, dirs_exist_ok=True)
    (staged / "freeze.json").write_text(json.dumps(freeze))
    print(json.dumps(dict(status="passed", captures=len(hashes), labels_in_job=False)))


if __name__ == "__main__":
    main()
