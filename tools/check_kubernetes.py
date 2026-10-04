"""Reviewable deployment input checks before server-side admission/real tests."""

from pathlib import Path
import hashlib, json, subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infrastructure/kubernetes"


def main():
    old = (INFRA / "resources.yaml").read_bytes()
    subprocess.run(
        [__import__("sys").executable, str(ROOT / "tools/render_kubernetes.py")],
        check=True,
        cwd=ROOT,
    )
    assert (
        INFRA / "resources.yaml"
    ).read_bytes() == old, "Generated deployment drift: review changed resources.yaml"
    rendered = subprocess.check_output(["kubectl", "kustomize", str(INFRA)], text=True)
    objects = list(yaml.safe_load_all(rendered))
    assert not any(
        x["kind"] == "Secret" for x in objects
    ), "No credentials may be checked in"
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
    for d in objects:
        if d["kind"] in ["Deployment", "StatefulSet"]:
            name = d["metadata"]["name"]
            spec = d["spec"]["template"]["spec"]
            assert spec["containers"][0]["image"] == compose[name]["image"]
            assert not spec.get("hostNetwork") and not spec.get("hostPID")
        if d["kind"] == "Service":
            assert d["spec"]["type"] == "ClusterIP"
        if d["kind"] == "PersistentVolume":
            assert d["spec"]["persistentVolumeReclaimPolicy"] == "Retain"
    meta = json.loads((INFRA / "vendor/manifest.json").read_text())
    assert (
        hashlib.sha256((INFRA / "vendor/calico.yaml").read_bytes()).hexdigest()
        == meta["vendored_sha256"]
    )
    assert all("@sha256:" in image for image in meta["images"].values())
    report = {
        "status": "passed",
        "resources": len(objects),
        "checks": [
            "rendered manifest drift",
            "same Compose images",
            "no checked-in Secret values",
            "internal services",
            "retained local volumes",
            "Calico vendor integrity and image pins",
        ],
    }
    (ROOT / "docs/phase-5/inputs.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
