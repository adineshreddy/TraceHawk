"""Workspace-scoped kind deployment. Never changes the default kubeconfig."""

from pathlib import Path
import argparse, hashlib, json, os, platform, secrets, subprocess, time
import yaml

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infrastructure/kubernetes"
KUBECONFIG = ROOT / "tmp/kind-kubeconfig"
DATA = ROOT / "tmp/kind-data"
NODE = "tracehawk-control-plane"
LOCK = json.loads((INFRA / "toolchain.json").read_text())


def run(args, **kw):
    return subprocess.run(args, cwd=ROOT, check=True, **kw)


def kubectl(*args, **kw):
    return run(["kubectl", "--kubeconfig", str(KUBECONFIG), *args], **kw)


def install_kind():
    system = platform.system().lower()
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}[platform.machine()]
    asset = f"kind-{system}-{arch}"
    target = ROOT / "tmp/bin/kind"
    target.parent.mkdir(parents=True, exist_ok=True)
    expected = LOCK["kind_binary_sha256"][asset]
    if (
        not target.exists()
        or hashlib.sha256(target.read_bytes()).hexdigest() != expected
    ):
        run(
            [
                "curl",
                "-fsSL",
                f'https://github.com/kubernetes-sigs/kind/releases/download/{LOCK["kind_version"]}/{asset}',
                "-o",
                str(target),
            ]
        )
    assert (
        hashlib.sha256(target.read_bytes()).hexdigest() == expected
    ), "kind binary checksum mismatch"
    target.chmod(0o755)
    return str(target)


def kind(*args, **kw):
    return run([install_kind(), *args], **kw)


def owned():
    result = subprocess.run(["docker", "inspect", NODE], capture_output=True, text=True)
    if result.returncode:
        return False
    info = json.loads(result.stdout)[0]
    assert info["Config"]["Labels"].get("io.x-k8s.kind.cluster") == "tracehawk"
    mounts = {m["Destination"]: m["Source"] for m in info["Mounts"]}
    assert mounts.get("/tracehawk-data", "").removeprefix("/host_mnt") == str(
        DATA
    ), "Refusing unrelated cluster or unexpected data mount"
    return True


def wait_api():
    for _ in range(120):
        r = subprocess.run(
            ["kubectl", "--kubeconfig", str(KUBECONFIG), "get", "--raw", "/readyz"],
            capture_output=True,
        )
        if r.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("Dedicated Kubernetes API did not become ready")


def load_images():
    services = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
    arch = run(
        ["docker", "exec", NODE, "uname", "-m"], capture_output=True, text=True
    ).stdout.strip()
    target = "linux/" + {"aarch64": "arm64", "x86_64": "amd64"}[arch]
    for image in sorted(set(v["image"] for v in services.values())):
        if "@sha256:" in image:
            # Classic Docker exports can rebuild a platform manifest and discard
            # the pinned multi-platform index. Pull in containerd by the exact
            # registry digest instead of assigning that digest to different bytes.
            repository = image.split("@")[0].split(":")[0]
            canonical = image
            if "/" not in repository:
                canonical = "docker.io/library/" + image
            elif "." not in repository.split("/")[0]:
                canonical = "docker.io/" + image
            run(
                [
                    "docker",
                    "exec",
                    NODE,
                    "ctr",
                    "-n",
                    "k8s.io",
                    "images",
                    "pull",
                    "--platform",
                    target,
                    canonical,
                ],
                stdout=subprocess.DEVNULL,
                timeout=300,
            )
            print("Pulled pinned", image.split("@")[0], flush=True)
            continue
        if subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode:
            assert "@sha256:" in image, "Build application images before loading"
            run(["docker", "pull", image], stdout=subprocess.DEVNULL)
        # Import only the host platform: Docker Desktop can export incomplete indexes.
        save = subprocess.Popen(
            ["docker", "image", "save", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        load = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                NODE,
                "ctr",
                "-n",
                "k8s.io",
                "images",
                "import",
                "--platform",
                target,
                "--digests",
                "-",
            ],
            stdin=save.stdout,
            capture_output=True,
            text=True,
        )
        save.stdout.close()
        error = save.stderr.read().decode()
        status = save.wait()
        assert status == 0, error
        assert load.returncode == 0, load.stderr
        rows = run(
            ["docker", "exec", NODE, "ctr", "-n", "k8s.io", "images", "ls"],
            capture_output=True,
            text=True,
        ).stdout.splitlines()[1:]
        # Digest-only Docker saves have no RepoTags; normalize their import aliases for CRI.
        for row in rows:
            ref = row.split()[0]
            if ref.startswith("import-"):
                run(
                    [
                        "docker",
                        "exec",
                        NODE,
                        "ctr",
                        "-n",
                        "k8s.io",
                        "images",
                        "tag",
                        "--force",
                        ref,
                        "docker.io/library/" + ref,
                    ],
                    stdout=subprocess.DEVNULL,
                )
        print("Loaded", image.split("@")[0], flush=True)


def prepare_secret():
    path = ROOT / "tmp/kubernetes-secrets.env"
    credentials = ROOT / "tmp/kubernetes-credentials.json"
    if not path.exists():
        values = {
            k: secrets.token_urlsafe(32)
            for k in (
                "POSTGRES_PASSWORD",
                "INTERNAL_TOKEN",
                "OPERATOR_PASSWORD",
                "ANALYST_PASSWORD",
            )
        }
        with path.open("x") as f:
            os.chmod(path, 0o600)
            f.write("".join(k + "=" + v + "\n" for k, v in values.items()))
        with credentials.open("x") as f:
            os.chmod(credentials, 0o600)
            json.dump(
                {
                    "operator": values["OPERATOR_PASSWORD"],
                    "analyst": values["ANALYST_PASSWORD"],
                },
                f,
            )
    assert path.stat().st_mode & 0o077 == 0, "Secret file must be private (chmod 600)"
    secret = kubectl(
        "-n",
        "tracehawk",
        "create",
        "secret",
        "generic",
        "runtime-secrets",
        "--from-env-file=" + str(path),
        "--dry-run=client",
        "-o",
        "json",
        capture_output=True,
        text=True,
    ).stdout
    kubectl(
        "apply",
        "--server-side",
        "-f",
        "-",
        input=secret,
        text=True,
        stdout=subprocess.DEVNULL,
    )


def up(build=True):
    ROOT.joinpath("tmp").mkdir(exist_ok=True)
    assert not DATA.is_symlink(), "Data directory must not be a symlink"
    version = run(
        ["kubectl", "version", "--client", "-o", "json"], capture_output=True, text=True
    )
    client = json.loads(version.stdout)["clientVersion"]
    assert (
        client["major"] == "1" and 34 <= int(client["minor"].rstrip("+")) <= 36
    ), "Use kubectl 1.34–1.36 with this Kubernetes 1.35 profile"
    # Verify ownership before touching a same-named existing cluster.
    existing = owned()
    run(["docker", "compose", "stop"], stdout=subprocess.DEVNULL)
    if build:
        run(
            ["docker", "compose", "build", "api", "collector", "console"],
            stdout=subprocess.DEVNULL,
        )
    if not existing:
        DATA.mkdir(exist_ok=True)
        DATA.chmod(0o700)
        config = yaml.safe_load((INFRA / "kind.yaml").read_text())
        config["nodes"][0]["extraMounts"] = [
            {"hostPath": str(DATA), "containerPath": "/tracehawk-data"}
        ]
        path = ROOT / "tmp/kind-runtime.yaml"
        path.write_text(yaml.safe_dump(config))
        kind(
            "create",
            "cluster",
            "--config",
            str(path),
            "--kubeconfig",
            str(KUBECONFIG),
            "--wait",
            "0s",
        )
    else:
        run(["docker", "start", NODE], stdout=subprocess.DEVNULL)
        kind(
            "export",
            "kubeconfig",
            "--name",
            "tracehawk",
            "--kubeconfig",
            str(KUBECONFIG),
        )
    KUBECONFIG.chmod(0o600)
    run(
        ["docker", "update", "--memory", "4g", "--memory-swap", "4g", NODE],
        stdout=subprocess.DEVNULL,
    )
    wait_api()
    vendor = INFRA / "vendor/calico.yaml"
    meta = json.loads((INFRA / "vendor/manifest.json").read_text())
    assert hashlib.sha256(vendor.read_bytes()).hexdigest() == meta["vendored_sha256"]
    kubectl("apply", "--server-side", "-f", str(vendor), stdout=subprocess.DEVNULL)
    load_images()
    for name, uid in [
        ("database", 70),
        ("broker", 1000),
        ("collector-state", 10001),
        ("publisher-state", 10001),
        ("metrics", 65534),
        ("grafana-data", 472),
    ]:
        path = "/tracehawk-data/" + name
        run(["docker", "exec", NODE, "mkdir", "-p", path])
        run(["docker", "exec", NODE, "chown", f"{uid}:{uid}", path])
        run(["docker", "exec", NODE, "chmod", "700", path])
    namespace = yaml.safe_load_all((INFRA / "resources.yaml").read_text())
    namespace = next(namespace)
    kubectl(
        "apply",
        "-f",
        "-",
        input=json.dumps(namespace),
        text=True,
        stdout=subprocess.DEVNULL,
    )
    prepare_secret()
    kubectl("apply", "--dry-run=server", "-k", str(INFRA), stdout=subprocess.DEVNULL)
    kubectl("apply", "-k", str(INFRA), stdout=subprocess.DEVNULL)
    # Internal service policies are installed before declaring application readiness.
    kubectl("wait", "--for=condition=Ready", "node/" + NODE, "--timeout=180s")
    kubectl(
        "-n",
        "kube-system",
        "rollout",
        "status",
        "daemonset/calico-node",
        "--timeout=180s",
    )
    kubectl(
        "-n",
        "tracehawk",
        "wait",
        "--for=condition=complete",
        "job/topics",
        "--timeout=300s",
    )
    for name in (
        "postgres",
        "kafka",
        "api",
        "collector",
        "detector",
        "detector-b",
        "publisher",
        "console",
        "prometheus",
        "grafana",
    ):
        resource = "statefulset" if name in ("postgres", "kafka") else "deployment"
        kubectl(
            "-n",
            "tracehawk",
            "rollout",
            "status",
            resource + "/" + name,
            "--timeout=300s",
        )
    print(
        "TraceHawk Kubernetes ready. Run: .venv/bin/python tools/kubernetes.py forward"
    )


def down():
    if owned():
        kind(
            "delete", "cluster", "--name", "tracehawk", "--kubeconfig", str(KUBECONFIG)
        )
    print("Dedicated cluster removed; host data and private credentials retained.")


def pause():
    if owned():
        run(["docker", "stop", NODE], stdout=subprocess.DEVNULL)
    print("Dedicated node paused; data retained.")


def forward():
    assert owned(), "Run up first"
    children = []
    try:
        for name, local, remote in [("console", 3102, 3100), ("grafana", 3103, 3000)]:
            children.append(
                subprocess.Popen(
                    [
                        "kubectl",
                        "--kubeconfig",
                        str(KUBECONFIG),
                        "-n",
                        "tracehawk",
                        "port-forward",
                        "--address",
                        "127.0.0.1",
                        "service/" + name,
                        f"{local}:{remote}",
                    ]
                )
            )
        while all(c.poll() is None for c in children):
            time.sleep(1)
        raise RuntimeError("Port-forward stopped; rerun after pod replacement")
    except KeyboardInterrupt:
        pass
    finally:
        for c in children:
            if c.poll() is None:
                c.terminate()
        for c in children:
            c.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["up", "down", "pause", "forward", "status", "install-tools"]
    )
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    if args.action == "up":
        up(not args.no_build)
    elif args.action == "down":
        down()
    elif args.action == "pause":
        pause()
    elif args.action == "forward":
        forward()
    elif args.action == "install-tools":
        print(install_kind())
    else:
        assert owned()
        kubectl("-n", "tracehawk", "get", "pods,services,pvc")
