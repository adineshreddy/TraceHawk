"""Check Git's publication inventory without printing private values."""

from pathlib import Path
import json, re, subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    files = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .split("\0")[:-1]
    )
    forbidden = [
        p
        for p in files
        if p.startswith(("tmp/", ".venv/"))
        or p == ".env"
        or "/node_modules/" in p
        or "/__pycache__/" in p
    ]
    assert not forbidden, forbidden
    values = []
    for relative in (".env", "tmp/kubernetes-secrets.env"):
        p = ROOT / relative
        if p.exists():
            values.extend(
                s.split("=", 1)[1] for s in p.read_text().splitlines() if "=" in s
            )
    for relative in ("tmp/credentials.json", "tmp/kubernetes-credentials.json"):
        p = ROOT / relative
        if p.exists():
            values.extend(
                v for v in json.loads(p.read_text()).values() if isinstance(v, str)
            )
    patterns = [
        rb"gh[pousr]_[A-Za-z0-9]{30,}",
        rb"github_pat_[A-Za-z0-9_]{30,}",
        rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ]
    problems = []
    for name in files:
        body = (ROOT / name).read_bytes()
        if any(v.encode() in body for v in values if len(v) >= 16) or any(
            re.search(p, body) for p in patterns
        ):
            problems.append(name)
        assert len(body) < 90_000_000, f"GitHub file-size limit: {name}"
    assert not problems, problems
    print(
        json.dumps(
            dict(
                status="passed",
                tracked_files=len(files),
                private_paths_excluded=True,
                local_credential_scan_clear=True,
                scope="Local credential values and selected token/private-key patterns; not a comprehensive secret audit.",
            )
        )
    )


if __name__ == "__main__":
    main()
