"""Lock the resolved Python dependency set to published release file hashes."""

from pathlib import Path
import concurrent.futures, json, ssl, urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    ctx = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    lines = (ROOT / "tmp/backend-freeze.txt").read_text().splitlines()

    def resolve(line):
        name, version = line.split("==")
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/{version}/json", context=ctx, timeout=30
        ) as r:
            data = json.load(r)
        hashes = sorted({x["digests"]["sha256"] for x in data["urls"]})
        assert hashes
        return line + " \\\n" + "\\\n".join("    --hash=sha256:" + h for h in hashes)

    rows = list(
        concurrent.futures.ThreadPoolExecutor(8).map(
            resolve, sorted(lines, key=str.lower)
        )
    )
    (ROOT / "services/backend/requirements.lock").write_text(
        "# Resolved on Linux ARM64 Python 3.13.16; all published release file hashes.\n"
        + "\n".join(rows)
        + "\n"
    )
    print("Locked", len(rows), "Python packages with hashes")


if __name__ == "__main__":
    main()
