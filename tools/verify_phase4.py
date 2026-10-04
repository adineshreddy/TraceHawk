"""Verify packaged evaluation responses and their evidence references."""

import hashlib, json
from pathlib import Path
import httpx
from prepare_evaluation import verify
from verify_phase2 import login, BASE

ROOT = Path(__file__).resolve().parents[1]


def main():
    verify()
    expected = json.loads((ROOT / "evaluation/reports/summary.json").read_text())
    for name, digest in expected["source_report_sha256"].items():
        assert (
            hashlib.sha256(
                (ROOT / f"evaluation/reports/{name}.json").read_bytes()
            ).hexdigest()
            == digest
        )
    manifest = json.loads((ROOT / "evaluation/model/manifest.json").read_text())
    assert (
        hashlib.sha256(
            (ROOT / "evaluation/model" / manifest["artifact"]).read_bytes()
        ).hexdigest()
        == manifest["sha256"]
    )
    assert not expected["model"]["default_enabled"]
    assert httpx.get(BASE + "/api/v1/evaluation").status_code == 401
    for role in ["operator", "analyst"]:
        c = login(role)
        try:
            response = c.get("/api/v1/evaluation")
            assert response.status_code == 200 and response.json() == expected
        finally:
            c.close()
    report = {
        "status": "passed",
        "checks": [
            "frozen corpus/protocol hashes",
            "summary evidence hashes",
            "exported model hash",
            "anonymous denied",
            "operator/analyst response parity against public contract",
            "offline model disabled",
        ],
    }
    (ROOT / "docs/phase-4/api.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
