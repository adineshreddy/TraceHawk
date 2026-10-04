"""Run production SQL evaluation in a disposable, private PostgreSQL database."""

from pathlib import Path
import json, os, secrets, subprocess, time, uuid
from prepare_evaluation import verify

ROOT = Path(__file__).resolve().parents[1]
POSTGRES = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"


def main(corpus=None, inputs=None, report=None, verify_fn=verify):
    verify_fn()
    corpus = corpus or ROOT / "evaluation/corpus"
    inputs = inputs or ROOT / "tmp/evaluation"
    report = report or ROOT / "evaluation/reports/rules.json"
    name = "tracehawk-evaluation-" + uuid.uuid4().hex[:10]
    envfile = ROOT / "tmp" / f"{name}.env"
    env = {
        "DB_HOST": name,
        "POSTGRES_DB": "tracehawk",
        "POSTGRES_USER": "tracehawk",
        **{
            k: secrets.token_urlsafe(32)
            for k in [
                "POSTGRES_PASSWORD",
                "OPERATOR_PASSWORD",
                "ANALYST_PASSWORD",
                "INTERNAL_TOKEN",
            ]
        },
    }
    with envfile.open("x") as f:
        os.chmod(envfile, 0o600)
        f.write("".join(k + "=" + v + "\n" for k, v in env.items()))

    def run(args, **kwargs):
        return subprocess.run(
            args, cwd=ROOT, text=True, check=True, capture_output=True, **kwargs
        )

    try:
        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "tracehawk_core",
                "--memory=192m",
                "--env-file",
                str(envfile),
                POSTGRES,
            ]
        )
        for _ in range(60):
            if (
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        name,
                        "pg_isready",
                        "-U",
                        "tracehawk",
                        "-d",
                        "tracehawk",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode
                == 0
            ):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Evaluation DB unavailable")
        args = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            "tracehawk_core",
            "--memory=256m",
            "--env-file",
            str(envfile),
            "-v",
            f"{corpus}:/corpus:ro",
            "-v",
            f"{inputs}:/inputs:ro",
            "-v",
            f'{ROOT/"tools"}:/tools:ro',
            "-e",
            "PYTHONPATH=/app:/tools",
            "tracehawk-backend:phase4",
            "python",
            "-",
        ]
        result = run(
            args, input=(ROOT / "tools/evaluate_rules_container.py").read_text()
        )
        data = json.loads(result.stdout)
        assert data["status"] == "passed"
        report.write_text(result.stdout)
        print(json.dumps({k: v for k, v in data.items() if k != "captures"}, indent=2))
    except subprocess.CalledProcessError as e:
        print(e.stderr[-2500:])
        raise
    finally:
        subprocess.run(
            ["docker", "rm", "-f", "-v", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        envfile.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
