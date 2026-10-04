"""Fresh-migration smoke in a disposable private database; preserve the application DB."""

from pathlib import Path
import os, secrets, subprocess, time, json, uuid

ROOT = Path(__file__).resolve().parents[1]
POSTGRES = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"


def main():
    name = "tracehawk-migration-check-" + uuid.uuid4().hex[:10]
    envfile = ROOT / "tmp" / f"{name}.env"
    values = {
        "POSTGRES_DB": "tracehawk",
        "POSTGRES_USER": "tracehawk",
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "OPERATOR_PASSWORD": secrets.token_urlsafe(32),
        "ANALYST_PASSWORD": secrets.token_urlsafe(32),
        "DB_HOST": name,
    }
    with open(envfile, "x") as f:
        os.chmod(envfile, 0o600)
        f.write("".join(k + "=" + v + "\n" for k, v in values.items()))

    def execute(args, **kwargs):
        return subprocess.run(
            args, cwd=ROOT, check=True, capture_output=True, text=True, **kwargs
        )

    try:
        execute(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "tracehawk_core",
                "--memory=192m",
                "--cpus=1",
                "--env-file",
                str(envfile),
                POSTGRES,
            ]
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = subprocess.run(
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
                capture_output=True,
            )
            if result.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Disposable database did not become ready")
        code = """
import json
from tracehawk.core import initialize,db
initialize();initialize()
with db() as c:
 migrations=c.execute('SELECT version FROM schema_migrations ORDER BY version').fetchall()
 assert [r['version'] for r in migrations]==['001_foundation.sql','002_detection_investigation.sql','003_reliability.sql','004_measurement.sql']
 assert c.execute('SELECT count(*) n FROM users').fetchone()['n']==2
 assert c.execute('SELECT count(*) n FROM rule_versions').fetchone()['n']==2
 assert c.execute('SELECT count(*) n FROM indicator_versions').fetchone()['n']==1
 c.execute("UPDATE schema_migrations SET checksum='tampered' WHERE version='002_detection_investigation.sql'")
try:initialize()
except RuntimeError as error:assert str(error)=='Migration checksum changed'
else:raise AssertionError('Checksum mismatch accepted')
print(json.dumps({'status':'passed','checks':['fresh 001 through 004 migrations','idempotent startup and seeds','applied checksum mismatch rejected'],'isolated_database':True,'application_data':'preserved'},indent=2))
"""
        result = execute(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "tracehawk_core",
                "--env-file",
                str(envfile),
                "--memory=256m",
                "tracehawk-backend:phase4",
                "python",
                "-c",
                code,
            ]
        )
        (ROOT / "docs/phase-2/migrations.json").write_text(result.stdout)
        print(result.stdout.strip())
    finally:
        subprocess.run(
            ["docker", "rm", "-f", "-v", name],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        envfile.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
