"""Generate isolated ignored local credentials without exposing them in output."""

from pathlib import Path
import json, os, secrets

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = ROOT / ".env"
    credentials = ROOT / "tmp/credentials.json"
    credentials.parent.mkdir(exist_ok=True)
    if env.exists():
        if not credentials.exists():
            raise SystemExit(
                "Existing .env found without credential record; preserve it and restore tmp/credentials.json."
            )
        print("Existing configuration preserved. Credentials: " + str(credentials))
        return
    values = {
        k: secrets.token_urlsafe(32)
        for k in (
            "POSTGRES_PASSWORD",
            "INTERNAL_TOKEN",
            "OPERATOR_PASSWORD",
            "ANALYST_PASSWORD",
        )
    }
    for p, content in [
        (env, "\n".join(k + "=" + v for k, v in values.items()) + "\n"),
        (
            credentials,
            json.dumps(
                {
                    "operator": values["OPERATOR_PASSWORD"],
                    "analyst": values["ANALYST_PASSWORD"],
                },
                indent=2,
            )
            + "\n",
        ),
    ]:
        with open(p, "x") as f:
            os.chmod(p, 0o600)
            f.write(content)
    print("Generated local configuration. Private credentials: " + str(credentials))


if __name__ == "__main__":
    main()
