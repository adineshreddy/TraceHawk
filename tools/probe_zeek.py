"""Run the pinned Zeek image against the controlled capture and verify output."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"


def main():
    dest = ROOT/"scenarios/phase0/zeek"
    dest.mkdir(exist_ok=True)
    for p in dest.glob("*.log"):
        p.unlink()
    command = ["docker","run","--rm","--network","none","--cap-drop","ALL",
               "--memory","512m","--cpus","1","-v",f"{ROOT/'scenarios/phase0'}:/input:ro",
               "-v",f"{dest}:/output","-w","/output",IMAGE,"zeek","-r",
               "/input/controlled-network.pcap","LogAscii::use_json=T"]
    subprocess.run(command,check=True,timeout=90)
    rows = {name:[json.loads(line) for line in (dest/f"{name}.log").read_text().splitlines()] for name in ("conn","dns")}
    states = dict(Counter(r.get("conn_state","unknown") for r in rows["conn"] if r["proto"]=="tcp"))
    rcodes = dict(Counter(r.get("rcode_name","unknown") for r in rows["dns"]))
    assert len(rows["conn"])==68 and len(rows["dns"])==40, "Unexpected telemetry counts"
    assert states=={"REJ":24,"S0":3,"SF":1}, states
    assert rcodes=={"NXDOMAIN":32,"NOERROR":8}, rcodes
    missing = sum("duration" not in r for r in rows["conn"])
    assert missing==3, missing
    for r in rows["dns"]:
        assert r["uid"] in {c["uid"] for c in rows["conn"]}
    report = {"status":"passed","zeek_image":IMAGE,"command":command,
              "connection_records":len(rows["conn"]),"dns_records":len(rows["dns"]),
              "tcp_states":states,"dns_response_codes":rcodes,"missing_duration_records":missing,
              "dns_connection_uids_linked":True,
              "log_hashes":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.glob("*.log")},
              "limitations":["Zeek UIDs are generated per processing run; derived logs may have different hashes when regenerated.",
                              "Connection ts+duration is an activity-end approximation, not log emission time."]}
    (ROOT/"docs/evidence/zeek-probe.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("status","connection_records","dns_records","tcp_states","dns_response_codes","missing_duration_records")},indent=2))


if __name__ == "__main__":
    main()
