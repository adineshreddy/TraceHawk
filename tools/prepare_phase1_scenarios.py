"""Derive a benign offline PCAP and process it with the pinned Zeek image."""

from pathlib import Path
import json, hashlib, subprocess
from scapy.all import rdpcap, wrpcap, TCP, DNS, IP

ROOT = Path(__file__).resolve().parents[1]


def main():
    dest = ROOT / "scenarios/phase1-benign"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "zeek").mkdir(exist_ok=True)
    packets = [
        p
        for p in rdpcap(str(ROOT / "scenarios/phase0/controlled-network.pcap"))
        if (DNS in p and p[DNS].id >= 1032)
        or (TCP in p and "192.0.2.40" in (p[IP].src, p[IP].dst))
    ]
    out = dest / "benign-network.pcap"
    wrpcap(str(out), packets)
    manifest = {
        "schema_version": "1.0",
        "scenario_id": "benign-network-v1",
        "capture_file": out.name,
        "capture_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "input_mode": "controlled_pcap",
        "packet_count": len(packets),
        "time_start_us": int(min(p.time for p in packets) * 1000000),
        "time_end_us": int(max(p.time for p in packets) * 1000000),
        "provenance": "Original offline development fixture derived from successful DNS transactions and normal TCP connection in Phase 0 capture. No transmitted traffic.",
        "license": "CC0-1.0",
        "expected_telemetry": {
            "connection_records": 9,
            "dns_records": 8,
            "tcp_normal": 1,
            "dns_noerror": 8,
        },
        "ground_truth": [],
        "limitations": [
            "Small development baseline; not an independent evaluation corpus."
        ],
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--memory",
            "256m",
            "-v",
            f"{dest}:/input:ro",
            "-v",
            f'{dest/"zeek"}:/output',
            "-w",
            "/output",
            "zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3",
            "zeek",
            "-r",
            "/input/benign-network.pcap",
            "LogAscii::use_json=T",
        ],
        check=True,
    )
    rows = {
        k: [
            json.loads(x) for x in (dest / "zeek" / f"{k}.log").read_text().splitlines()
        ]
        for k in ("conn", "dns")
    }
    assert len(packets) == 22 and len(rows["conn"]) == 9 and len(rows["dns"]) == 8
    assert all(x["rcode"] == 0 for x in rows["dns"])
    print(
        "Benign PCAP verified: 22 packets, 9 connection records, 8 successful DNS responses"
    )


if __name__ == "__main__":
    main()
