"""Construct offline PCAPs and freeze their pinned-Zeek telemetry and labels."""

from pathlib import Path
from decimal import Decimal
import hashlib, json, random, subprocess, sys
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "evaluation/corpus"
ZEEK = "zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
BASE = 1791028800000000


def capture(name, split, index, kind, n, spacing=0.45):
    rng = random.Random(4100 + index)
    folder = DEST / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "zeek").mkdir(exist_ok=True)
    src = f"192.0.2.{60+index}"
    dst = "198.51.100.22"
    dnsdst = "198.51.100.53"
    packets = []
    truth = []
    policy = []
    serial = 0

    def add(p, t):
        p.time = Decimal(BASE) / 1000000 + Decimal(str(t))
        packets.append(p)

    def eth(a, b):
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
            src=a, dst=b
        )

    def tcp(t, port=443, state="SF", destination=dst):
        nonlocal serial
        sport = 33000 + serial
        serial += 1
        if state == "S0":
            add(
                eth(src, destination)
                / TCP(sport=sport, dport=port, flags="S", seq=100),
                t,
            )
            return
        if state == "REJ":
            add(
                eth(src, destination)
                / TCP(sport=sport, dport=port, flags="S", seq=100),
                t,
            )
            add(
                eth(destination, src)
                / TCP(sport=port, dport=sport, flags="RA", ack=101),
                t + 0.01,
            )
            return
        frames = [
            (src, destination, sport, port, "S", 100, 0),
            (destination, src, port, sport, "SA", 200, 101),
            (src, destination, sport, port, "A", 101, 201),
            (src, destination, sport, port, "FA", 101, 201),
            (destination, src, port, sport, "FA", 201, 102),
            (src, destination, sport, port, "A", 102, 202),
        ]
        for j, (a, b, sp, dp, f, s, ack) in enumerate(frames):
            add(
                eth(a, b) / TCP(sport=sp, dport=dp, flags=f, seq=s, ack=ack),
                t + j * 0.004,
            )

    def dns(t, i, nx=False, query=None):
        sport = 47000 + i
        q = DNSQR(qname=(query or f"www{i%7}.example.test") + ".", qtype="A")
        add(
            eth(src, dnsdst)
            / UDP(sport=sport, dport=53)
            / DNS(id=2000 + i, rd=1, qd=q),
            t,
        )
        response = DNS(id=2000 + i, qr=1, rd=1, ra=1, rcode=3 if nx else 0, qd=q)
        if not nx:
            response.an = DNSRR(rrname=q.qname, type="A", ttl=60, rdata="198.51.100.8")
        add(eth(dnsdst, src) / UDP(sport=53, dport=sport) / response, t + 0.012)

    if kind in ("normal", "busy-dns", "benign-nx", "dns-attack"):
        for i in range(n):
            t = 1 + i * spacing
            nx = (
                (i < round(n * 0.86))
                if kind in ("benign-nx", "dns-attack")
                else rng.random() < 0.04
            )
            dns(t, i, nx)
        for i in range(max(2, n // 8)):
            tcp(2 + i * spacing * 7, port=443 if i % 2 else 80)
        if kind == "dns-attack":
            truth.append(("dns_nxdomain_burst", None, 1, 1 + (n - 1) * spacing))
    elif kind == "indicator":
        tcp(1, destination="192.0.2.20")
        dns(3, 0, False, "host0.example.test")
        truth.extend(
            [
                ("known_indicator", "192.0.2.20", 1, 1.02),
                ("known_indicator", None, 3, 3),
            ]
        )
    elif kind == "near-indicator":
        tcp(1, destination="192.0.2.21")
        dns(3, 0, False, "prefix.host0.example.test")
        dns(5, 1, False, "host0.example.test.evil.test")
    else:
        for i in range(n):
            port = 7000 + i if kind in ("scan", "slow-scan", "authorized") else 443
            state = "REJ" if kind in ("denied", "outage") else "SF"
            destination = f"198.51.100.{70+i}" if kind == "horizontal" else dst
            tcp(1 + i * spacing, port, state, destination)
        if kind in ("scan", "slow-scan"):
            truth.append(("vertical_tcp_scan", dst, 1, 1 + (n - 1) * spacing + 0.02))
        if kind == "denied":
            truth.append(
                ("failed_tcp_connections", dst, 1, 1 + (n - 1) * spacing + 0.01)
            )
        if kind == "horizontal":
            truth.append(("horizontal_scan", None, 1, 1 + (n - 1) * spacing + 0.02))
        if kind == "authorized":
            policy.append(
                {
                    "detector_id": "vertical_tcp_scan",
                    "source_ip": src,
                    "destination_ip": dst,
                    "reason": "Explicit authorized asset inventory scan; policy known before replay.",
                }
            )
    # One benign packet anchors a declared five-minute source observation interval.
    tcp(299, 443)
    packets.sort(key=lambda p: p.time)
    pcap = folder / "traffic.pcap"
    wrpcap(str(pcap), packets)
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
            "128m",
            "-v",
            f"{folder}:/input:ro",
            "-v",
            f'{folder/"zeek"}:/output',
            "-w",
            "/output",
            ZEEK,
            "zeek",
            "-r",
            "/input/traffic.pcap",
            "LogAscii::use_json=T",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    for log in ("conn", "dns"):
        p = folder / "zeek" / f"{log}.log"
        if not p.exists():
            p.write_text("")
    meta = {
        "scenario_id": name,
        "split": split,
        "input_mode": "controlled_pcap",
        "license": "CC0-1.0",
        "provenance": "Original offline synthetic packet construction; no network transmission. Pinned Zeek 8.0.10.",
        "generator_seed": 4100 + index,
        "time_start_us": BASE,
        "time_end_us": BASE + 300000000,
        "folder": f"evaluation/corpus/{name}",
        "source_ip": src,
        "observed_host_hours": 300 / 3600,
        "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "log_hashes": {
            k: hashlib.sha256((folder / "zeek" / f"{k}.log").read_bytes()).hexdigest()
            for k in ("conn", "dns")
        },
        "total": sum(
            len((folder / "zeek" / f"{k}.log").read_text().splitlines())
            for k in ("conn", "dns")
        ),
    }
    (folder / "manifest.json").write_text(json.dumps(meta, indent=2) + "\n")
    labels = {
        "episodes": [
            {
                "detector_id": family,
                "source_ip": src,
                "destination_ip": target,
                "start_us": BASE + int(a * 1000000),
                "end_us": BASE + int(b * 1000000),
            }
            for family, target, a, b in truth
        ],
        "policies": policy,
        "context": kind,
        "benign_explanation": {
            "outage": "Rejected retries to one service during an authorized maintenance outage.",
            "benign-nx": "Legitimate mistyped/stale DNS cache refresh; many NXDOMAIN responses.",
            "authorized": "Authorized inventory scan.",
        }.get(kind),
    }
    (folder / "labels.json").write_text(json.dumps(labels, indent=2) + "\n")
    return name


def main():
    if (DEST / "freeze.json").exists():
        raise SystemExit(
            "Corpus is frozen. Verify existing inputs; create a new version to change them."
        )
    cases = []
    for i in range(10):
        cases.append(
            (
                f"train-benign-{i:02}",
                "development-train",
                "normal",
                20 + i * 3,
                2.3 + i * 0.17,
            )
        )
    cases += [
        (
            f"validation-benign-{i:02}",
            "development-validation",
            "normal",
            30 + i * 7,
            1.7 + i * 0.1,
        )
        for i in range(4)
    ]
    cases += [
        ("validation-scan", "development-validation", "scan", 45, 0.63),
        ("validation-dns", "development-validation", "dns-attack", 68, 0.38),
    ]
    cases += [
        ("heldout-web", "held-out", "normal", 48, 1.3),
        ("heldout-busy-dns", "held-out", "busy-dns", 120, 0.21),
        ("heldout-outage", "held-out", "outage", 47, 0.72),
        ("heldout-authorized", "held-out", "authorized", 53, 0.42),
        ("heldout-fast-scan", "held-out", "scan", 61, 0.31),
        ("heldout-slow-scan", "held-out", "slow-scan", 17, 7.8),
        ("heldout-denied", "held-out", "denied", 38, 0.89),
        ("heldout-dns-attack", "held-out", "dns-attack", 93, 0.28),
        ("heldout-benign-nx", "held-out", "benign-nx", 76, 0.37),
        ("heldout-indicator", "held-out", "indicator", 1, 1),
        ("heldout-near-indicator", "held-out", "near-indicator", 1, 1),
        ("heldout-horizontal", "held-out", "horizontal", 41, 0.51),
    ]
    names = [
        capture(name, split, i, kind, n, gap)
        for i, (name, split, kind, n, gap) in enumerate(cases)
    ]
    hashes = {
        str(p.relative_to(DEST)): hashlib.sha256(p.read_bytes()).hexdigest()
        for name in names
        for p in sorted((DEST / name).rglob("*"))
        if p.is_file()
        and (
            p.name
            in ("traffic.pcap", "manifest.json", "labels.json", "conn.log", "dns.log")
        )
    }
    freeze = {
        "version": "synthetic-corpus-v1",
        "protocol_sha256": hashlib.sha256(
            (ROOT / "evaluation/PROTOCOL.md").read_bytes()
        ).hexdigest(),
        "captures": names,
        "files": hashes,
        "limitations": [
            "Authored synthetic captures, not blind or representative external traffic.",
            "No real threat intelligence.",
            "Five-minute declared laboratory observation per source; benign host-hour rates do not extrapolate to production.",
        ],
    }
    (DEST / "freeze.json").write_text(json.dumps(freeze, indent=2) + "\n")
    print(json.dumps({"captures": len(names), "frozen_files": len(hashes)}))


if __name__ == "__main__":
    main()
