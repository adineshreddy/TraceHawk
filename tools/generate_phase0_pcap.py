"""Generate a deterministic offline capture; never sends packets to a network."""
from pathlib import Path
from decimal import Decimal
import hashlib
import json
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "scenarios/phase0"
BASE = Decimal("1791028800")  # 2026-10-03T12:00:00Z


def main():
    packets = []
    def add(packet, seconds):
        packet.time = BASE + Decimal(str(seconds))
        packets.append(packet)
    def eth(src, dst):
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst)
    # Twenty-four explicit rejected TCP attempts at different destination ports.
    for i in range(24):
        sport, dport, t = 40000+i, 8000+i, 1+i
        add(eth("192.0.2.10", "192.0.2.20") / TCP(sport=sport,dport=dport,flags="S",seq=100+i), t)
        add(eth("192.0.2.20", "192.0.2.10") / TCP(sport=dport,dport=sport,flags="RA",ack=101+i), t+.01)
    # Three unanswered attempts, exhibiting missing duration fields.
    for i in range(3):
        add(eth("192.0.2.11", "192.0.2.20") / TCP(sport=41000+i,dport=9000+i,flags="S",seq=200+i), 30+i)
    # Forty independent DNS transactions: 32 NXDOMAIN, eight successful.
    for i in range(40):
        q = DNSQR(qname=f"host{i}.example.test.",qtype="A")
        add(eth("192.0.2.30", "192.0.2.53") / UDP(sport=42000+i,dport=53) / DNS(id=1000+i,rd=1,qd=q), 40+i/5)
        dns = DNS(id=1000+i,qr=1,rd=1,ra=1,rcode=3 if i<32 else 0,qd=q)
        if i>=32:
            dns.an = DNSRR(rrname=q.qname,type="A",ttl=60,rdata="198.51.100.8")
        add(eth("192.0.2.53", "192.0.2.30") / UDP(sport=53,dport=42000+i) / dns, 40+i/5+.02)
    # A normal fully established and terminated TCP connection, not a login.
    client, server = "192.0.2.40", "198.51.100.8"
    frames = [(client,server,43000,443,"S",100,0), (server,client,443,43000,"SA",200,101),
              (client,server,43000,443,"A",101,201), (client,server,43000,443,"FA",101,201),
              (server,client,443,43000,"FA",201,102), (client,server,43000,443,"A",102,202)]
    for i,(src,dst,sp,dp,f,s,a) in enumerate(frames):
        add(eth(src,dst)/TCP(sport=sp,dport=dp,flags=f,seq=s,ack=a), 55+i*.1)
    packets.sort(key=lambda p: p.time)
    DEST.mkdir(parents=True,exist_ok=True)
    path = DEST/"controlled-network.pcap"
    wrpcap(str(path),packets)
    manifest = {"schema_version":"1.0", "scenario_id":"phase0-controlled-network-v1",
        "input_mode":"controlled_pcap", "capture_file":path.name,
        "capture_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"packet_count":len(packets),
        "generator":"tools/generate_phase0_pcap.py", "license":"CC0-1.0",
        "provenance":"Original offline synthetic packet construction; no live capture or transmitted traffic.",
        "time_start_us":int(BASE*1000000),"time_end_us":int(packets[-1].time*1000000),
        "expected_telemetry":{"connection_records":68,"dns_records":40,"tcp_rejected":24,"tcp_unanswered":3,"tcp_normal":1,"dns_nxdomain":32},
        "ground_truth":[{"family":"vertical_tcp_scan","source_ip":"192.0.2.10","destination_ip":"192.0.2.20","distinct_ports":24},
                        {"family":"failed_tcp_connections","source_ip":"192.0.2.10","attempts":24,"failure_ratio":1.0},
                        {"family":"dns_nxdomain_burst","source_ip":"192.0.2.30","completed_responses":40,"nxdomain_ratio":0.8}],
        "limitations":["Development feasibility fixture, not independent detector evaluation.","Normal traffic is minimal; benign-counterexample corpus is a later phase.","Known indicator uses a separate contract fixture, not a live malicious endpoint."]}
    (DEST/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(f"Generated {len(packets)} offline packets: {path}")


if __name__ == "__main__":
    main()
