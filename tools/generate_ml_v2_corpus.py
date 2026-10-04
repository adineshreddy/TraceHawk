"""Fresh offline PCAP corpus; freeze inputs before fitting, never rewrite v1."""
from decimal import Decimal
from pathlib import Path
import hashlib, json, random, subprocess
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap
from generate_evaluation_corpus import ROOT, ZEEK

EXPERIMENT = ROOT / "evaluation/experiments/ml-v2"
CORPUS = ROOT / "evaluation/corpus"
BASE = 1791115200000000
BENIGN = ["web", "busy-dns", "mixed-failure", "outage", "stale-dns"]
ATTACK = ["fast-scan", "slow-scan", "horizontal", "denied", "dns-attack"]


def capture(index, split, kind, variant):
    name = f"v2-{split}-{kind}-{variant:02}"
    folder = CORPUS / name
    if folder.exists():
        raise RuntimeError(f"Refusing to overwrite {name}")
    (folder / "zeek").mkdir(parents=True)
    rng = random.Random(81000 + index)
    src = f"203.0.113.{20 + index}"
    dst = "198.51.100.22"
    packets, episodes, policies = [], [], []
    serial = 0

    def add(a, b, transport, t):
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=a, dst=b) / transport
        p.time = Decimal(BASE) / 1000000 + Decimal(str(t))
        packets.append(p)

    def tcp(t, port=443, target=dst, reject=False):
        nonlocal serial
        sport = 20000 + serial
        serial += 1
        add(src, target, TCP(sport=sport, dport=port, flags="S", seq=100), t)
        if reject:
            add(target, src, TCP(sport=port, dport=sport, flags="RA", ack=101), t + .01)
            return
        for j, (a, b, sp, dp, flags, seq, ack) in enumerate([
            (target, src, port, sport, "SA", 200, 101),
            (src, target, sport, port, "A", 101, 201),
            (src, target, sport, port, "FA", 101, 201),
            (target, src, port, sport, "FA", 201, 102),
            (src, target, sport, port, "A", 102, 202),
        ]):
            add(a, b, TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack), t + (j+1)*.004)

    def dns(t, i, nx=False, query=None):
        target = "198.51.100.53"
        q = DNSQR(qname=(query or f"www{i%13}.example.test") + ".")
        add(src, target, UDP(sport=45000+i, dport=53)/DNS(id=i, rd=1, qd=q), t)
        response = DNS(id=i, qr=1, rd=1, ra=1, rcode=3 if nx else 0, qd=q)
        if not nx:
            response.an = DNSRR(rrname=q.qname, ttl=60, rdata="198.51.100.8")
        add(target, src, UDP(sport=53, dport=45000+i)/response, t+.012)

    # Benign activity fills all five minutes and varies in intensity and timing.
    for i in range(35 + rng.randrange(45)):
        tcp(rng.uniform(1, 290), rng.choice([80,443,22,8080]),
            f"198.51.100.{22+rng.randrange(4)}",
            reject=rng.random() < (.18 if kind == "mixed-failure" else .025))
    for i in range(30 + rng.randrange(35)):
        dns(rng.uniform(1,290), i, rng.random() < .05)
    if kind == "busy-dns":
        for i in range(70, 170 + rng.randrange(40)):
            dns(rng.uniform(1,290), i, rng.random() < .07)
    if kind in ("outage", "denied"):
        n = 32 + rng.randrange(20)
        for i in range(n):
            tcp(90+i*.7, reject=True)
        if kind == "denied":
            episodes.append(("failed_tcp_connections", dst, 90, 90+(n-1)*.7+.01))
    if kind in ("stale-dns", "dns-attack"):
        n = 70 + rng.randrange(25)
        for i in range(n):
            dns(100+i*.28, 300+i, i < int(n*.86))
        if kind == "dns-attack":
            episodes.append(("dns_nxdomain_burst", None, 100, 100+(n-1)*.28))
    if kind in ("fast-scan", "slow-scan", "horizontal", "authorized"):
        n = (19+rng.randrange(5)) if kind == "slow-scan" else 44+rng.randrange(15)
        gap = 6.8 if kind == "slow-scan" else .38
        for i in range(n):
            tcp(65+i*gap, 443 if kind == "horizontal" else 7000+i,
                f"198.51.100.{70+i}" if kind == "horizontal" else dst)
        if kind == "authorized":
            policies.append(dict(detector_id="vertical_tcp_scan", source_ip=src, destination_ip=dst,
                reason="Authorized inventory, declared before scoring."))
        else:
            episodes.append(("horizontal_scan" if kind == "horizontal" else "vertical_tcp_scan",
                None if kind == "horizontal" else dst, 65, 65+(n-1)*gap+.02))
    if kind == "indicator":
        tcp(50, target="192.0.2.20")
        dns(55,600,query="host0.example.test")
        episodes += [("known_indicator","192.0.2.20",50,50.02), ("known_indicator",None,55,55)]
    tcp(299)
    packets.sort(key=lambda p:p.time)
    wrpcap(str(folder / "traffic.pcap"), packets)
    subprocess.run(["docker","run","--rm","--network","none","--cap-drop","ALL","--memory","128m",
        "-v",f"{folder}:/input:ro","-v",f'{folder/"zeek"}:/output',"-w","/output",ZEEK,
        "zeek","-r","/input/traffic.pcap","LogAscii::use_json=T"],check=True,capture_output=True)
    hashes = {k:hashlib.sha256((folder/"zeek"/f"{k}.log").read_bytes()).hexdigest() for k in ("conn","dns")}
    metadata = dict(scenario_id=name, split=split, input_mode="controlled_pcap", license="CC0-1.0",
        provenance="Original offline synthetic packets; pinned Zeek 8.0.10; no network transmission.",
        generator_seed=81000+index, time_start_us=BASE, time_end_us=BASE+300000000,
        folder=f"evaluation/corpus/{name}", source_ip=src, observed_host_hours=300/3600,
        pcap_sha256=hashlib.sha256((folder/"traffic.pcap").read_bytes()).hexdigest(), log_hashes=hashes,
        total=sum(len((folder/"zeek"/f"{k}.log").read_text().splitlines()) for k in hashes))
    (folder/"manifest.json").write_text(json.dumps(metadata,indent=2)+"\n")
    (folder/"labels.json").write_text(json.dumps(dict(context=kind, policies=policies,
        benign_explanation="Declared authorized maintenance or stale DNS, statistically confusable with attacks." if kind in ("outage","stale-dns") else None,
        episodes=[dict(detector_id=f,source_ip=src,destination_ip=d,start_us=BASE+int(a*1e6),end_us=BASE+int(b*1e6)) for f,d,a,b in episodes]),indent=2)+"\n")
    return name


def main():
    if (EXPERIMENT/"freeze.json").exists():
        raise SystemExit("V2 corpus already frozen; use prepare_ml_v2.py to verify.")
    cases = [("development-train",k,i) for k in BENIGN for i in range(8)]
    cases += [(s,k,i) for s in ("development-validation","held-out") for k in BENIGN+ATTACK for i in range(2)]
    cases += [("held-out","authorized",0),("held-out","indicator",0)]
    names=[]
    for index,(split,kind,variant) in enumerate(cases):
        names.append(capture(index,split,kind,variant))
        print(f"Generated {index+1}/{len(cases)}",flush=True)
    files={str(p.relative_to(CORPUS)):hashlib.sha256(p.read_bytes()).hexdigest()
        for name in names for p in sorted((CORPUS/name).rglob("*"))
        if p.is_file() and p.name in ("traffic.pcap","conn.log","dns.log","labels.json","manifest.json")}
    frozen = dict(version="synthetic-ml-v2", captures=names, files=files,
        protocol_sha256=hashlib.sha256((EXPERIMENT/"PROTOCOL.md").read_bytes()).hexdigest(),
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (EXPERIMENT/"freeze.json").write_text(json.dumps(frozen,indent=2)+"\n")


if __name__ == "__main__":
    main()
