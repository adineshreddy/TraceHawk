"""Capture-time source windows; labels and addresses never become model features."""

FEATURES = [
    "connections",
    "distinct_destinations",
    "distinct_tcp_ports",
    "failure_ratio",
    "completed_dns",
    "nxdomain_ratio",
    "outgoing_bytes",
    "missing_tcp_ratio",
    "missing_dns_ratio",
]
STEP = 60000000
BUCKET = 300000000


def extract(events, manifest):
    src = manifest["source_ip"]
    start = manifest["time_start_us"]
    end = manifest["time_end_us"]
    output = []
    for t in range(start, end, STEP):
        rows = [
            e
            for e in events
            if e["source_ip"] == src and t <= e["event_time_us"] < t + STEP
        ]
        conns = [e for e in rows if e["event_kind"] == "connection"]
        tcp = [
            e
            for e in conns
            if e["protocol"] == "tcp" and e["connection"]["state"] not in (None, "OTH")
        ]
        dns = [
            e
            for e in rows
            if e["event_kind"] == "dns" and e["dns"]["rcode"] is not None
        ]
        values = [
            len(conns),
            len({e["destination_ip"] for e in conns}),
            len({e["destination_port"] for e in tcp}),
            (
                sum(e["connection"]["state"] in ("S0", "REJ") for e in tcp) / len(tcp)
                if tcp
                else 0
            ),
            len(dns),
            sum(e["dns"]["rcode"] == 3 for e in dns) / len(dns) if dns else 0,
            sum(e["connection"]["orig_bytes"] or 0 for e in conns),
            int(not tcp),
            int(not dns),
        ]
        output.append(
            {
                "capture": manifest["scenario_id"],
                "source_ip": src,
                "window_start_us": t,
                "bucket_start_us": t // BUCKET * BUCKET,
                "values": values,
            }
        )
    return output
