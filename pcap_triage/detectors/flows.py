"""
flows.py — network flow analysis & traffic profiling.

Characterises how the capture behaved as a network, not just what leaked:

 - flow_records:   bidirectional 5-tuple flows (NetFlow/IPFIX-style) with
                   per-direction packets/bytes, duration, TCP flags, handshake
                   and teardown state, and the HTTP requests carried.
 - endpoints:      top talkers (packets/bytes sent and received per host).
 - protocol_hierarchy: frame counts and bytes per protocol stack.
 - io_timeline:    packets/bytes per time bin (an IO graph) plus the number of
                   TCP connections open in each bin (browser parallelism).
 - profile:        all of the above plus summary statistics in one dict.

Everything is computed offline from the pcap with scapy.
"""
import csv
import datetime
from collections import defaultdict

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether

FLAG_NAMES = [("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"), ("U", "URG")]
WELL_KNOWN = {80: "HTTP", 8080: "HTTP", 8000: "HTTP", 443: "HTTPS", 8443: "HTTPS",
              53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP", 67: "DHCP", 68: "DHCP",
              123: "NTP", 5353: "mDNS", 137: "NetBIOS", 138: "NetBIOS"}


def _utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _l3(pk):
    return pk.getlayer(IP) or pk.getlayer(IPv6)


def _stack(pk):
    """Return a protocol-stack label such as 'Ethernet/IPv4/TCP/HTTP'."""
    parts = []
    layer = pk
    while layer and layer.name not in ("Raw", "Padding", "NoPayload"):
        name = {"IP": "IPv4", "Ether": "Ethernet"}.get(layer.name, layer.name)
        if name.startswith("ICMPv6"):
            parts.append("ICMPv6")
            break
        parts.append(name)
        layer = layer.payload
    if pk.haslayer(TCP):
        t = pk[TCP]
        app = WELL_KNOWN.get(int(t.dport)) or WELL_KNOWN.get(int(t.sport))
        if app and len(t.payload):
            parts.append(app)
    return "/".join(parts)


def _flow_key(src, sport, dst, dport, proto):
    """Canonical bidirectional key (order-independent)."""
    a, b = (src, sport), (dst, dport)
    return (proto,) + (a + b if a <= b else b + a)


def flow_records(cap):
    flows = {}
    for idx, pk in enumerate(cap.packets, start=1):
        l3 = _l3(pk)
        if l3 is None:
            continue
        if pk.haslayer(TCP):
            l4, proto = pk[TCP], "TCP"
        elif pk.haslayer(UDP):
            l4, proto = pk[UDP], "UDP"
        else:
            continue
        src, dst = l3.src, l3.dst
        sport, dport = int(l4.sport), int(l4.dport)
        ts = float(pk.time)
        size = len(pk)
        payload = len(l4.payload)
        key = _flow_key(src, sport, dst, dport, proto)
        f = flows.get(key)
        if f is None:
            # initiator = sender of the first packet (SYN for TCP)
            f = flows[key] = {
                "proto": proto, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
                "service": WELL_KNOWN.get(dport) or WELL_KNOWN.get(sport) or "",
                "start": ts, "end": ts, "first_frame": idx,
                "pkts_fwd": 0, "pkts_rev": 0, "bytes_fwd": 0, "bytes_rev": 0,
                "payload_fwd": 0, "payload_rev": 0,
                "flags": set(), "syn": False, "synack": False, "fin": False, "rst": False,
                "first_fin_by": None,
                "syn_ts": None, "synack_ts": None, "ack_ts": None,
                "first_payload_fwd": None, "first_payload_rev": None,
                "seen_seq": set(), "retrans": 0, "zero_win": 0,
                "opts_fwd": None, "opts_rev": None, "fin_fwd": None, "fin_rev": None, "last_payload": None,
            }
        fwd = (src == f["src_ip"] and sport == f["src_port"])
        d = "fwd" if fwd else "rev"
        f["pkts_" + d] += 1
        f["bytes_" + d] += size
        f["payload_" + d] += payload
        f["end"] = max(f["end"], ts)
        if proto == "TCP":
            fl = str(l4.flags)
            if payload:
                f["last_payload"] = ts
                if f["first_payload_" + d] is None:
                    f["first_payload_" + d] = ts
                sk = (d, int(l4.seq), payload)
                if sk in f["seen_seq"]:
                    f["retrans"] += 1
                f["seen_seq"].add(sk)
            if int(l4.window) == 0 and "R" not in fl:
                f["zero_win"] += 1
            if "S" in fl:
                o = dict((k, v) for k, v in l4.options if k in ("MSS", "WScale"))
                f["opts_" + d] = {"mss": o.get("MSS"), "wscale": o.get("WScale"),
                                  "window": int(l4.window), "ttl": getattr(l3, "ttl", getattr(l3, "hlim", None))}
                if "A" not in fl and f["syn_ts"] is None:
                    f["syn_ts"] = ts
                elif "A" in fl and f["synack_ts"] is None:
                    f["synack_ts"] = ts
            elif fl == "A" and f["synack_ts"] is not None and f["ack_ts"] is None and fwd:
                f["ack_ts"] = ts
            for ch, name in FLAG_NAMES:
                if ch in fl:
                    f["flags"].add(name)
            if "S" in fl and "A" not in fl:
                f["syn"] = True
            if "S" in fl and "A" in fl:
                f["synack"] = True
            if "F" in fl:
                f["fin"] = True
                if f["fin_" + d] is None:
                    f["fin_" + d] = (ts, int(l4.seq), int(l4.ack))
                if f["first_fin_by"] is None:
                    f["first_fin_by"] = "client" if fwd else "server"
            if "R" in fl:
                f["rst"] = True

    # attach HTTP requests carried by each TCP flow
    http_by_flow = defaultdict(list)
    http_status = defaultdict(list)
    for tx in getattr(cap, "transactions", []):
        if tx.request:
            k = _flow_key(tx.client_ip, tx.client_port, tx.server_ip, tx.server_port, "TCP")
            http_by_flow[k].append(" ".join(tx.request.start_line.split(" ")[:2]))
            if tx.response:
                http_status[k].append(" ".join(tx.response.start_line.split(" ")[1:2]))

    t0 = cap.first_time or (min(f["start"] for f in flows.values()) if flows else 0.0)
    out = []
    for i, (key, f) in enumerate(sorted(flows.items(), key=lambda kv: kv[1]["start"]), start=1):
        if f["proto"] == "TCP":
            handshake = "complete" if (f["syn"] and f["synack"]) else ("partial" if f["syn"] else "mid-stream")
            close = "RST" if f["rst"] else ("FIN" if f["fin"] else "open")
        else:
            handshake, close = "n/a", "n/a"
        reqs = http_by_flow.get(key, [])
        teardown = None
        if f["fin_fwd"] and f["fin_rev"]:
            first, second = sorted([f["fin_fwd"], f["fin_rev"]])
            teardown = "responsive" if second[2] == first[1] + 1 else "simultaneous"
        rtt = (f["synack_ts"] - f["syn_ts"]) if (f["syn_ts"] and f["synack_ts"]) else None
        setup = (f["ack_ts"] - f["syn_ts"]) if (f["syn_ts"] and f["ack_ts"]) else None
        ttfb = (f["first_payload_rev"] - f["first_payload_fwd"]) \
            if (f["first_payload_rev"] and f["first_payload_fwd"]) else None
        out.append({
            "flow_id": i,
            "proto": f["proto"], "service": f["service"],
            "src_ip": f["src_ip"], "src_port": f["src_port"],
            "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
            "start_utc": _utc(f["start"]), "end_utc": _utc(f["end"]),
            "rel_start": round(f["start"] - t0, 3), "rel_end": round(f["end"] - t0, 3),
            "duration_s": round(f["end"] - f["start"], 3),
            "packets": f["pkts_fwd"] + f["pkts_rev"],
            "bytes": f["bytes_fwd"] + f["bytes_rev"],
            "pkts_fwd": f["pkts_fwd"], "pkts_rev": f["pkts_rev"],
            "bytes_fwd": f["bytes_fwd"], "bytes_rev": f["bytes_rev"],
            "payload_fwd": f["payload_fwd"], "payload_rev": f["payload_rev"],
            "tcp_flags": "".join(ch for ch, n in FLAG_NAMES if n in f["flags"]),
            "handshake": handshake, "close": close,
            "closed_by": f["first_fin_by"] or ("n/a" if f["proto"] != "TCP" else "unknown"),
            "first_frame": f["first_frame"],
            "http_requests": reqs,
            "http_status": http_status.get(key, []),
            "handshake_rtt_ms": round(rtt * 1000, 3) if rtt is not None else None,
            "setup_ms": round(setup * 1000, 3) if setup is not None else None,
            "ttfb_ms": round(ttfb * 1000, 3) if ttfb is not None else None,
            "teardown": teardown,
            "idle_before_fin_s": round(min(x[0] for x in (f["fin_fwd"], f["fin_rev"]) if x)
                                       - max(t for t in (f["first_payload_fwd"], f["last_payload"]) if t), 3)
            if (f["fin_fwd"] or f["fin_rev"]) and f["last_payload"] else None,
            "retransmissions": f["retrans"], "zero_window": f["zero_win"],
            "client_opts": f["opts_fwd"], "server_opts": f["opts_rev"],
        })
    return out


def endpoints(cap):
    hosts = defaultdict(lambda: {"pkts_tx": 0, "pkts_rx": 0, "bytes_tx": 0, "bytes_rx": 0, "peers": set()})
    for pk in cap.packets:
        l3 = _l3(pk)
        if l3 is not None:
            src, dst = l3.src, l3.dst
        elif pk.haslayer(ARP):
            src, dst = pk[ARP].psrc, pk[ARP].pdst
        else:
            continue
        n = len(pk)
        hosts[src]["pkts_tx"] += 1; hosts[src]["bytes_tx"] += n; hosts[src]["peers"].add(dst)
        hosts[dst]["pkts_rx"] += 1; hosts[dst]["bytes_rx"] += n; hosts[dst]["peers"].add(src)
    total = sum(h["bytes_tx"] for h in hosts.values()) or 1
    out = []
    for ip, h in hosts.items():
        b = h["bytes_tx"] + h["bytes_rx"]
        out.append({"address": ip, "packets": h["pkts_tx"] + h["pkts_rx"], "bytes": b,
                    "pkts_tx": h["pkts_tx"], "pkts_rx": h["pkts_rx"],
                    "bytes_tx": h["bytes_tx"], "bytes_rx": h["bytes_rx"],
                    "share_pct": round(100.0 * h["bytes_tx"] / total, 1),
                    "peers": len(h["peers"])})
    out.sort(key=lambda r: -r["bytes"])
    return out


def protocol_hierarchy(cap):
    stacks = defaultdict(lambda: {"frames": 0, "bytes": 0})
    for pk in cap.packets:
        s = _stack(pk)
        stacks[s]["frames"] += 1
        stacks[s]["bytes"] += len(pk)
    n = len(cap.packets) or 1
    out = [{"stack": k, "frames": v["frames"], "bytes": v["bytes"],
            "pct_frames": round(100.0 * v["frames"] / n, 1)} for k, v in stacks.items()]
    out.sort(key=lambda r: -r["frames"])
    return out


def io_timeline(cap, flows, bin_s=None):
    if not cap.packets:
        return {"bin_s": 1, "bins": []}
    t0 = float(cap.packets[0].time)
    span = max(float(cap.last_time or cap.packets[-1].time) - t0, 0.001)
    if bin_s is None:                        # aim for ~60-120 bins
        bin_s = max(1, int(round(span / 90)))
    nbins = int(span // bin_s) + 1
    bins = [{"t": i * bin_s, "packets": 0, "bytes": 0, "open_conns": 0, "new_conns": 0}
            for i in range(nbins)]
    for pk in cap.packets:
        i = min(int((float(pk.time) - t0) // bin_s), nbins - 1)
        bins[i]["packets"] += 1
        bins[i]["bytes"] += len(pk)
    for f in flows:
        if f["proto"] != "TCP":
            continue
        a = min(int(f["rel_start"] // bin_s), nbins - 1)
        b = min(int(f["rel_end"] // bin_s), nbins - 1)
        bins[a]["new_conns"] += 1
        for i in range(a, b + 1):
            bins[i]["open_conns"] += 1
    for b in bins:
        b["throughput_bps"] = round(8.0 * b["bytes"] / bin_s, 1)
    return {"bin_s": bin_s, "bins": bins}


def _svg_geometry(flows, timeline, span):
    """Pre-compute coordinates for the HTML IO graph and flow-timeline charts."""
    W = 860
    bins = timeline["bins"]
    peak = max((b["bytes"] for b in bins), default=0) or 1
    bw = W / max(len(bins), 1)
    io = [{"x": round(i * bw, 2), "w": round(max(bw - 1, 1), 2),
           "h": round(110.0 * b["bytes"] / peak, 2), "t": b["t"], "bytes": b["bytes"],
           "packets": b["packets"], "open": b["open_conns"]} for i, b in enumerate(bins)]
    tcp = [f for f in flows if f["proto"] == "TCP"]
    span = span or 1
    lanes = [{"y": 18 * i, "x": round(W * f["rel_start"] / span, 2),
              "w": round(max(W * f["duration_s"] / span, 2), 2),
              "label": f"{f['src_port']}→{f['dst_port']}",
              "close": f["close"], "flow_id": f["flow_id"],
              "reqs": f["http_requests"]} for i, f in enumerate(tcp)]
    ticks = []
    step = max(10, int(round(span / 8 / 10.0)) * 10)
    t = 0
    while t <= span:
        ticks.append({"x": round(W * t / span, 2), "t": t})
        t += step
    return {"width": W, "io": io, "io_peak_bytes": peak, "lanes": lanes,
            "lanes_height": 18 * len(lanes), "ticks": ticks}


def _ladder_geometry(events, l2):
    """Coordinates for a two-lane sequence diagram (client left, server right)."""
    cli = next((h["ips"][0] for h in l2 if h["role"] == "client" and h["ips"]), None)
    srv = next((h["ips"][0] for h in l2 if h["role"] == "web server" and h["ips"]), None)
    rows = []
    y = 40
    for e in events:
        if e["kind"] == "fin":
            continue
        right = e["src"] == cli
        rows.append({"y": y, "t": e["t"], "label": e["label"], "kind": e["kind"], "to_server": right,
                     "port": e["sport"] if right else e["dport"]})
        y += 20
    return {"client": cli, "server": srv, "rows": rows, "height": y + 10}


def profile(cap):
    flows = flow_records(cap)
    eps = endpoints(cap)
    phs = protocol_hierarchy(cap)
    tl = io_timeline(cap, flows)
    span = round((cap.last_time - cap.first_time), 3) if cap.packets else 0.0
    tcp = [f for f in flows if f["proto"] == "TCP"]
    total_bytes = sum(len(p) for p in cap.packets)
    peak_bin = max(tl["bins"], key=lambda b: b["bytes"]) if tl["bins"] else None
    summary = {
        "duration_s": span,
        "total_packets": len(cap.packets),
        "total_bytes": total_bytes,
        "avg_throughput_bps": round(8.0 * total_bytes / span, 1) if span else 0.0,
        "peak_throughput_bps": peak_bin["throughput_bps"] if peak_bin else 0.0,
        "peak_at_s": peak_bin["t"] if peak_bin else 0,
        "flow_count": len(flows),
        "tcp_flows": len(tcp),
        "udp_flows": sum(1 for f in flows if f["proto"] == "UDP"),
        "complete_handshakes": sum(1 for f in tcp if f["handshake"] == "complete"),
        "closed_fin": sum(1 for f in tcp if f["close"] == "FIN"),
        "closed_rst": sum(1 for f in tcp if f["close"] == "RST"),
        "left_open": sum(1 for f in tcp if f["close"] == "open"),
        "max_parallel_conns": max((b["open_conns"] for b in tl["bins"]), default=0),
        "flows_with_http": sum(1 for f in tcp if f["http_requests"]),
        "max_requests_per_flow": max((len(f["http_requests"]) for f in tcp), default=0),
        "mean_flow_duration_s": round(sum(f["duration_s"] for f in tcp) / len(tcp), 3) if tcp else 0.0,
        "mean_flow_bytes": round(sum(f["bytes"] for f in tcp) / len(tcp), 1) if tcp else 0.0,
        "host_count": len(eps),
    }
    summary["server_closed"] = sum(1 for f in tcp if f["closed_by"] == "server")
    summary["simultaneous_close"] = sum(1 for f in tcp if f.get("teardown") == "simultaneous")
    idle = sorted(f["idle_before_fin_s"] for f in tcp if f.get("idle_before_fin_s") is not None)
    summary["idle_before_fin_s"] = {"min": idle[0], "max": idle[-1]} if idle else None
    convs = conversations(cap)
    l2 = l2_inventory(cap)
    plen = packet_lengths(cap)
    health = tcp_health(flows)
    act = activity(flows)
    lad = ladder(cap)
    ctx = {"l2": l2, "plen": plen, "health": health, "activity": act}
    return {"summary": summary, "insights": insights(summary, flows, eps, ctx), "flows": flows,
            "conversations": convs, "l2_inventory": l2, "packet_lengths": plen,
            "tcp_health": health, "activity": act, "ladder": lad,
            "ladder_chart": _ladder_geometry(lad, l2), "endpoints": eps,
            "protocol_hierarchy": phs, "io": tl, "chart": _svg_geometry(flows, tl, span)}


def insights(summary, flows, eps, ctx=None):
    """Plain-language observations an analyst would draw from the profile."""
    out = []
    tcp = [f for f in flows if f["proto"] == "TCP"]
    if not tcp:
        return out
    total = sum(f["bytes"] for f in tcp) or 1
    durs = sorted(f["duration_s"] for f in tcp)
    med = durs[len(durs) // 2]
    tight = sum(1 for d in durs if abs(d - med) <= 0.25)
    idle = summary.get("idle_before_fin_s")
    if len(durs) >= 3 and tight >= 0.8 * len(durs):
        extra = ""
        if idle:
            extra = (f" Every connection is closed {idle['min']:.2f}–{idle['max']:.2f}s after its last data packet; "
                     f"in {summary.get('simultaneous_close', 0)} flows both FINs cross on the wire (simultaneous close), "
                     f"so client and server time out together.")
        out.append(f"{tight}/{len(tcp)} TCP flows last ~{med:.1f}s from SYN to FIN regardless of how much data "
                   f"they carry: connection lifetime is set by the HTTP keep-alive idle timeout "
                   f"(about {round(med)}s), not by user activity." + extra)
    up = sum(f["bytes_fwd"] for f in tcp); down = sum(f["bytes_rev"] for f in tcp)
    if up + down:
        out.append(f"Traffic is strongly asymmetric: {round(100.0 * down / (up + down), 1)}% of bytes flow "
                   f"server-to-client (page and image downloads), {round(100.0 * up / (up + down), 1)}% client-to-server.")
    big = sorted(tcp, key=lambda f: -f["bytes"])[:2]
    share = round(100.0 * sum(f["bytes"] for f in big) / total, 1)
    if share >= 50:
        out.append(f"The two largest flows (#{big[0]['flow_id']}, #{big[1]['flow_id']}) carry {share}% of all TCP bytes: "
                   + "; ".join(", ".join(f["http_requests"]) or "no HTTP" for f in big) + ".")
    if summary["max_parallel_conns"] > 1:
        out.append(f"The browser opened up to {summary['max_parallel_conns']} parallel TCP connections "
                   f"(peak at ~{summary['peak_at_s']}s) to fetch embedded resources concurrently.")
    if summary["max_requests_per_flow"] > 1:
        out.append(f"Connections are reused for up to {summary['max_requests_per_flow']} requests "
                   f"(HTTP/1.1 persistent connections).")
    if summary["complete_handshakes"] == len(tcp) and summary["closed_rst"] == 0:
        out.append("Every TCP flow has a complete three-way handshake and an orderly FIN teardown; "
                   "no resets, scans or half-open connections were observed.")
    clear = sum(f["bytes"] for f in tcp if f["service"] == "HTTP")
    if clear == total:
        out.append("100% of TCP flows are cleartext HTTP on port 80; no flow is encrypted.")
    if ctx:
        srv = next((h for h in ctx["l2"] if h["role"] == "web server"), None)
        cli = next((h for h in ctx["l2"] if h["role"] == "client"), None)
        if srv and cli and srv["hops_away"] and not cli["hops_away"]:
            out.append(f"The server's packets arrive with TTL {srv['observed_ttl']} while the client's leave with "
                       f"{cli['observed_ttl']}: both look like Linux (initial TTL 64), but the server sits "
                       f"{srv['hops_away']} routed hop away despite sharing the subnet, consistent with DVWA running "
                       f"in a container behind the VM's bridge.")
        if all(h["locally_administered"] for h in ctx["l2"]):
            out.append("Every MAC address is locally administered (randomised/virtual), as expected for VM "
                       "network adapters; no vendor OUI is present.")
        ras = [h for h in ctx["l2"] if h["nd_frames"]]
        if ras:
            out.append(f"A third device ({ras[0]['mac']}) only sends IPv6 router advertisements to ff02::1: "
                       f"the hypervisor's virtual-network gateway, not a participant in the session.")
        pl = ctx["plen"]
        if pl["over_mtu_frames"]:
            out.append(f"{pl['over_mtu_frames']} frames are larger than the 1,514-byte Ethernet MTU (up to "
                       f"{pl['max']:,} B): an artefact of segmentation offload (GRO/LRO) on the capturing NIC, "
                       f"not jumbo frames on the wire. Byte counts are right; per-frame counts are understated.")
        h = ctx["health"]
        if h["handshake_rtt_ms"]:
            out.append(f"TCP health is clean: handshake RTT {h['handshake_rtt_ms']['min']}–{h['handshake_rtt_ms']['max']} ms "
                       f"(median {h['handshake_rtt_ms']['median']} ms), {h['retransmissions']} retransmissions, "
                       f"{h['zero_window']} zero-window events. The slowest server response is "
                       f"{h['slowest_responses'][0]['request']} at {h['slowest_responses'][0]['ttfb_ms']} ms.")
        a = ctx["activity"]
        if a["bursts"]:
            out.append(f"Separated by idle gaps of ≥{a['gap_threshold_s']:.0f}s, the session forms "
                       f"{len(a['bursts'])} activity bursts; the median time between new connections is "
                       f"{a['inter_flow_start_s']['median']}s, a human browsing pace rather than automated traffic.")
    real = [e for e in eps if not e["address"].startswith(("fe80:", "ff02:"))]
    if len(real) <= 2:
        out.append(f"Only {len(real)} IPv4 hosts exchange application traffic; the remaining frames are "
                   f"link-local ARP / IPv6 neighbour-discovery noise.")
    return out


# ---------------------------------------------------------------------------
# whole-network profiling
# ---------------------------------------------------------------------------

def _locally_administered(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _guess_initial_ttl(ttl):
    for base in (64, 128, 255):
        if ttl is not None and ttl <= base:
            return base
    return None


def conversations(cap):
    """Wireshark-style conversation tables at layer 2 (MAC) and layer 3 (IP)."""
    l2 = defaultdict(lambda: {"frames": 0, "bytes": 0, "first": None, "last": None, "a_to_b": 0, "b_to_a": 0})
    l3 = defaultdict(lambda: {"frames": 0, "bytes": 0, "first": None, "last": None, "a_to_b": 0, "b_to_a": 0, "protos": set()})
    t0 = float(cap.packets[0].time) if cap.packets else 0.0

    def add(table, a, b, pk, proto=None):
        key = tuple(sorted((a, b)))
        c = table[key]
        ts = float(pk.time) - t0
        c["frames"] += 1
        c["bytes"] += len(pk)
        c["first"] = ts if c["first"] is None else c["first"]
        c["last"] = ts
        c["a_to_b" if a == key[0] else "b_to_a"] += len(pk)
        if proto and "protos" in c:
            c["protos"].add(proto)

    for pk in cap.packets:
        if pk.haslayer(Ether):
            add(l2, pk[Ether].src, pk[Ether].dst, pk)
        l3l = _l3(pk)
        if l3l is not None:
            proto = "TCP" if pk.haslayer(TCP) else "UDP" if pk.haslayer(UDP) else "ICMPv6" if isinstance(l3l, IPv6) else "IP"
            add(l3, l3l.src, l3l.dst, pk, proto)

    def rows(table, kind):
        out = []
        for (a, b), c in table.items():
            dur = (c["last"] - c["first"]) if c["first"] is not None else 0.0
            out.append({"layer": kind, "a": a, "b": b, "frames": c["frames"], "bytes": c["bytes"],
                        "bytes_a_to_b": c["a_to_b"], "bytes_b_to_a": c["b_to_a"],
                        "rel_start": round(c["first"] or 0.0, 3), "duration_s": round(dur, 3),
                        "bps": round(8.0 * c["bytes"] / dur, 1) if dur > 0 else 0.0,
                        "protocols": sorted(c.get("protos", []))})
        out.sort(key=lambda r: -r["bytes"])
        return out

    return {"ethernet": rows(l2, "Ethernet"), "ip": rows(l3, "IP")}


def l2_inventory(cap):
    """Map every MAC address to the IPs it used, its TTL and what it said."""
    hosts = {}
    for pk in cap.packets:
        if not pk.haslayer(Ether):
            continue
        mac = pk[Ether].src
        h = hosts.setdefault(mac, {"mac": mac, "ips": set(), "frames": 0, "ttls": set(),
                                   "arp": 0, "nd": 0, "tcp_ports": set()})
        h["frames"] += 1
        if pk.haslayer(ARP):
            h["arp"] += 1
            h["ips"].add(pk[ARP].psrc)
        l3l = _l3(pk)
        if l3l is not None:
            h["ips"].add(l3l.src)
            ttl = getattr(l3l, "ttl", None)
            if ttl is None:
                ttl = getattr(l3l, "hlim", None)
            if ttl is not None and not isinstance(l3l, IPv6):
                h["ttls"].add(int(ttl))
            if isinstance(l3l, IPv6) and "ICMPv6" in pk.lastlayer().name or pk.haslayer("ICMPv6ND_RA"):
                h["nd"] += 1
        if pk.haslayer(TCP):
            h["tcp_ports"].add(int(pk[TCP].sport))
    out = []
    for h in hosts.values():
        ttl = min(h["ttls"]) if h["ttls"] else None
        init = _guess_initial_ttl(ttl)
        hops = (init - ttl) if (ttl is not None and init) else None
        if 80 in h["tcp_ports"] or 443 in h["tcp_ports"]:
            role = "web server"
        elif h["tcp_ports"]:
            role = "client"
        elif h["nd"]:
            role = "IPv6 router advertiser (virtual-network gateway)"
        else:
            role = "other"
        out.append({"mac": h["mac"], "ips": sorted(h["ips"]), "frames": h["frames"],
                    "locally_administered": _locally_administered(h["mac"]),
                    "observed_ttl": ttl, "initial_ttl_guess": init, "hops_away": hops,
                    "os_family_guess": ("Linux/Unix" if init == 64 else "Windows" if init == 128
                                        else "Network device" if init == 255 else None),
                    "arp_frames": h["arp"], "nd_frames": h["nd"], "role": role})
    out.sort(key=lambda r: -r["frames"])
    return out


LEN_BUCKETS = [(0, 79), (80, 159), (160, 319), (320, 639), (640, 1279), (1280, 1514), (1515, 9999), (10000, 10 ** 9)]


def packet_lengths(cap):
    n = len(cap.packets) or 1
    rows = []
    for lo, hi in LEN_BUCKETS:
        sizes = [len(p) for p in cap.packets if lo <= len(p) <= hi]
        label = f"{lo}–{hi}" if hi < 10 ** 9 else f"≥{lo}"
        rows.append({"range": label, "frames": len(sizes), "pct": round(100.0 * len(sizes) / n, 1),
                     "bytes": sum(sizes)})
    sizes = sorted(len(p) for p in cap.packets)
    jumbo = sum(1 for x in sizes if x > 1514)
    return {"buckets": rows, "min": sizes[0] if sizes else 0, "max": sizes[-1] if sizes else 0,
            "median": sizes[len(sizes) // 2] if sizes else 0,
            "mean": round(sum(sizes) / len(sizes), 1) if sizes else 0.0,
            "over_mtu_frames": jumbo}


def tcp_health(flows):
    tcp = [f for f in flows if f["proto"] == "TCP"]
    rtts = sorted(f["handshake_rtt_ms"] for f in tcp if f["handshake_rtt_ms"] is not None)
    ttfb = sorted(f["ttfb_ms"] for f in tcp if f["ttfb_ms"] is not None)

    def stats(xs):
        if not xs:
            return None
        return {"min": xs[0], "median": xs[len(xs) // 2], "max": xs[-1],
                "mean": round(sum(xs) / len(xs), 3)}
    copts = next((f["client_opts"] for f in tcp if f["client_opts"]), None)
    sopts = next((f["server_opts"] for f in tcp if f["server_opts"]), None)
    slow = sorted((f for f in tcp if f["ttfb_ms"] is not None), key=lambda f: -f["ttfb_ms"])[:3]
    return {"handshake_rtt_ms": stats(rtts), "ttfb_ms": stats(ttfb),
            "retransmissions": sum(f["retransmissions"] for f in tcp),
            "zero_window": sum(f["zero_window"] for f in tcp),
            "client_syn_options": copts, "server_synack_options": sopts,
            "slowest_responses": [{"flow_id": f["flow_id"], "ttfb_ms": f["ttfb_ms"],
                                   "request": (f["http_requests"] or [""])[0]} for f in slow]}


def activity(flows, gap_s=10.0):
    """Split the session into activity bursts separated by idle gaps of at least gap_s."""
    tcp = sorted((f for f in flows if f["proto"] == "TCP"), key=lambda f: f["rel_start"])
    bursts, cur, gaps = [], None, []
    last_end = None
    for f in tcp:
        if last_end is not None:
            gaps.append(round(f["rel_start"] - last_end, 3))
        if cur is None or f["rel_start"] - cur["end"] >= gap_s:
            if cur:
                bursts.append(cur)
            cur = {"start": f["rel_start"], "end": f["rel_end"], "flows": [], "requests": []}
        cur["end"] = max(cur["end"], f["rel_end"])
        cur["flows"].append(f["flow_id"])
        cur["requests"] += f["http_requests"]
        last_end = f["rel_end"]
    if cur:
        bursts.append(cur)
    starts = [f["rel_start"] for f in tcp]
    think = sorted(round(b - a, 3) for a, b in zip(starts, starts[1:]))
    return {"gap_threshold_s": gap_s, "bursts": [
        {"id": i + 1, "start": round(b["start"], 1), "end": round(b["end"], 1),
         "flows": b["flows"], "requests": b["requests"]} for i, b in enumerate(bursts)],
        "inter_flow_start_s": {"min": think[0], "median": think[len(think) // 2], "max": think[-1]} if think else None}


def ladder(cap, client=None, server=None):
    """Session flow graph: every HTTP request/response line between the two main hosts, in time order."""
    t0 = float(cap.packets[0].time) if cap.packets else 0.0
    events = []
    ports = {}
    for pk in cap.packets:
        if not (pk.haslayer(TCP) and _l3(pk) is not None):
            continue
        t = pk[TCP]
        l3l = _l3(pk)
        flags = str(t.flags)
        pl = bytes(t.payload)
        label = None
        if "S" in flags and "A" not in flags:
            label, kind = f"SYN :{int(t.sport)}", "syn"
        elif pl.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
            line = pl.split(b"\r\n", 1)[0].decode("latin1")
            m, u = (line.split(" ") + ["", ""])[:2]
            label, kind = f"{m} {u}", "request"
        elif pl.startswith(b"HTTP/"):
            line = pl.split(b"\r\n", 1)[0].decode("latin1")
            label, kind = line.split(" ", 1)[1] if " " in line else line, "response"
        elif "F" in flags and ports.get((l3l.src, int(t.sport), "fin")) is None:
            ports[(l3l.src, int(t.sport), "fin")] = 1
            label, kind = "FIN", "fin"
        if label is None:
            continue
        events.append({"t": round(float(pk.time) - t0, 3), "src": l3l.src, "dst": l3l.dst,
                       "sport": int(t.sport), "dport": int(t.dport), "label": label[:48], "kind": kind})
    return events


NETFLOW_FIELDS = ["flow_id", "start_utc", "end_utc", "duration_s", "proto", "src_ip", "src_port",
                  "dst_ip", "dst_port", "service", "packets", "bytes", "pkts_fwd", "pkts_rev",
                  "bytes_fwd", "bytes_rev", "tcp_flags", "handshake", "close", "closed_by", "http_requests"]


def write_netflow_csv(flows, path):
    """Write NetFlow-style flow records (one row per bidirectional flow)."""
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=NETFLOW_FIELDS, extrasaction="ignore")
        w.writeheader()
        for f in flows:
            row = dict(f)
            row["http_requests"] = " | ".join(f["http_requests"])
            w.writerow(row)
