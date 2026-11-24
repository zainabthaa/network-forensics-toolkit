"""
pcap_http.py — reassemble TCP streams from a pcap and parse HTTP messages.

The capture is read with scapy (no external tools such as tshark required).
Each TCP stream is reassembled per-direction by sequence number, then the
reassembled byte stream is split into HTTP/1.x messages using Content-Length.
Requests and responses within a keep-alive connection are paired by order.
"""
from dataclasses import dataclass, field
from scapy.all import rdpcap, IP, IPv6, TCP, Raw

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


@dataclass
class HttpMessage:
    start_line: str
    headers: dict
    body: bytes
    frame: int = 0


@dataclass
class HttpTransaction:
    stream_id: int
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    request: HttpMessage = None
    response: HttpMessage = None


@dataclass
class Capture:
    packets: list
    transactions: list = field(default_factory=list)
    http_bytes: int = 0        # TCP payload bytes on HTTP ports (cleartext)
    https_bytes: int = 0       # TCP payload bytes on TLS ports (encrypted)
    total_tcp_bytes: int = 0
    first_time: float = 0.0
    last_time: float = 0.0


HTTP_PORTS = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}


def _reassemble(segments):
    """segments: list of (seq, payload). Return the reassembled byte string."""
    if not segments:
        return b""
    segments = sorted(segments, key=lambda s: s[0])
    out = bytearray()
    next_seq = segments[0][0]
    for seq, payload in segments:
        if not payload:
            continue
        if seq < next_seq:                      # overlap / retransmission
            payload = payload[next_seq - seq:]
            seq = next_seq
        if seq > next_seq:                      # gap — accept what we have
            next_seq = seq
        out += payload
        next_seq = seq + len(payload)
    return bytes(out)


def _parse_http(data, is_request):
    """Split a reassembled byte stream into HTTP messages."""
    messages = []
    while data:
        marker = data.find(b"\r\n\r\n")
        if marker == -1:
            break
        header_blob = data[:marker]
        rest = data[marker + 4:]
        lines = header_blob.split(b"\r\n")
        start = lines[0]
        if is_request and not start.startswith(HTTP_METHODS):
            break
        if not is_request and not start.startswith(b"HTTP/"):
            break
        headers = {}
        for h in lines[1:]:
            if b":" in h:
                k, v = h.split(b":", 1)
                key = k.strip().lower().decode("latin1")
                val = v.strip().decode("latin1")
                # preserve duplicate Set-Cookie headers as a list
                if key in headers:
                    if isinstance(headers[key], list):
                        headers[key].append(val)
                    else:
                        headers[key] = [headers[key], val]
                else:
                    headers[key] = val
        clen_raw = headers.get("content-length", "0")
        clen = int(clen_raw) if str(clen_raw).isdigit() else 0
        body = rest[:clen]
        data = rest[clen:]
        messages.append(HttpMessage(start.decode("latin1"), headers, body))
    return messages


def load_capture(path):
    pkts = rdpcap(path)
    cap = Capture(packets=pkts)
    times = []
    streams = {}  # key -> {"c2s": [...], "s2c": [...], meta}

    for pk in pkts:
        times.append(float(pk.time))
        if not pk.haslayer(TCP):
            continue
        t = pk[TCP]
        ipl = pk.getlayer(IP) or pk.getlayer(IPv6)
        if ipl is None:
            continue
        src, dst = ipl.src, ipl.dst
        sport, dport = int(t.sport), int(t.dport)
        payload = bytes(t[Raw].load) if pk.haslayer(Raw) else b""
        cap.total_tcp_bytes += len(payload)
        if sport in HTTP_PORTS or dport in HTTP_PORTS:
            cap.http_bytes += len(payload)
        elif sport in HTTPS_PORTS or dport in HTTPS_PORTS:
            cap.https_bytes += len(payload)

        # identify server side as the HTTP port end
        if dport in HTTP_PORTS:
            server_ip, server_port, client_ip, client_port, direction = dst, dport, src, sport, "c2s"
        elif sport in HTTP_PORTS:
            server_ip, server_port, client_ip, client_port, direction = src, sport, dst, dport, "s2c"
        else:
            continue  # not HTTP — skip for parsing

        key = (client_ip, client_port, server_ip, server_port)
        s = streams.setdefault(key, {"c2s": [], "s2c": [],
                                     "client_ip": client_ip, "client_port": client_port,
                                     "server_ip": server_ip, "server_port": server_port})
        if payload:
            s[direction].append((int(t.seq), payload))

    cap.first_time = min(times) if times else 0.0
    cap.last_time = max(times) if times else 0.0

    # parse each stream, pair requests with responses in order
    for sid, (key, s) in enumerate(streams.items()):
        requests = _parse_http(_reassemble(s["c2s"]), is_request=True)
        responses = _parse_http(_reassemble(s["s2c"]), is_request=False)
        for i, req in enumerate(requests):
            resp = responses[i] if i < len(responses) else None
            cap.transactions.append(HttpTransaction(
                stream_id=sid,
                client_ip=s["client_ip"], server_ip=s["server_ip"],
                client_port=s["client_port"], server_port=s["server_port"],
                request=req, response=resp,
            ))
    return cap
