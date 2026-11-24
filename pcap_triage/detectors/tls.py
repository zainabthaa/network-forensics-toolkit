"""
tls.py — TLS awareness (no decryption).

Parses TLS ClientHello records to recover the negotiated version and the
SNI (server name) of each encrypted session. This lets the tool report what
*was* encrypted even though it cannot read it — and, by contrast, highlight
how much of the capture was cleartext.
"""
from scapy.all import TCP, Raw, IP, IPv6

TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def _parse_client_hello(data):
    """Return (version_str, sni) from a TLS record if it is a ClientHello."""
    try:
        if len(data) < 6 or data[0] != 0x16:        # 0x16 = handshake record
            return None
        if data[5] != 0x01:                          # 0x01 = ClientHello
            return None
        # skip: record hdr(5) + hs type(1) + hs len(3) + client version(2) + random(32)
        i = 5 + 1 + 3 + 2 + 32
        sid_len = data[i]; i += 1 + sid_len          # session id
        cs_len = int.from_bytes(data[i:i + 2], "big"); i += 2 + cs_len   # cipher suites
        comp_len = data[i]; i += 1 + comp_len        # compression methods
        if i + 2 > len(data):
            return (TLS_VERSIONS.get(int.from_bytes(data[9:11], "big"), "TLS"), None)
        ext_len = int.from_bytes(data[i:i + 2], "big"); i += 2
        end = min(len(data), i + ext_len)
        sni = None
        while i + 4 <= end:
            etype = int.from_bytes(data[i:i + 2], "big")
            elen = int.from_bytes(data[i + 2:i + 4], "big")
            body = data[i + 4:i + 4 + elen]
            if etype == 0x0000 and len(body) >= 5:   # server_name
                nlen = int.from_bytes(body[3:5], "big")
                sni = body[5:5 + nlen].decode("latin1", "ignore")
            i += 4 + elen
        ver = TLS_VERSIONS.get(int.from_bytes(data[9:11], "big"), "TLS")
        return (ver, sni)
    except Exception:
        return None


def detect(cap):
    sessions = []
    seen = set()
    for pk in cap.packets:
        if not pk.haslayer(TCP) or not pk.haslayer(Raw):
            continue
        res = _parse_client_hello(bytes(pk[Raw].load))
        if not res:
            continue
        ver, sni = res
        ipl = pk.getlayer(IP) or pk.getlayer(IPv6)
        dst = ipl.dst if ipl else "?"
        key = (dst, sni)
        if key in seen:
            continue
        seen.add(key)
        sessions.append({"server": dst, "port": int(pk[TCP].dport), "version": ver, "sni": sni})
    return {"tls_sessions": sessions, "encrypted_session_count": len(sessions)}
