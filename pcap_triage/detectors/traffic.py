"""
traffic.py — traffic-composition detectors.

 - encryption_ratio: cleartext (HTTP) vs encrypted (HTTPS/TLS) payload bytes.
 - endpoints: inventory of HTTP endpoints, methods, and submitted form fields.
"""
from urllib.parse import parse_qsl


def encryption_ratio(cap):
    cleartext = cap.http_bytes
    encrypted = cap.https_bytes
    total = cleartext + encrypted
    pct = (100.0 * cleartext / total) if total else 0.0
    return {
        "cleartext_bytes": cleartext,
        "encrypted_bytes": encrypted,
        "cleartext_pct": round(pct, 1),
        "verdict": "ALL traffic is unencrypted" if encrypted == 0 and cleartext > 0
                   else f"{round(pct, 1)}% of application traffic is cleartext",
    }


def endpoints(cap):
    inv = {}
    for tx in cap.transactions:
        req = tx.request
        if not req:
            continue
        parts = req.start_line.split(" ")
        if len(parts) < 2:
            continue
        method, uri = parts[0], parts[1]
        path = uri.split("?")[0]
        key = (method, path)
        rec = inv.setdefault(key, {"method": method, "path": path, "count": 0,
                                   "form_fields": set(), "status": set()})
        rec["count"] += 1
        if method == "POST" and "urlencoded" in (req.headers.get("content-type") or ""):
            try:
                for k, _ in parse_qsl(req.body.decode("latin1"), keep_blank_values=True):
                    rec["form_fields"].add(k)
            except Exception:
                pass
        if tx.response:
            code = tx.response.start_line.split(" ")
            if len(code) > 1:
                rec["status"].add(code[1])
    out = []
    for rec in inv.values():
        rec["form_fields"] = sorted(rec["form_fields"])
        rec["status"] = sorted(rec["status"])
        out.append(rec)
    out.sort(key=lambda r: (-r["count"], r["path"]))
    return out
