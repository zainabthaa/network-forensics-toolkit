"""
cookies.py — detect session cookies and audit their security attributes.

Parses Set-Cookie headers from responses (attribute audit) and Cookie headers
from requests (reuse detection). Flags missing Secure / HttpOnly / SameSite and
reports any session token that is replayed in cleartext across requests.
"""
import re

SESSION_NAMES = {"phpsessid", "jsessionid", "sessionid", "session", "sid",
                 "asp.net_sessionid", "connect.sid", "sessid", "auth_token"}


def _is_session(name):
    return name.lower() in SESSION_NAMES or "session" in name.lower()


def _parse_set_cookie(value):
    parts = [p.strip() for p in value.split(";")]
    name, _, val = parts[0].partition("=")
    attrs = {p.split("=")[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
             for p in parts[1:]}
    return name.strip(), val.strip(), attrs


def detect(cap):
    cookies = {}            # name -> audit record
    token_requests = {}     # "name=value" -> count of requests carrying it

    # 1) audit Set-Cookie attributes from responses
    for tx in cap.transactions:
        resp = tx.response
        if not resp:
            continue
        raw = resp.headers.get("set-cookie")
        if not raw:
            continue
        for sc in (raw if isinstance(raw, list) else [raw]):
            name, val, attrs = _parse_set_cookie(sc)
            if not _is_session(name):
                continue
            rec = cookies.setdefault(name, {
                "name": name,
                "secure": False, "httponly": False, "samesite": None,
                "sample_value": val, "issues": [],
            })
            rec["secure"] = rec["secure"] or ("secure" in attrs)
            rec["httponly"] = rec["httponly"] or ("httponly" in attrs)
            if "samesite" in attrs:
                rec["samesite"] = attrs["samesite"]

    # 2) detect token reuse across requests (same value replayed in cleartext)
    for tx in cap.transactions:
        req = tx.request
        if not req:
            continue
        cookie_hdr = req.headers.get("cookie")
        if not cookie_hdr:
            continue
        for pair in cookie_hdr.split(";"):
            if "=" not in pair:
                continue
            name, val = pair.split("=", 1)
            name, val = name.strip(), val.strip()
            if _is_session(name):
                key = f"{name}={val}"
                token_requests[key] = token_requests.get(key, 0) + 1
                cookies.setdefault(name, {
                    "name": name, "secure": False, "httponly": False,
                    "samesite": None, "sample_value": val, "issues": [],
                })

    # 3) build issue list
    for name, rec in cookies.items():
        if not rec["secure"]:
            rec["issues"].append("Missing 'Secure' flag — cookie can be sent over plaintext HTTP")
        if not rec["httponly"]:
            rec["issues"].append("Missing 'HttpOnly' flag — cookie readable by JavaScript")
        if not rec["samesite"]:
            rec["issues"].append("No 'SameSite' attribute — cross-site request exposure")
        reuse = max([c for k, c in token_requests.items()
                     if k.startswith(rec["name"] + "=")] + [0])
        rec["reuse_count"] = reuse
        if reuse > 1:
            rec["issues"].append(
                f"Session token replayed in cleartext across {reuse} requests (replayable/hijackable)")

    return list(cookies.values())
