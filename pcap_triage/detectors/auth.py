"""
auth.py — detect authentication artifacts beyond form credentials.

 - HTTP Basic authentication  (Authorization: Basic <base64 user:pass>)
 - Bearer tokens / JWTs        (Authorization: Bearer …, cookies, bodies)
 - API keys / secrets          (named params/headers + known key patterns)

All of these are high-value because the capture is cleartext HTTP, so any
match is exposed verbatim on the wire.
"""
import base64
import json
import re
from urllib.parse import parse_qsl, urlparse

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
KNOWN_SECRET_RE = re.compile(
    r"(sk_live_[0-9a-zA-Z]{10,}|ghp_[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{20,})"
)
API_KEY_NAMES = {"api_key", "apikey", "api-key", "x-api-key", "access_token",
                 "auth_token", "client_secret", "secret", "token"}


def _b64url_json(part):
    """Best-effort decode of a base64url JWT segment to a dict."""
    try:
        pad = "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part + pad))
    except Exception:
        return None


def _decode_jwt(tok):
    bits = tok.split(".")
    if len(bits) < 2:
        return None
    return {"header": _b64url_json(bits[0]), "payload": _b64url_json(bits[1]), "token": tok}


def detect(cap):
    basic, jwts, api_keys = [], [], []
    seen_jwt = set()

    for tx in cap.transactions:
        req = tx.request
        if not req:
            continue
        hdrs = req.headers
        uri = req.start_line.split(" ")[1] if len(req.start_line.split(" ")) > 1 else ""
        blob = (uri + "\n" + (req.body.decode("latin1") if req.body else "") + "\n" +
                " ".join(v if isinstance(v, str) else " ".join(v) for v in hdrs.values()))

        # --- HTTP Basic auth ---
        authz = hdrs.get("authorization", "")
        if isinstance(authz, list):
            authz = authz[0]
        if authz.lower().startswith("basic "):
            try:
                dec = base64.b64decode(authz.split(" ", 1)[1]).decode("latin1")
                u, _, p = dec.partition(":")
                basic.append({"endpoint": uri, "username": u, "password": p})
            except Exception:
                pass
        elif authz.lower().startswith("bearer "):
            tok = authz.split(" ", 1)[1].strip()
            if JWT_RE.fullmatch(tok) and tok not in seen_jwt:
                seen_jwt.add(tok)
                jwts.append(_decode_jwt(tok))

        # --- JWTs anywhere (headers, cookies, body) ---
        for m in JWT_RE.findall(blob):
            if m not in seen_jwt:
                seen_jwt.add(m)
                jwts.append(_decode_jwt(m))

        # --- API keys: named params/headers ---
        params = dict(parse_qsl(urlparse(uri).query, keep_blank_values=True))
        if req.body and "urlencoded" in (hdrs.get("content-type") or ""):
            try:
                params.update(dict(parse_qsl(req.body.decode("latin1"), keep_blank_values=True)))
            except Exception:
                pass
        for k, v in list(params.items()) + [(hk, hv) for hk, hv in hdrs.items() if isinstance(hv, str)]:
            if k.lower() in API_KEY_NAMES and v and len(v) >= 8:
                api_keys.append({"name": k, "value": v, "where": "parameter/header", "endpoint": uri})

        # --- API keys: known secret patterns ---
        for pat, label in ((AWS_KEY_RE, "AWS access key"), (KNOWN_SECRET_RE, "known secret pattern")):
            for m in pat.findall(blob):
                api_keys.append({"name": label, "value": m, "where": "pattern match", "endpoint": uri})

    # de-dup api_keys by (name,value)
    uniq, out = set(), []
    for a in api_keys:
        key = (a["name"], a["value"])
        if key not in uniq:
            uniq.add(key)
            out.append(a)
    return {"basic_auth": basic, "jwts": jwts, "api_keys": out}
