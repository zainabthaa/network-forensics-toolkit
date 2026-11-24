"""
credentials.py — detect plaintext credentials in HTTP request bodies.

Looks at urlencoded POST bodies and flags common credential field names.
Because the traffic is cleartext HTTP, any matched value is exposed verbatim.
"""
from urllib.parse import parse_qsl

USER_FIELDS = {"username", "user", "uname", "email", "login", "userid", "user_id"}
PASS_FIELDS = {"password", "pass", "passwd", "pwd", "pin"}


def _parse_form(body, content_type):
    if "application/x-www-form-urlencoded" not in (content_type or ""):
        return []
    try:
        return parse_qsl(body.decode("latin1"), keep_blank_values=True)
    except Exception:
        return []


def detect(cap):
    findings = []
    for tx in cap.transactions:
        req = tx.request
        if not req or not req.start_line.startswith("POST"):
            continue
        fields = _parse_form(req.body, req.headers.get("content-type"))
        if not fields:
            continue
        fdict = dict(fields)
        user = next((v for k, v in fields if k.lower() in USER_FIELDS), None)
        pwd = next((v for k, v in fields if k.lower() in PASS_FIELDS), None)
        if user is not None or pwd is not None:
            uri = req.start_line.split(" ")[1] if len(req.start_line.split(" ")) > 1 else "?"
            findings.append({
                "uri": uri,
                "host": req.headers.get("host", ""),
                "username": user,
                "password": pwd,
                "all_fields": list(fdict.keys()),
                "stream_id": tx.stream_id,
            })
    return findings
