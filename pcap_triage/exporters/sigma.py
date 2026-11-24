"""
sigma.py — emit Sigma detection rules derived from the triage findings.

Sigma (https://sigmahq.io) is a vendor-neutral detection-rule format. These
rules describe the *patterns* the capture exhibited so the same exposure can be
detected in proxy / Zeek HTTP logs by any SIEM. This is detection-content
authoring, performed offline from evidence.
"""
import uuid
import datetime

_NS = uuid.UUID("12345678-1234-5678-1234-567812345678")
_DATE = datetime.date.today().isoformat()


def _rid(title):
    return str(uuid.uuid5(_NS, title))


def _rule(title, desc, detection, level, tags):
    return f"""title: {title}
id: {_rid(title)}
status: experimental
description: {desc}
author: pcap-triage
date: {_DATE}
logsource:
    category: proxy
detection:
{detection}
    condition: selection
falsepositives:
    - Legitimate internal applications that have not yet migrated to HTTPS
level: {level}
tags:
{chr(10).join('    - ' + t for t in tags)}
"""


def build(report):
    rules = []
    creds = report.get("credentials") or []
    auth = report.get("auth") or {}
    cookies = report.get("session_cookies") or []
    enc = report.get("encryption") or {}

    if creds or auth.get("basic_auth"):
        rules.append(_rule(
            "Cleartext Credentials Submitted Over HTTP",
            "Detects username/password fields or HTTP Basic auth sent over unencrypted HTTP.",
            "    selection:\n        c-protocol: 'http'\n        cs-method: 'POST'\n"
            "        cs-uri-query|contains:\n            - 'password='\n            - 'passwd='\n            - 'pwd='",
            "high",
            ["attack.credential_access", "attack.t1040", "attack.t1557"],
        ))
    if any(any("Secure" in i for i in c.get("issues", [])) for c in cookies):
        rules.append(_rule(
            "Session Cookie Set Without Secure Attribute",
            "Detects Set-Cookie responses for session identifiers that omit the Secure attribute, allowing transmission over HTTP.",
            "    selection:\n        sc-set-cookie|contains:\n            - 'PHPSESSID='\n            - 'JSESSIONID='\n            - 'SESSIONID='\n"
            "    filter:\n        sc-set-cookie|contains: 'Secure'",
            "medium",
            ["attack.credential_access", "attack.t1550.004"],
        ))
        # fix condition for the filtered rule
        rules[-1] = rules[-1].replace("    condition: selection",
                                      "    condition: selection and not filter")
    if enc.get("encrypted_bytes", 1) == 0 and enc.get("cleartext_bytes", 0) > 0:
        rules.append(_rule(
            "Web Authentication Over Unencrypted Channel",
            "Detects authenticated web sessions (session cookie present) carried entirely over HTTP with no TLS.",
            "    selection:\n        c-protocol: 'http'\n        cs-cookie|contains: 'SESSID'",
            "high",
            ["attack.credential_access", "attack.t1040"],
        ))
    if not rules:
        rules.append(_rule(
            "No High-Risk Cleartext Exposure Observed",
            "Placeholder rule; the analysed capture contained no cleartext credential or session exposure.",
            "    selection:\n        c-protocol: 'http'",
            "informational",
            ["attack.t1040"],
        ))
    return "\n---\n".join(rules)
