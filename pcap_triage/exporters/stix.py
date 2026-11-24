"""
stix.py — emit a STIX 2.1 bundle of the indicators found in the capture.

STIX (https://oasis-open.github.io/cti-documentation/) is the standard format
for sharing cyber-threat intelligence. Exporting IOCs as STIX lets the findings
feed a TIP/SIEM directly.
"""
import uuid
import datetime


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(kind):
    return f"{kind}--{uuid.uuid4()}"


def _indicator(name, pattern, now, labels=("anomalous-activity",)):
    return {
        "type": "indicator", "spec_version": "2.1", "id": _id("indicator"),
        "created": now, "modified": now, "name": name,
        "indicator_types": list(labels),
        "pattern": pattern, "pattern_type": "stix", "valid_from": now,
    }


def build(report):
    now = _now()
    meta = report.get("meta", {})
    objs = []

    ident = {"type": "identity", "spec_version": "2.1", "id": _id("identity"),
             "created": now, "modified": now, "name": "pcap-triage", "identity_class": "tool"}
    objs.append(ident)

    # host indicators (from endpoints / meta — use well-known capture hosts if present)
    for ep in report.get("endpoints", [])[:1]:
        pass
    # target + client IPs are embedded in findings' context; pull from a convention field
    for ip, role in report.get("_hosts", []):
        objs.append(_indicator(f"{role} host {ip}", f"[ipv4-addr:value = '{ip}']", now))

    # URLs
    host = ""
    for c in report.get("credentials", []):
        host = c.get("host") or host
    for ep in report.get("endpoints", [])[:8]:
        url = f"http://{host}{ep['path']}" if host else ep["path"]
        objs.append(_indicator(f"HTTP {ep['method']} {ep['path']}",
                               f"[url:value = '{url}']", now))

    # user-agent
    ua = report.get("auth", {}).get("_user_agent")
    if ua:
        objs.append(_indicator("Observed client User-Agent",
                               f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{ua}']", now))

    # cleartext-credential indicator
    if report.get("credentials"):
        objs.append(_indicator("Cleartext credentials transmitted over HTTP",
                               "[network-traffic:protocols[*] = 'http']", now,
                               labels=("anomalous-activity", "compromised")))

    return {"type": "bundle", "id": _id("bundle"), "objects": objs}
