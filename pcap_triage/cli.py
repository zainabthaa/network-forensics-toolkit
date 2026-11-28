#!/usr/bin/env python3
"""
cli.py — command-line entry point for pcap_triage.

    pcap-triage <capture.pcapng> [-o report.html] [-j report.json]
                                 [--sigma rules.yml] [--stix bundle.json]
                                 [--flows-csv flows.csv]

Pipeline: load pcap -> reassemble TCP streams -> parse HTTP -> run detectors
-> profile network flows -> aggregate findings -> render JSON + HTML and
export Sigma + STIX + NetFlow-style CSV.
"""
import argparse
import datetime
import hashlib
import json
import os
import sys

from .detectors import pcap_http, credentials, cookies, traffic, auth, tls, flows
from .exporters import sigma as sigma_export, stix as stix_export

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    sys.exit("jinja2 is required: pip install jinja2")

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _ts(t):
    if not t:
        return "—"
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_findings(creds, authf, cooky, enc, rot=None):
    f = []
    if creds:
        f.append({"severity": "CRITICAL", "category": "Credential Exposure",
                  "title": f"{len(creds)} plaintext credential submission(s) recovered",
                  "detail": "Form credentials were transmitted unencrypted and are readable from the capture (OWASP A02)."})
    if authf.get("basic_auth"):
        f.append({"severity": "CRITICAL", "category": "Credential Exposure",
                  "title": f"{len(authf['basic_auth'])} HTTP Basic-Auth credential(s) recovered",
                  "detail": "Base64 is encoding, not encryption — the username and password were decoded directly."})
    if authf.get("api_keys"):
        f.append({"severity": "HIGH", "category": "Secret Exposure",
                  "title": f"{len(authf['api_keys'])} API key/secret(s) exposed",
                  "detail": "API keys or secrets were transmitted in cleartext parameters, headers, or bodies."})
    if authf.get("jwts"):
        f.append({"severity": "MEDIUM", "category": "Token Exposure",
                  "title": f"{len(authf['jwts'])} JSON Web Token(s) observed in cleartext",
                  "detail": "Bearer/JWT tokens were visible on the wire and can be replayed until they expire."})
    if enc.get("encrypted_bytes") == 0 and enc.get("cleartext_bytes", 0) > 0:
        f.append({"severity": "HIGH", "category": "No Transport Encryption",
                  "title": "All application traffic is cleartext (no TLS)",
                  "detail": "No HTTPS/TLS traffic was observed; every request, response, and header is exposed."})
    for c in cooky:
        if any("Secure" in i for i in c["issues"]) or c.get("reuse_count", 0) > 1:
            f.append({"severity": "HIGH", "category": "Session Token Exposure",
                      "title": f"Session cookie '{c['name']}' is exposed/replayable",
                      "detail": "; ".join(c["issues"])})
    if rot and rot.get("fixation"):
        f.append({"severity": "HIGH", "category": "Session Management",
                  "title": "Session ID is not regenerated at login (session fixation)",
                  "detail": f"The same session ID was kept across every login; {rot['distinct_session_ids']} distinct "
                            "session ID(s) seen in the whole capture (OWASP A07, CWE-384)."})
    if rot and rot.get("logout_not_invalidated"):
        f.append({"severity": "MEDIUM", "category": "Session Management",
                  "title": "Session ID survives logout",
                  "detail": "After /logout the client kept presenting the pre-logout session ID; "
                            "the token was not rotated or invalidated (CWE-613)."})
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    f.sort(key=lambda x: order.get(x["severity"], 9))
    return f


def risk_level(findings):
    for lvl in ("CRITICAL", "HIGH", "MEDIUM"):
        if any(x["severity"] == lvl for x in findings):
            return lvl
    return "LOW"


def analyze(pcap_path):
    cap = pcap_http.load_capture(pcap_path)
    creds = credentials.detect(cap)
    cooky = cookies.detect(cap)
    enc = traffic.encryption_ratio(cap)
    eps = traffic.endpoints(cap)
    authf = auth.detect(cap)
    tlsf = tls.detect(cap)
    rot = cookies.session_rotation(cap)
    prof = flows.profile(cap)

    # context for exporters
    clients, servers = set(), set()
    ua = None
    for tx in cap.transactions:
        clients.add(tx.client_ip); servers.add(tx.server_ip)
        if ua is None and tx.request:
            uah = tx.request.headers.get("user-agent")
            ua = uah[0] if isinstance(uah, list) else uah
    authf["_user_agent"] = ua
    hosts = [(ip, "client") for ip in sorted(clients)] + [(ip, "server") for ip in sorted(servers)]

    findings = build_findings(creds, authf, cooky, enc, rot)
    report = {
        "meta": {
            "pcap_file": os.path.basename(pcap_path),
            "sha256": sha256_file(pcap_path),
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "packet_count": len(cap.packets),
            "http_transactions": len(cap.transactions),
            "capture_start_utc": _ts(cap.first_time),
            "capture_end_utc": _ts(cap.last_time),
            "duration_s": prof["summary"]["duration_s"],
        },
        "risk_level": risk_level(findings),
        "findings": findings,
        "credentials": creds,
        "auth": authf,
        "session_cookies": cooky,
        "tls": tlsf,
        "encryption": enc,
        "endpoints": eps,
        "session_rotation": rot,
        "network": prof,
        "_hosts": hosts,
    }
    return report


def render_html(report):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    return env.get_template("report.html.j2").render(**report)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pcap-triage",
                                 description="Offline PCAP triage for web-traffic forensics.")
    ap.add_argument("pcap", help="path to the .pcap/.pcapng capture file")
    ap.add_argument("-o", "--output", default="report.html", help="HTML report path")
    ap.add_argument("-j", "--json", default="report.json", help="JSON report path")
    ap.add_argument("--sigma", default="sigma_rules.yml", help="Sigma rules output path")
    ap.add_argument("--stix", default="stix_bundle.json", help="STIX 2.1 bundle output path")
    ap.add_argument("--flows-csv", default="flows.csv", help="NetFlow-style flow records (CSV) output path")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.pcap):
        sys.exit(f"No such file: {args.pcap}")

    print(f"[*] Loading capture: {args.pcap}")
    report = analyze(args.pcap)
    print(f"[*] {report['meta']['packet_count']} packets, "
          f"{report['meta']['http_transactions']} HTTP transactions")

    with open(args.json, "w") as f:
        json.dump(report, f, indent=2, default=list)
    print(f"[+] JSON report  -> {args.json}")
    with open(args.output, "w") as f:
        f.write(render_html(report))
    print(f"[+] HTML report  -> {args.output}")
    with open(args.sigma, "w") as f:
        f.write(sigma_export.build(report))
    print(f"[+] Sigma rules  -> {args.sigma}")
    with open(args.stix, "w") as f:
        json.dump(stix_export.build(report), f, indent=2)
    print(f"[+] STIX bundle  -> {args.stix}")
    flows.write_netflow_csv(report["network"]["flows"], args.flows_csv)
    print(f"[+] Flow records -> {args.flows_csv}")

    a = report["auth"]
    print(f"\n[=] Risk: {report['risk_level']} | "
          f"{len(report['credentials'])} form-cred(s), {len(a['basic_auth'])} basic-auth, "
          f"{len(a['jwts'])} JWT(s), {len(a['api_keys'])} API key(s), "
          f"{len(report['session_cookies'])} session cookie(s), "
          f"{report['encryption']['cleartext_pct']}% cleartext, "
          f"{report['tls']['encrypted_session_count']} TLS session(s)")
    n = report["network"]["summary"]
    print(f"[=] Network: {n['flow_count']} flow(s), {n['host_count']} host(s), "
          f"{n['duration_s']}s, avg {n['avg_throughput_bps']/1000:.1f} kbit/s, "
          f"peak {n['peak_throughput_bps']/1000:.1f} kbit/s, "
          f"max {n['max_parallel_conns']} parallel connection(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
