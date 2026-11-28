"""Unit tests for pcap_triage, validated against the bundled sample capture."""
import json
from pathlib import Path

import pytest

from pcap_triage import cli
from pcap_triage.detectors import pcap_http, credentials, cookies, traffic, auth, tls
from pcap_triage.exporters import sigma as sigma_export, stix as stix_export

SAMPLE = Path(__file__).resolve().parent.parent / "sample" / "traffic_capture.pcapng"


@pytest.fixture(scope="module")
def cap():
    return pcap_http.load_capture(str(SAMPLE))


def test_sample_exists():
    assert SAMPLE.is_file()


def test_capture_loads(cap):
    assert len(cap.packets) == 298
    assert len(cap.transactions) == 28


def test_credentials_recovered(cap):
    creds = credentials.detect(cap)
    pairs = {(c["username"], c["password"]) for c in creds}
    assert ("admin", "password") in pairs


def test_session_cookie_insecure(cap):
    cks = cookies.detect(cap)
    php = next((c for c in cks if c["name"].upper() == "PHPSESSID"), None)
    assert php is not None
    assert php["secure"] is False
    assert php["reuse_count"] >= 2


def test_all_cleartext(cap):
    enc = traffic.encryption_ratio(cap)
    assert enc["cleartext_pct"] == 100.0
    assert enc["encrypted_bytes"] == 0


def test_endpoints_present(cap):
    eps = traffic.endpoints(cap)
    paths = {e["path"] for e in eps}
    assert "/login.php" in paths


def test_auth_detector_runs(cap):
    out = auth.detect(cap)
    assert set(out) >= {"basic_auth", "jwts", "api_keys"}


def test_tls_detector_runs(cap):
    out = tls.detect(cap)
    # the sample has no TLS traffic
    assert out["encrypted_session_count"] == 0


def test_exporters_valid():
    report = cli.analyze(str(SAMPLE))
    # STIX bundle must be valid JSON with a bundle type
    bundle = stix_export.build(report)
    assert json.loads(json.dumps(bundle))["type"] == "bundle"
    # Sigma output must be non-empty text with a title
    rules = sigma_export.build(report)
    assert "title:" in rules


def test_end_to_end_risk():
    report = cli.analyze(str(SAMPLE))
    assert report["risk_level"] == "CRITICAL"


# ---- network flow analysis ------------------------------------------------
from pcap_triage.detectors import flows  # noqa: E402


@pytest.fixture(scope="module")
def prof(cap):
    return flows.profile(cap)


def test_flow_records(prof):
    s = prof["summary"]
    assert s["tcp_flows"] == 22
    assert s["complete_handshakes"] == s["tcp_flows"]
    assert s["closed_rst"] == 0
    f = prof["flows"][0]
    assert {"src_ip", "src_port", "dst_ip", "dst_port", "proto", "bytes", "packets"} <= set(f)
    assert sum(f["packets"] for f in prof["flows"]) == 290  # every TCP frame lands in a flow


def test_flows_carry_http(prof):
    reqs = [r for f in prof["flows"] for r in f["http_requests"]]
    assert "POST /login.php" in reqs
    assert len(reqs) == 28


def test_top_talkers(prof):
    top = prof["endpoints"][0]["address"]
    assert top in {"192.168.128.5", "192.168.128.20"}


def test_protocol_hierarchy(prof):
    stacks = {p["stack"] for p in prof["protocol_hierarchy"]}
    assert "Ethernet/IPv4/TCP/HTTP" in stacks
    assert sum(p["frames"] for p in prof["protocol_hierarchy"]) == 298


def test_io_timeline(prof):
    bins = prof["io"]["bins"]
    assert sum(b["packets"] for b in bins) == 298
    assert prof["summary"]["max_parallel_conns"] >= 2


def test_netflow_csv(prof, tmp_path):
    out = tmp_path / "flows.csv"
    flows.write_netflow_csv(prof["flows"], str(out))
    lines = out.read_text().splitlines()
    assert lines[0].startswith("flow_id,")
    assert len(lines) == 1 + len(prof["flows"])


def test_session_not_rotated(cap):
    rot = cookies.session_rotation(cap)
    assert rot["fixation"] is True
    assert rot["distinct_session_ids"] == 1


def test_conversations(prof):
    ip = prof["conversations"]["ip"]
    assert {ip[0]["a"], ip[0]["b"]} == {"192.168.128.5", "192.168.128.20"}
    assert prof["conversations"]["ethernet"][0]["frames"] >= 290


def test_l2_inventory(prof):
    srv = next(h for h in prof["l2_inventory"] if h["role"] == "web server")
    assert srv["ips"] == ["192.168.128.20"]
    assert srv["hops_away"] == 1  # TTL 63 -> one routed hop (container bridge)


def test_tcp_health(prof):
    h = prof["tcp_health"]
    assert h["retransmissions"] == 0
    assert h["client_syn_options"]["mss"] == 1460
    assert all(f["idle_before_fin_s"] >= 4.9 for f in prof["flows"])


def test_activity_and_ladder(prof):
    assert len(prof["activity"]["bursts"]) >= 2
    kinds = {e["kind"] for e in prof["ladder"]}
    assert {"syn", "request", "response"} <= kinds
    assert sum(1 for e in prof["ladder"] if e["kind"] == "request") == 28


def test_html_report_renders():
    html = cli.render_html(cli.analyze(str(SAMPLE)))
    for anchor in ("s-ladder", "s-conv", "s-tcp", "cat-network"):
        assert f'id="{anchor}"' in html
