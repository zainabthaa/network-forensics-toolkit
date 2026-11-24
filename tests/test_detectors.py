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
