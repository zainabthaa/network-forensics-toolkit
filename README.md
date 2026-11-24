# Network Forensics & Traffic Analysis Toolkit

Captured and forensically analysed web-application traffic in an isolated virtual
lab — recovering cleartext credentials and a replayable session token — then built
a **pip-installable Python PCAP triage tool** that turns any capture into a
JSON/HTML evidence report and exports **Sigma** detection rules and a **STIX 2.1**
threat-intel bundle automatically.

> CS3093 course project. Analysts: **Zainab Taha**, **Natali Soukh**.

[![CI](https://github.com/zainabthaa/network-forensics-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/zainabthaa/network-forensics-toolkit/actions/workflows/ci.yml)

---

## TL;DR — key findings

The target web app (DVWA) runs entirely over **unencrypted HTTP**. From a 4-minute capture:

- **Administrator credentials** (`admin` / `password`) recovered in cleartext from a login POST.
- The **authenticated session token** (`PHPSESSID`) travelled in cleartext, was reused across the session, and was shown to be **replayable** — a full **session hijack with no password**.
- The authenticated session cookie carries **none** of `Secure` / `HttpOnly` / `SameSite`.
- **100%** of application traffic was cleartext.

Overall risk: **CRITICAL**. Fix: enforce TLS, set `Secure`/`HttpOnly`/`SameSite`, regenerate session IDs on login.

---

## The tool — `pcap-triage`

An offline analyzer (pure Python, **no tshark/Wireshark at runtime**). It reassembles
TCP streams, parses HTTP, runs a suite of detectors, and emits four artifacts.

**Detects:** plaintext form credentials · HTTP Basic-Auth · JWTs · API keys/secrets ·
insecure session cookies (`Secure`/`HttpOnly`/`SameSite` + token reuse) ·
TLS/SNI awareness · cleartext-vs-encrypted ratio · full endpoint inventory.

**Emits:** `report.html` · `report.json` · `sigma_rules.yml` · `stix_bundle.json`.

### Install & run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pcap-triage sample/traffic_capture.pcapng -o report.html -j report.json \
            --sigma sigma_rules.yml --stix stix_bundle.json
open report.html            # macOS (use xdg-open on Linux)
```

Point it at **any** `.pcapng`, not just the bundled sample.

### Tests & CI

```bash
python -m pytest -q         # validated against the bundled capture
```
A GitHub Actions workflow runs the suite and a CLI smoke-test on every push across
Python 3.9–3.12 (`.github/workflows/ci.yml`).

---

## Repository structure

```
network-forensics-toolkit/
├── pcap_triage/              # the tool (installable package)
│   ├── cli.py                # pipeline + console entry point
│   ├── detectors/            # TCP reassembly, HTTP parse, credential/cookie/auth/TLS detectors
│   ├── exporters/            # Sigma + STIX exporters
│   └── templates/            # HTML report template
├── tests/                    # pytest suite
├── sample/traffic_capture.pcapng
├── pyproject.toml            # pip-installable; `pcap-triage` entry point
├── .github/workflows/ci.yml  # CI: install + test + smoke-run
├── report/                   # project report (PDF + DOCX)
└── evidence/                 # capture + the tool's rendered outputs
```

**Evidence integrity** — `traffic_capture.pcapng`
SHA-256: `dc4e142dda0461ea17ddcd7a17ad017293895a83f1efd95b732dddaa3b2ee351`

---

## Scope & ethics

All work was performed in an **isolated host-only lab** (`192.168.128.0/24`) against a
deliberately vulnerable application. No live or third-party systems were involved.
For educational, defensive, and forensic learning only.
