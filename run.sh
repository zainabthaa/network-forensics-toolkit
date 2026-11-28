#!/usr/bin/env bash
# One command: set up, test, analyse the capture, open the report.
#   ./run.sh                      -> uses sample/traffic_capture.pcapng
#   ./run.sh path/to/other.pcapng -> analyse another capture
set -euo pipefail
cd "$(dirname "$0")"

PCAP="${1:-sample/traffic_capture.pcapng}"
OUT="out"
PY="${PYTHON:-python3}"

if [ ! -x .venv/bin/python ]; then
  echo "[*] Creating virtual environment (.venv)"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
echo "[*] Installing pcap-triage and test dependencies"
pip install -q --upgrade pip >/dev/null
pip install -q --force-reinstall --no-deps . >/dev/null
pip install -q ".[dev]"

echo "[*] Running the test suite"
python -m pytest -q

mkdir -p "$OUT"
echo "[*] Analysing $PCAP"
pcap-triage "$PCAP" -o "$OUT/report.html" -j "$OUT/report.json" \
  --sigma "$OUT/sigma_rules.yml" --stix "$OUT/stix_bundle.json" --flows-csv "$OUT/flows.csv"

echo "[*] Opening $OUT/report.html"
case "$(uname -s)" in
  Darwin) open "$OUT/report.html" ;;
  Linux)  xdg-open "$OUT/report.html" >/dev/null 2>&1 || echo "Open $OUT/report.html in a browser" ;;
  *)      echo "Open $OUT/report.html in a browser" ;;
esac
