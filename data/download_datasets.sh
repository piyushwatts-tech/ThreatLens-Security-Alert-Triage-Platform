#!/usr/bin/env bash
# Download (a slice of) the real public datasets and ingest them into ThreatLens.
#
#   ./data/download_datasets.sh cicids   # CIC-IDS2017 Friday PortScan + DDoS flows
#   ./data/download_datasets.sh otrf     # OTRF Security-Datasets Windows logs
#
# The CIC-IDS2017 archive is ~270 MB zipped. We extract only the Friday afternoon
# files (PortScan + DDoS) and keep the first $CIC_MAX_ROWS rows of each, so the
# demo database stays small. Mirrors move over time: if a URL 404s, override it
# with the env var shown next to it.
set -euo pipefail
cd "$(dirname "$0")"
API=${THREATLENS_API:-http://localhost:8080}
mkdir -p raw

CIC_URL=${CIC_URL:-http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/GeneratedLabelledFlows.zip}
CIC_MAX_ROWS=${CIC_MAX_ROWS:-50000}
# Any OTRF dataset zip that contains Windows Security / Sysmon JSON lines works.
OTRF_URL=${OTRF_URL:-https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip}

case "${1:-}" in
  cicids)
    [ -f raw/cic.zip ] || curl -fL "$CIC_URL" -o raw/cic.zip
    unzip -o -j raw/cic.zip '*Friday-WorkingHours-Afternoon*' -d raw/cic >/dev/null
    for f in raw/cic/*.csv; do
      head -n $((CIC_MAX_ROWS + 1)) "$f" > "$f.slice"
      echo "ingesting $f (first $CIC_MAX_ROWS rows)"
      curl -fsS -X POST "$API/api/ingest/cicids?rebaseTime=true" -F "file=@$f.slice"; echo
    done ;;
  otrf)
    curl -fL "$OTRF_URL" -o raw/otrf.zip
    unzip -o raw/otrf.zip -d raw/otrf >/dev/null
    for f in raw/otrf/*.json; do
      echo "ingesting $f"
      curl -fsS -X POST "$API/api/ingest/windows?rebaseTime=true" -F "file=@$f"; echo
    done ;;
  *) echo "usage: $0 cicids|otrf"; exit 1 ;;
esac
