#!/usr/bin/env bash
# Load the bundled sample datasets into a running ThreatLens backend.
# Timestamps are rebased to "now" so the dashboard timelines look live.
set -euo pipefail
API=${THREATLENS_API:-http://localhost:8080}
DIR="$(cd "$(dirname "$0")/.." && pwd)/data/sample"
HDR=()
[ -n "${INGEST_API_KEY:-}" ] && HDR=(-H "X-API-Key: $INGEST_API_KEY")

echo "Waiting for $API ..."
for _ in $(seq 1 60); do curl -fs "$API/actuator/health" >/dev/null && break; sleep 2; done

echo "Ingesting CIC-IDS2017 network flows"
curl -fsS "${HDR[@]}" -X POST "$API/api/ingest/cicids?rebaseTime=true" -F "file=@$DIR/cicids2017_sample.csv"; echo
echo "Ingesting Windows Security events"
curl -fsS "${HDR[@]}" -X POST "$API/api/ingest/windows?rebaseTime=true" -F "file=@$DIR/windows_security_sample.jsonl"; echo
echo "Done. Open http://localhost:3000 (Docker) or http://localhost:5173 (dev)."
