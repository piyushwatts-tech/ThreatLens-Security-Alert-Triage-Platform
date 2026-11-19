#!/bin/sh
# POSIX-sh variant of seed.sh for the curl container used by docker compose.
# Skips seeding if alerts already exist, so restarts don't duplicate data.
set -eu
API=${THREATLENS_API:-http://backend:8080}
if curl -fs "$API/api/alerts?size=1" | grep -q '"total":0'; then
  KEY=${INGEST_API_KEY:-}
  curl -fsS ${KEY:+-H "X-API-Key: $KEY"} -X POST "$API/api/ingest/cicids?rebaseTime=true" -F "file=@/data/sample/cicids2017_sample.csv"; echo
  curl -fsS ${KEY:+-H "X-API-Key: $KEY"} -X POST "$API/api/ingest/windows?rebaseTime=true" -F "file=@/data/sample/windows_security_sample.jsonl"; echo
  echo "Seeded. Open http://localhost:3000"
else
  echo "Alerts already present, skipping seed."
fi
