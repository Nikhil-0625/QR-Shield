#!/bin/sh
set -eu
# Only the dedicated demo data directory is provisioned. Never copy development data.
mkdir -p /data
chown 10001:10001 /data
cd /app/backend
exec gosu 10001:10001 python -m uvicorn demo_app:create_app --factory --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --no-proxy-headers --no-access-log --limit-concurrency 8 --timeout-keep-alive 5
