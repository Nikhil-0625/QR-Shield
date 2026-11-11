#!/bin/sh
set -eu

MODE="${QR_SHIELD_MODE:-restricted-demo}"
case "$MODE" in
    restricted-demo)
        # Preserve the existing isolated SQLite demo startup and data directory.
        mkdir -p /data
        chown 10001:10001 /data
        APP_MODULE="demo_app:create_app"
        FACTORY=1
        ;;
    production)
        # database.py validates that DATABASE_URL points to PostgreSQL and requires TLS.
        if [ -z "${DATABASE_URL:-}" ]; then
            echo "Production mode requires DATABASE_URL" >&2
            exit 1
        fi
        APP_MODULE="main:app"
        FACTORY=0
        ;;
    *)
        echo "QR_SHIELD_MODE must be restricted-demo or production in this container" >&2
        exit 1
        ;;
esac

cd /app/backend
set -- "$APP_MODULE"
if [ "$FACTORY" -eq 1 ]; then
    set -- "$@" --factory
fi
set -- "$@" --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --no-proxy-headers --no-access-log --limit-concurrency 8 --timeout-keep-alive 5
exec gosu 10001:10001 python -m uvicorn "$@"
