#!/usr/bin/env bash
# Load golden fixture, build console, start server, capture README PNGs, stop server.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${GRC_LAKE_SCREENSHOT_PORT:-8787}"
BASE="http://127.0.0.1:${PORT}"
# A dedicated throwaway lake: seeded remediation rows and app state from a
# previous capture never leak into the next one.
LAKE="${GRC_LAKE_SCREENSHOT_LAKE:-build/screenshot-lake}"
case "$LAKE" in
  build/*) rm -rf "$LAKE" ;;
  *) echo "GRC_LAKE_SCREENSHOT_LAKE must live under build/ (got ${LAKE})" >&2; exit 1 ;;
esac

echo "==> Load golden fixture into ${LAKE}"
uv run grc-lake fixtures load --company golden --out "$LAKE" --rebase-times
uv run grc-lake db upgrade --lake "$LAKE"

echo "==> Build console static export"
npm --prefix app/web run build

echo "==> Start server on ${BASE}"
uv run grc-lake serve \
  --lake "$LAKE" \
  --server \
  --allow-insecure-no-auth \
  --port "$PORT" \
  --host 127.0.0.1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$((SECONDS + 30))
until curl -sf "${BASE}/api/v1/healthz" >/dev/null 2>&1; do
  if (( SECONDS > deadline )); then
    echo "Server failed to start on ${BASE}" >&2
    exit 1
  fi
  sleep 0.5
done

echo "==> Capture screenshots to docs/images/ (light + dark, one frozen clock)"
GRC_LAKE_SCREENSHOT_NOW="${GRC_LAKE_SCREENSHOT_NOW:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
  GRC_LAKE_SCREENSHOT_URL="$BASE" npm --prefix app/web run demo-screenshots

echo "==> Optimize PNGs"
uv run python tools/optimize_screenshots.py

echo "==> Done. PNGs in docs/images/grc-lake-demo-*.png"
