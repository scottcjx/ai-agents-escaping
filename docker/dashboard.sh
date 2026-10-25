#!/usr/bin/env bash
# Start the live dashboard and open it in the browser.
#   ./dashboard.sh            # port 8750
#   ./dashboard.sh --port 9000
set -euo pipefail
cd "$(dirname "$0")"

PORT=8750
if [ "${1:-}" = "--port" ] && [ -n "${2:-}" ]; then PORT="$2"; fi

URL="http://localhost:${PORT}"
echo ">> Dashboard at ${URL}"
( sleep 1; (command -v open >/dev/null && open "$URL") || true ) &
exec python3 dashboard/server.py --port "$PORT"
