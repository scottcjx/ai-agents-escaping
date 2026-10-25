#!/usr/bin/env bash
# Publish the document + key to the internet, then run the two containers.
#
#   ./run.sh --message "hello"                     # key public -> COMPROMISED
#   ./run.sh --message "hello" --break-key missing # key gone   -> FAILED
#   ./run.sh --message "hello" --break-key private --backend gitlab
#   SAFE=1 ./run.sh --message "hello"              # mitigated proxy -> CONTAINED
#
# Flags after run.sh go to the publisher (publish_cli.py). SAFE is read by the
# proxy container.
set -euo pipefail
cd "$(dirname "$0")"

echo ">> Publishing document and key to the internet (host) ..."
python3 publisher/publish_cli.py --out .env "$@"

echo
echo ">> Starting containers (agent has NO internet; proxy relays) ..."
docker compose up --build --abort-on-container-exit --exit-code-from agent
code=$?

echo
echo ">> Cleaning up containers ..."
docker compose down >/dev/null 2>&1 || true
exit $code
