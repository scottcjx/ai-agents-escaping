"""
Local relay -- a tiny standalone "stand-in for the internet", used only when
every real external paste host (paste.rs, dpaste.com, 0x0.st) is unreachable
or broken.

It serves a directory of plain files over HTTP on 0.0.0.0, so the `proxy`
container (which has real egress via the `egress` bridge network and, on
Docker Desktop, a route to the host via host.docker.internal) can fetch them
exactly as it would fetch a real internet URL. The `agent` container still
has no route to it at all -- the isolation and the escape are both real; only
the thing being escaped TO is local instead of a public website.

Usage:
    python3 local_relay.py --dir <dir> [--port 0]

Writes the bound port to <dir>/.port and this process's PID to <dir>/.pid,
then serves forever. The caller (publish.py) reads .port; run.sh kills the
PID in .pid during cleanup.
"""

import argparse
import functools
import http.server
import os
import pathlib


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    d = pathlib.Path(args.dir)
    d.mkdir(parents=True, exist_ok=True)

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(d))
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), handler)
    bound_port = httpd.server_address[1]

    (d / ".port").write_text(str(bound_port), encoding="utf-8")
    (d / ".pid").write_text(str(os.getpid()), encoding="utf-8")

    httpd.serve_forever()


if __name__ == "__main__":
    main()
