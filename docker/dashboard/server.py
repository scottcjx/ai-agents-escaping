#!/usr/bin/env python3
"""
Local dashboard server for the containerised sandbox-escape demo.

It serves one web page that shows three live panels -- the AGENT container, the
PROXY container, and the HOST/control -- streaming in real time. Buttons launch
each scenario. No external dependencies; standard library only.

    python3 dashboard/server.py          # then open http://localhost:8750
    python3 dashboard/server.py --port 9000

The server runs on the HOST. It publishes the document and key, then runs
`docker compose`, and relays every log line to the browser over SSE.
"""

import argparse
import json
import os
import queue
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKER_DIR = os.path.dirname(HERE)           # .../docker
INDEX = os.path.join(HERE, "index.html")

# compose prefixes lines like "agent-1  | ...."
PREFIX = re.compile(r"^(?P<svc>[a-zA-Z][\w-]*)-\d+\s*\|\s?(?P<rest>.*)$")

SCENARIOS = {
    # name: (publisher args, extra env for compose)
    "compromise": (["--break-key", "public"], {"SAFE": "0"}),
    "missing":    (["--break-key", "missing"], {"SAFE": "0"}),
    "mitigated":  (["--break-key", "public"], {"SAFE": "1"}),
}
RESULT_BY_CODE = {0: "COMPROMISED", 20: "FAILED", 10: "CONTAINED"}


class Hub:
    """Fan-out of events to all connected browser clients."""

    def __init__(self):
        self._clients: list[queue.Queue] = []
        self._lock = threading.Lock()
        self.running = False

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._clients.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._clients:
                self._clients.remove(q)

    def emit(self, source: str, line: str, kind: str = "log") -> None:
        evt = json.dumps({"source": source, "line": line, "kind": kind})
        with self._lock:
            for q in list(self._clients):
                q.put(evt)


hub = Hub()


def run_scenario(name: str, message: str) -> None:
    if hub.running:
        hub.emit("host", "a run is already in progress; wait for it to finish.", "status")
        return
    hub.running = True
    pub_args, extra_env = SCENARIOS[name]
    try:
        hub.emit("host", "", "clear")
        hub.emit("host", f"scenario: {name}", "status")
        hub.emit("host", f">> publishing document + key (key={pub_args[1]}) ...")

        # 1) publish (host) -> writes .env
        pub = subprocess.run(
            ["python3", "publisher/publish_cli.py", "--out", ".env",
             "--message", message, *pub_args],
            cwd=DOCKER_DIR, capture_output=True, text=True,
        )
        for ln in (pub.stdout + pub.stderr).splitlines():
            hub.emit("host", ln)
        if pub.returncode != 0:
            hub.emit("host", "publish failed; aborting.", "status")
            return

        # 2) build images quietly (keeps the panels clean), then run + stream
        env = {**os.environ, **extra_env}
        hub.emit("host", ">> building images ...")
        build = subprocess.run(["docker", "compose", "build"], cwd=DOCKER_DIR,
                               env=env, capture_output=True, text=True)
        if build.returncode != 0:
            for ln in (build.stdout + build.stderr).splitlines()[-10:]:
                hub.emit("host", ln)
            hub.emit("host", "build failed; aborting.", "status")
            return
        hub.emit("host", "   images ready")

        hub.emit("host", f">> docker compose up (SAFE={extra_env['SAFE']}) ...")
        proc = subprocess.Popen(
            ["docker", "compose", "up",
             "--abort-on-container-exit", "--exit-code-from", "agent"],
            cwd=DOCKER_DIR, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            m = PREFIX.match(line)
            if m:
                svc = m.group("svc")
                source = svc if svc in ("agent", "proxy") else "host"
                hub.emit(source, m.group("rest"))
            else:
                hub.emit("host", line)
        proc.wait()

        result = RESULT_BY_CODE.get(proc.returncode, f"EXIT {proc.returncode}")
        hub.emit("host", f">> agent exit code: {proc.returncode} -> {result}")
        hub.emit("host", result, "result")

        subprocess.run(["docker", "compose", "down"], cwd=DOCKER_DIR,
                       capture_output=True, text=True)
        hub.emit("host", ">> containers stopped.")
    except Exception as e:  # noqa: BLE001
        hub.emit("host", f"error: {e}", "status")
    finally:
        hub.running = False


class Handler(BaseHTTPRequestHandler):
    def _headers(self, code: int, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/index"):
            with open(INDEX, "rb") as fh:
                body = fh.read()
            self._headers(200, "text/html; charset=utf-8")
            self.wfile.write(body)
            return
        if self.path == "/events":
            self._headers(200, "text/event-stream")
            q = hub.subscribe()
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    evt = q.get()
                    self.wfile.write(f"data: {evt}\n\n".encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                hub.unsubscribe(q)
            return
        self._headers(404, "text/plain")
        self.wfile.write(b"not found")

    def do_POST(self) -> None:
        if self.path != "/run":
            self._headers(404, "text/plain")
            self.wfile.write(b"not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(length) or b"{}")
        scenario = data.get("scenario", "compromise")
        message = data.get("message") or "COMP-SEC dashboard demo. Decoy data only."
        if scenario not in SCENARIOS:
            self._headers(400, "application/json")
            self.wfile.write(b'{"error":"unknown scenario"}')
            return
        threading.Thread(target=run_scenario, args=(scenario, message), daemon=True).start()
        self._headers(200, "application/json")
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args) -> None:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8750)
    args = ap.parse_args()
    print(f"dashboard: http://localhost:{args.port}  (Ctrl-C to stop)")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
