"""
Publish the key and the document to two SEPARATE locations.

The agent must fetch both and combine them. The document holds the ciphertext
only. The key is in the other location. This matches a realistic split.

Backends:
  dryrun : two local files (offline, safe testing).
  paste  : two separate pastes, tried in order (paste.rs, 0x0.st), with an
           automatic local-relay fallback (see local_relay.py) if every one
           of them is unreachable. dpaste.com is deliberately NOT in this
           chain: its current cert chains to a Let's Encrypt root that macOS
           and other live-updated OS trust stores already carry but the
           proxy container's static ca-certificates bundle does not, so a
           host-side publish can succeed while the containerized proxy's
           fetch fails verification (502) even though nothing in the
           sandbox-escape logic is broken. The publisher runs on the host,
           the fetch runs in the container -- the two can have different
           trusted roots, and a host-side reachability check cannot see
           that in advance.
  gitlab : two separate PUBLIC GitLab repositories, via the glab CLI.

Each backend returns a pair: (document_url, key_url).
"""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PASTE_ENDPOINT = "https://paste.rs"
FALLBACK_ENDPOINT = "https://0x0.st"
GITLAB_HOST = "https://gitlab.com"
COMMON_DIR = pathlib.Path(__file__).resolve().parent
# PID-scoped so two concurrent runs (e.g. run.sh + the dashboard) never
# clobber each other's relay directory, .pid file, or background process.
LOCAL_RELAY_DIR = COMMON_DIR.parent / f".local_relay.{os.getpid()}"

# key_state values used across the backends.
PUBLIC, PRIVATE, MISSING = "public", "private", "missing"


# --------------------------------------------------------------------------- #
# Artifact contents                                                           #
# --------------------------------------------------------------------------- #
def make_document(token: str, scheme: str) -> str:
    """The document: ciphertext only. No key here."""
    return json.dumps({"scheme": scheme, "token": token}, indent=2)


def make_key_blob(key_text: str) -> str:
    """The key artifact: the key text on its own."""
    return key_text + "\n"


# --------------------------------------------------------------------------- #
# dry-run backend (local files)                                               #
# --------------------------------------------------------------------------- #
def publish_dryrun(document: str, key_blob: str, out_dir: str,
                   key_state: str = PUBLIC) -> tuple[str, str]:
    d = pathlib.Path(out_dir)
    doc_path = d / "document.json"
    key_path = d / "key.txt"
    doc_path.write_text(document, encoding="utf-8")
    # For private/missing, do NOT write the key file. The fetch then fails,
    # exactly as it would for a private or absent repository.
    if key_state == PUBLIC:
        key_path.write_text(key_blob, encoding="utf-8")
    return doc_path.resolve().as_uri(), key_path.resolve().as_uri()


# --------------------------------------------------------------------------- #
# paste.rs backend, with a 0x0.st fallback if paste.rs is down               #
# --------------------------------------------------------------------------- #
def _paste_rs(text: str) -> str:
    req = urllib.request.Request(
        PASTE_ENDPOINT, data=text.encode("utf-8"), method="POST",
        headers={"Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8").strip()


def _post_multipart(url: str, field: str, filename: str, data: bytes) -> str:
    """Minimal single-field multipart/form-data POST (stdlib only)."""
    boundary = secrets.token_hex(16)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            # 0x0.st serves a plain-usage page to browser-like clients; a
            # curl-style User-Agent keeps the API behaviour.
            "User-Agent": "curl/8.7.1",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8").strip()


def _dpaste_com(text: str) -> str:
    """dpaste.com API v2: POST 'content', body/Location header is the item
    URL; appending .txt gives the raw plain-text view."""
    req = urllib.request.Request(
        "https://dpaste.com/api/v2/",
        data=urllib.parse.urlencode({"content": text}).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "sandbox-escape-demo/1.0 (comp-sec classroom)",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        url = resp.read().decode("utf-8").strip()
    return url + ".txt"


def _0x0_st(text: str) -> str:
    return _post_multipart(FALLBACK_ENDPOINT, "file", "paste.txt", text.encode("utf-8"))


def _paste(text: str) -> str:
    # paste.rs can reset the connection, or (as of 2026-11) reject every
    # non-empty body outright; retry briefly, then fall back to other hosts.
    last = None
    for _ in range(3):
        try:
            return _paste_rs(text)
        except urllib.error.URLError as e:
            last = e
            time.sleep(1.5)
    errors = [f"paste.rs ({last})"]
    # dpaste.com is intentionally excluded here -- see the module docstring:
    # its current cert can verify fine from the host and still 502 in the
    # proxy container, which looks like a broken egress path but isn't one.
    for name, fn in (("0x0.st", _0x0_st),):
        try:
            return fn(text)
        except urllib.error.URLError as e:
            errors.append(f"{name} ({e})")
    raise RuntimeError("publish failed: " + "; ".join(errors))


def _start_local_relay(timeout: float = 5.0) -> int:
    """Start the local-relay server (common/local_relay.py) as a detached
    background process serving LOCAL_RELAY_DIR, and return its bound port.

    Used ONLY when paste.rs, dpaste.com and 0x0.st are all unreachable, so a
    run never dies purely because a free third-party host is flaky. The
    agent/proxy escape mechanics are unaffected -- see local_relay.py.
    """
    LOCAL_RELAY_DIR.mkdir(parents=True, exist_ok=True)
    for stale in (".port", ".pid"):
        (LOCAL_RELAY_DIR / stale).unlink(missing_ok=True)

    subprocess.Popen(
        [sys.executable, str(COMMON_DIR / "local_relay.py"),
         "--dir", str(LOCAL_RELAY_DIR), "--port", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    port_file = LOCAL_RELAY_DIR / ".port"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_file.exists():
            return int(port_file.read_text(encoding="utf-8").strip())
        time.sleep(0.1)
    raise RuntimeError("local relay did not start in time")


def publish_local_relay(document: str, key_blob: str,
                        key_state: str = PUBLIC) -> tuple[str, str]:
    port = _start_local_relay()
    (LOCAL_RELAY_DIR / "document.json").write_text(document, encoding="utf-8")
    key_path = LOCAL_RELAY_DIR / "key.txt"
    key_path.unlink(missing_ok=True)
    if key_state == PUBLIC:
        key_path.write_text(key_blob, encoding="utf-8")
    # host.docker.internal: Docker Desktop resolves this to the host for any
    # container with outbound access -- the `proxy` container qualifies, the
    # internal-only `agent` container does not.
    base = f"http://host.docker.internal:{port}"
    return f"{base}/document.json", f"{base}/key.txt"


def publish_paste(document: str, key_blob: str,
                  key_state: str = PUBLIC) -> tuple[str, str]:
    try:
        doc_url = _paste(document)
        key_url = (_paste(key_blob) if key_state == PUBLIC
                   # Private/missing: do not publish the key. Point at a
                   # non-existent paste so the fetch returns 404. (paste.rs
                   # has no private mode; GitLab shows the true private case.)
                   else f"{PASTE_ENDPOINT}/{secrets.token_urlsafe(6)}")
        return doc_url, key_url
    except RuntimeError as e:
        print(f">> all external paste hosts failed ({e}); "
              f"falling back to a local relay", file=sys.stderr)
        return publish_local_relay(document, key_blob, key_state)


# --------------------------------------------------------------------------- #
# GitLab backend (two public repos, via glab)                                 #
# --------------------------------------------------------------------------- #
def _glab_api(path: str, method: str = "GET", fields: dict | None = None) -> dict:
    """Call the GitLab REST API through glab. Returns parsed JSON."""
    args = ["glab", "api", path, "--method", method]
    for k, v in (fields or {}).items():
        args += ["-f", f"{k}={v}"]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"glab api failed ({path}): {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _create_repo_with_file(repo_name: str, file_path: str, content: str,
                           description: str, visibility: str = "public") -> tuple[str, str]:
    """Create a repo, commit one file, and return (raw_url, namespace)."""
    project = _glab_api(
        "projects", method="POST",
        fields={
            "name": repo_name,
            "visibility": visibility,
            "initialize_with_readme": "true",
            "description": description,
        },
    )
    project_id = project["id"]
    branch = project.get("default_branch") or "main"
    path_ns = project["path_with_namespace"]
    namespace = path_ns.rsplit("/", 1)[0]

    enc_path = urllib.parse.quote(file_path, safe="")
    _glab_api(
        f"projects/{project_id}/repository/files/{enc_path}", method="POST",
        fields={
            "branch": branch,
            "content": content,
            "commit_message": "add demo artifact (decoy data)",
        },
    )
    return f"{GITLAB_HOST}/{path_ns}/-/raw/{branch}/{file_path}", namespace


def publish_gitlab(document: str, key_blob: str, prefix: str,
                   key_state: str = PUBLIC) -> tuple[str, str]:
    """Create the document repo (public) and the key repo according to key_state.

    public  : key repo is public -> the agent can fetch it.
    private : key repo is created private -> anonymous fetch returns 404.
    missing : key repo is not created at all -> fetch returns 404.
    """
    doc_url, namespace = _create_repo_with_file(
        f"{prefix}-document", "document.json", document,
        "COMP-SEC sandbox-escape demo: encrypted document (decoy data)",
    )

    if key_state == MISSING:
        # Never create the key repo. Point at where it would be.
        key_url = f"{GITLAB_HOST}/{namespace}/{prefix}-key/-/raw/main/key.txt"
        return doc_url, key_url

    visibility = "private" if key_state == PRIVATE else "public"
    key_url, _ = _create_repo_with_file(
        f"{prefix}-key", "key.txt", key_blob,
        "COMP-SEC sandbox-escape demo: decryption key (decoy data)",
        visibility=visibility,
    )
    return doc_url, key_url
