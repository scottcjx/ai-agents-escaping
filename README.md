# AI Agents Escaping the Sandbox -- COMP-SEC Demo

This project is a safe classroom demonstration. It models the July 2026
OpenAI x Hugging Face incident. In that incident, an AI agent left its
evaluation sandbox, abused a package-registry proxy, and reached systems it
must not reach.

The demonstration uses two Docker containers and a real network boundary. It is
not a simulation of the network. The isolated container truly has no internet.
Use decoy data only.

Explanations use Simplified Technical English (ASD-STE100).

> **Safety note.** The demo publishes a document and a key to the public
> internet. Any person with both links can decrypt the message. Never put real
> or sensitive data in the demo.

---

## 1. The real incident (what this models)

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  REAL INCIDENT (July 2026)                                        │
   │                                                                   │
   │   AI agent in an eval sandbox                                     │
   │        │                                                          │
   │        │ (1) escapes the sandbox egress filter                   │
   │        ▼                                                          │
   │   package-registry proxy  ──(2) relays to the real internet──▶    │
   │        │                                                          │
   │        ▼                                                          │
   │   stolen credentials + a zero-day  ──(3)──▶  Hugging Face breach  │
   └─────────────────────────────────────────────────────────────────┘
```

The core failure is an **egress allow-list that trusts a substring**. The agent
crafts a URL that contains the trusted name but still resolves to a different
host. The filter sees the trusted name and allows the request.

## 2. How the demo maps to the incident

| Real incident | This demo |
|---------------|-----------|
| AI agent in an eval sandbox | `agent` container, on an internal-only network, no internet |
| Package-registry proxy with internet | `proxy` container ("artifactory"), on both networks |
| Weak egress allow-list | substring check of the whole URL in `proxy_server.py` |
| The escape | a `#mirror.internal.corp` URL fragment that the filter trusts |
| The stolen secret | a key published to a second public location |
| The breach | the agent fetches the document and the key, then decrypts |
| The fix | `SAFE=1` checks the real host only, so the escape is refused |

## 3. Architecture

```
   HOST (has internet)
   ├─ publisher ── encrypts the message, publishes 2 parts to the internet,
   │               writes .env (document URL, key URL, checksum, key state)
   └─ dashboard ── runs the containers, streams every log line to a web page

   docker compose
   ┌────────────────────────┐   internal net      ┌───────────────────────┐
   │  AGENT                 │   (no route out)     │  PROXY (artifactory)  │
   │  no internet           │ ──HTTP /fetch (IPC)─▶│  has internet         │
   │  proves its isolation  │                      │  egress allow-list    │
   │  escapes, decrypts     │                      │                       │
   └────────────────────────┘                      └──────────┬────────────┘
                                                               │ egress net
                                                               ▼
                                             paste.rs / GitLab (public)
                                             document.json   +   key.txt
```

- The `internal` network is created with `internal: true`. Docker gives it no
  route to the internet. The agent joins this network only.
- The `proxy` joins two networks. So the agent can reach the proxy, and the
  proxy can reach the internet.
- Before the escape, the agent runs `ip route`, `ping`, and a TCP test. Each
  test must fail. This proves the boundary is real.

## 4. Quick start

Install Docker Desktop and start it. Then:

```bash
cd docker

# Option A -- live dashboard (three panels: agent, proxy, host)
./dashboard.sh                 # opens http://localhost:8750

# Option B -- terminal
./run.sh --message "COMP-SEC demo. Decoy data only."
```

## 5. The three outcomes

| Condition | Result | Exit code |
|-----------|--------|-----------|
| Key public, proxy vulnerable | COMPROMISED -- the agent recovers the message | 0 |
| Key private or missing | FAILED -- the agent escapes, but no key to decrypt | 20 |
| Proxy mitigated (`SAFE=1`) | CONTAINED -- the proxy refuses the escape | 10 |

Full command list, the escape detail, and the file map are in
[docker/README.md](docker/README.md).

## 6. Layout

```
ai-agents-escaping/
├─ README.md            this file -- the overview
└─ docker/              the demo (the only iteration)
   ├─ README.md         how to run it, the escape, the results table
   ├─ docker-compose.yml
   ├─ agent/            the isolated AI agent container
   ├─ proxy/            the artifactory proxy container
   ├─ publisher/        the host script that publishes the 2 parts
   ├─ common/           shared cipher + publish code (one source of truth)
   ├─ dashboard/        the live web view
   ├─ run.sh            terminal mode
   └─ dashboard.sh      dashboard mode
```
