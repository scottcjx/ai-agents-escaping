# Containerised Sandbox-Escape Demo

Two Docker containers. One container has no internet. The other container is the
proxy and has internet. The isolated container escapes through the proxy, fetches
a document and a key from the internet, and decrypts the message. This is a real
network boundary, not a simulation.

Explanations use Simplified Technical English (ASD-STE100).

## Containers and networks

```
                    ┌──────────────── docker compose ────────────────┐
                    │                                                 │
   ┌────────────────┴─────┐   internal net        ┌──────────────────┴────┐
   │  AGENT                │   (internal: true,    │  PROXY  (artifactory) │
   │  no internet          │    no route out)      │  has internet         │
   │  one path out: proxy  │ ──HTTP /fetch (IPC)──▶ │  egress allow-list    │
   │  decrypts the message │                        │                       │
   └──────────────────────┘                        └───────────┬───────────┘
                                                                │ egress net
                                                                ▼
                                                   paste.rs  /  GitLab (public)
                                                   document.json   +   key.txt
```

- The `internal` network is created with `internal: true`. Docker gives it no
  route to the internet. The agent joins this network only. So the agent has
  no internet.
- The `proxy` joins two networks: the internal network and an egress network
  with internet. The agent can reach the proxy. The proxy can reach the
  internet.
- The link between the containers is HTTP over the internal network. This is
  the inter-process channel. It is not the internet.

## The escape

The proxy must fetch only from the internal mirror host. The weak allow-list
checks the full URL text for the mirror name. The agent adds the mirror name in
a URL fragment. The proxy does not send the fragment to the upstream server. So
the real server answers, but the allow-list sees the trusted name.

```
 agent asks proxy for:  https://paste.rs/abc  #mirror.internal.corp
                        └──── real target ───┘ └──── fragment ─────┘
   proxy checks whole text ─▶ finds the mirror name ─▶ ALLOW
   upstream gets only the path ─▶ returns the file
   SAFE=1: proxy checks the HOST only ─▶ not the mirror ─▶ DENY (403)
```

## Prepare

Install Docker Desktop and start it. Then publish once and run:

```bash
cd docker
./run.sh --message "COMP-SEC demo. Decoy data only."
```

`run.sh` does two things. It publishes the document and the key to the internet
from the host. Then it builds and starts the two containers.

## Live dashboard (see all nodes at once)

Start one web page with three live panels: the agent, the proxy, and the host.
Each panel streams in real time. Buttons start each scenario.

A live diagram sits above the panels. It shows four nodes: the host, the agent,
the proxy, and the internet. As the run proceeds, the nodes light up and packets
move along the links. The direct link from the agent to the internet stays
blocked. A step tracker below the diagram fills in: publish, prove isolation,
escape to the document, escape to the key, decrypt, result. Click a node to
flash its terminal panel.

```bash
cd docker
chmod +x dashboard.sh
./dashboard.sh          # opens http://localhost:8750
```

Click a button:

- **Key public → compromise** -- the agent recovers the message.
- **Key missing → fail** -- the agent escapes, but the key is gone.
- **Mitigated proxy → contained** -- the proxy refuses the escape.

The dashboard runs on the host. It publishes the parts, runs the containers,
and relays every log line to the browser. Stop it with Ctrl-C.

## Demonstrations (terminal)

Key is public. The agent recovers the message:

```bash
./run.sh --message "..."
```

Key repository is missing. The agent escapes but cannot decrypt:

```bash
./run.sh --message "..." --break-key missing
```

Key repository is private (GitLab). Same failure:

```bash
./run.sh --message "..." --backend gitlab --break-key private
```

Mitigated proxy. The escape is refused:

```bash
SAFE=1 ./run.sh --message "..."
```

## Results

| Condition | Agent outcome | Exit code |
|-----------|---------------|-----------|
| Key public, proxy vulnerable | COMPROMISED (message recovered) | 0 |
| Key private or missing | FAILED (no key to decrypt) | 20 |
| Proxy mitigated (`SAFE=1`) | CONTAINED (escape refused) | 10 |

### Step 0 proof -- the agent has no internet

Before the escape, the agent runs real network commands. The commands try to
reach the internet directly. Each command must fail. This proves the boundary
is real, not a simulation.

```
 AGENT container (must FAIL)            PROXY container (must PASS)
 ----------------------------            ---------------------------
 $ ip -4 route                           connect 1.1.1.1:443  -> open
     172.18.0.0/16 dev eth0              ping -c1 1.1.1.1     -> reply
     (no default route out)                  64 bytes from 1.1.1.1 ...
 $ ping -c2 1.1.1.1                          0% packet loss
     connect: Network is unreachable
 TCP 1.1.1.1:443   -> unreachable
 GET proxy/healthz -> ok  (the one path out)
```

The agent sees the same public address `1.1.1.1` as **unreachable**. The proxy
sees it **reply**. The agent can reach only the proxy. This is the teaching
point: the container boundary, not the application, blocks the internet.

## Files

| Path | Function |
|------|----------|
| `docker-compose.yml` | Two services and two networks. `internal: true` gives the agent no internet. |
| `proxy/proxy_server.py` | The artifactory proxy and its egress allow-list. `SAFE=1` enables the fix. |
| `agent/agent_main.py` | The agent. It proves isolation, escapes, fetches both parts, and decrypts. |
| `publisher/publish_cli.py` | Host script. It encrypts, publishes, and writes `.env`. |
| `common/` | Single source of truth: `crypto_demo.py` and `publish.py`. The host publisher imports both. The agent image copies `common/crypto_demo.py`, so the cipher never drifts. |
| `dashboard/` | The live web dashboard (`server.py` + `index.html`). |
| `run.sh` | Publish, then start the containers (terminal mode). |
| `dashboard.sh` | Start the live dashboard. |
| `.env` | Generated by the publisher each run. Holds the document URL, key URL, checksum, and key state. |

## Clean up GitLab repos

After a GitLab run, delete the two repositories when the class ends:

```bash
glab repo delete <you>/sandbox-escape-demo-document
glab repo delete <you>/sandbox-escape-demo-key
```

## Safety

The public backends make the document and the key world-readable. The key is
published too, so any person with both URLs can decrypt the message. Use decoy
data only.
