# Gotzi — Product Plan & Roadmap

**Vision:** A Wireshark-like toolkit for **security, scanning, and traffic analysis** — all controllable from **one web UI** and **one CLI**. Capture, digest, visualize, and (for authorized testing) attack traffic; store what you need in a small PostgreSQL DB. Fully Dockerized, Python via Poetry.

---

## 1. Feature Tiers (Basic → Advanced)

### Tier 1 — Foundation (Basic)

| Feature | Description | Web | CLI | DB |
|--------|-------------|-----|-----|-----|
| **Live packet capture** | Sniff UDP (extend to TCP/ICMP) with BPF-style filters | Start/stop, filters | `capture --interface eth0 --filter udp` | Optional stream to DB |
| **Port scanner** | Single host / small range (e.g. 1–1024), TCP connect + UDP probe | Target, range, scan button | `scan --target 192.168.1.1 --ports 1-1024` | Store scan results |
| **Traffic digest/summary** | Packet count, bytes, top talkers, basic RTT/loss (build on existing probe) | Dashboard widgets | `digest --pcap file.pcap` or live | Optional summary tables |
| **Config & targets** | Manage scan targets, capture filters, output paths (evolve `config.json`) | Settings page | `config set/get` | — |

*Builds on: `udp_probe_server.py`, `udp_probe_client.py`, `packet_sniffer.py`, `csv_analyzer.py`.*

---

### Tier 2 — Monitoring & Storage (Intermediate)

| Feature | Description | Web | CLI | DB |
|--------|-------------|-----|-----|-----|
| **Persistent capture** | Save to PCAP and/or stream packets to Postgres (metadata + optional payload) | Session list, download PCAP | `capture --output session_01 --db` | `captures`, `packets` tables |
| **Traffic monitoring dashboard** | Real-time charts: packets/s, bytes/s, top IPs/ports, protocol breakdown | Live charts (e.g. Chart.js / similar) | — | Read from DB or live stream |
| **Scan history & diff** | Store every scan, compare “before/after” (e.g. new open ports) | Scan history, compare view | `scan --save`, `scan diff id1 id2` | `scans`, `scan_results` |
| **Alerting (simple)** | Thresholds: e.g. “port scan detected”, “> N failed connections/min” | Configure thresholds, log | `alerts list` | `alerts`, `alert_rules` |
| **Network discovery** | Build on `discover_network_devices.py`; ARP/ping sweep, optional OS fingerprint | Discovery tab, device list | `discover --range 192.168.1.0/24` | `hosts`, `discovery_runs` |

---

### Tier 3 — Security & Attack Simulation (Advanced)

| Feature | Description | Web | CLI | DB |
|--------|-------------|-----|-----|-----|
| **Security-oriented scan** | Service/version detection, script-like checks (e.g. weak TLS, open dangerous ports) | “Security scan” mode, report | `scan --security --target x.x.x.x` | `security_findings` |
| **Traffic replay / attack simulation** | Replay PCAP, flood (UDP/TCP), slowloris-style, port knocking sequences | “Attack” tab with warnings + target form | `attack flood --target x --port y --duration 60` | `attack_sessions` (audit) |
| **Traffic interception (MITM-style)** | Optional proxy mode for HTTP/HTTPS (with cert) to inspect/modify (clearly “lab use”) | Proxy config, request/response viewer | `proxy start --port 8080` | Optional `requests` table |
| **IDS-style rules** | Simple rule engine: match packet patterns → alert or tag (e.g. regex on payload, port) | Rule editor, enable/disable | `rules add/list/run` | `rules`, `rule_matches` |
| **Honeypot mode** | Fake open ports / services; log connection attempts for analysis | Honeypot config, connection log | `honeypot start --ports 22,80` | `honeypot_events` |

*Legal/ethical: All attack and interception features must require explicit target authorization and clear warnings in UI/CLI.*

---

## 2. Single Web UI & Single CLI

- **Web:** One SPA or server-rendered app (e.g. FastAPI + Jinja + HTMX, or FastAPI + React/Vue). Tabs/sections: Capture, Scans, Discovery, Traffic Viz, Security Scan, Attack Sim, Alerts, Config, DB/Export.
- **CLI:** One entrypoint (e.g. `udp-probe` or `probe`) with subcommands: `capture`, `scan`, `discover`, `digest`, `attack`, `alerts`, `config`, `export`, etc. Same backend APIs as the web UI where it makes sense.
- **Control plane:** Backend service (FastAPI) that both Web and CLI talk to; optional “local-only” mode where CLI talks to the same process or a small daemon.

---

## 3. Data & Storage (PostgreSQL)

- **Small Postgres:** One instance (e.g. in Docker); schema for:
  - **Sessions/captures:** `id`, `name`, `started_at`, `stopped_at`, `filter`, `pcap_path`, `packet_count`.
  - **Packets (optional):** Sampled or full; `capture_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `length`, `payload_hash` or `payload_snippet`.
  - **Scans:** `id`, `target`, `port_range`, `started_at`, `results` (JSON or normalized table).
  - **Security findings, alerts, rules, attack sessions, honeypot events** as above.
- **“Store as needed”:** Configurable retention; raw packets optional (e.g. only metadata or last N minutes in DB; full PCAP on disk).

---

## 4. Visualizing Data / Traffic

- **Live:** Packets/s, bytes/s, top IPs/ports, protocol pie chart (from live capture or DB).
- **Historical:** Time-series of traffic and scan results; simple flow/timeline view of who talked to whom.
- **Scan/security:** List of open ports, service names, risk tags; diff view between two scans.
- **Export:** CSV/JSON from any view; PCAP download for captures.

---

## 5. Docker & Poetry

- **Poetry:** Single `pyproject.toml` at repo root; all app and dev dependencies; scripts for `probe` CLI and (if desired) `uvicorn` web.
- **Docker:** 
  - **App image:** Multi-stage; Poetry export to `pip install -r requirements.txt` (or Poetry install) in image; run web + worker/capture processes.
  - **Postgres:** Official image; one volume for data; env for user/password/db name.
  - **Compose:** `app` + `postgres`; app depends on Postgres; optional `redis` later for queues/cache. Env file for DB URL and feature flags (e.g. enable_attack_ui).

---

## 6. Suggested Repo Layout (After Refactor)

```
udp-probe/
├── pyproject.toml          # Poetry; CLI entrypoint "probe"
├── README.md
├── docs/
│   ├── PLAN.md             # This file
│   ├── ARCHITECTURE.md     # Components, APIs, DB schema
│   └── FEATURES.md         # Detailed feature list & API surface
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── src/
│   └── udp_probe/
│       ├── __init__.py
│       ├── main.py         # CLI (Typer/Click)
│       ├── api/            # FastAPI app, routes
│       ├── core/           # Config, DB connection, logging
│       ├── capture/        # Sniffer, PCAP write, DB stream
│       ├── scan/           # Port scan, security scan
│       ├── discovery/      # Network discovery
│       ├── attack/         # Flood, replay, etc. (guarded)
│       ├── alerts/         # Rules, threshold checks
│       └── models/         # SQLAlchemy or similar
├── web/                    # Frontend (if SPA) or templates under api/
└── tests/
```

---

## 7. Implementation Order (Suggested)

1. **Poetry + layout:** Move existing scripts into `src/udp_probe`, add `pyproject.toml`, single CLI entrypoint.
2. **Postgres + core:** Schema (captures, packets, scans), connection from app, config via env.
3. **FastAPI backend:** Minimal app; endpoints for capture (start/stop), scan (run), and config.
4. **Web UI (minimal):** One page with Capture and Scan sections; call API from browser.
5. **CLI:** Subcommands that call same API or shared Python modules.
6. **Digest + dashboard:** Traffic summary, live charts, optional DB storage for packets.
7. **Docker:** Dockerfile + Compose for app + Postgres.
8. **Security scan + alerts:** Extended scan logic, simple rules, alert storage.
9. **Attack simulation:** Isolated module; UI/CLI warnings and audit logging.
10. **Honeypot / IDS-style rules:** After core traffic and scan pipeline is stable.

---

## 8. Out of Scope (For Now)

- Full Wireshark-level dissection (thousands of protocols); focus on IP/TCP/UDP and key headers.
- Distributed deployment; single-node first.
- User auth (optional later); assume trusted environment or add later.
- Official “pentest distribution” packaging; this is a toolkit, not a replacement for legal/process.

---

## 9. Success Criteria

- One URL and one CLI to: start/stop capture, run port/security scans, see traffic summary and history.
- All persistent data (as needed) in one small Postgres DB.
- One `docker compose up` to run app + DB.
- Clear separation between “monitoring/digesting” and “attack simulation,” with explicit controls and warnings.
