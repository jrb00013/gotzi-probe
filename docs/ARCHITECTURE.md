# Architecture

## Overview

Single backend (FastAPI) serves both the **web UI** and the **CLI** (via shared Python modules or HTTP). Data is stored in **PostgreSQL** when needed; raw PCAP can stay on disk. Everything runs in **Docker** (app + DB); Python is managed with **Poetry**.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Clients                                    │
│  ┌──────────────┐                    ┌─────────────────────────┐ │
│  │   Web UI     │                    │   CLI (gotzi)            │ │
│  │  (browser)   │                    │  capture, scan, attack…  │ │
│  └──────┬───────┘                    └────────────┬─────────────┘ │
│         │ HTTP/WS                                 │ HTTP or       │
│         │                                         │ direct import │
└─────────┼─────────────────────────────────────────┼───────────────┘
          │                                         │
          ▼                                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Backend (FastAPI)                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐  │
│  │ Capture │ │  Scan   │ │Discovery│ │ Attack  │ │  Alerts   │  │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └─────┬─────┘  │
│       │           │           │           │             │        │
│       └───────────┴───────────┴───────────┴─────────────┘        │
│                              │                                    │
│                    ┌─────────┴─────────┐                          │
│                    │  Core / Config    │                          │
│                    │  DB Session       │                          │
│                    └─────────┬─────────┘                          │
└──────────────────────────────┼────────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
   │  PostgreSQL │      │  PCAP files │      │  Logs       │
   │  (Docker)   │      │  (volume)   │      │  (stdout)   │
   └─────────────┘      └─────────────┘      └─────────────┘
```

---

## Components

### 1. Web UI

- **Single app:** One frontend (SPA or server-rendered with HTMX/Jinja).
- **Tabs/sections:** Capture, Scans, Discovery, Traffic Viz, Security Scan, Attack Sim, Alerts, Config, DB/Export.
- **Real-time:** WebSockets or SSE for live packet stats and charts.
- **Calls:** REST (and optionally WebSocket) to the FastAPI backend.

### 2. CLI

- **Entrypoint:** `gotzi` from Poetry script.
- **Subcommands:** `capture`, `scan`, `discover`, `digest`, `attack`, `alerts`, `config`, `export`.
- **Modes:**
  - **API mode:** CLI calls backend HTTP (e.g. `probe --api http://localhost:8000 scan ...`).
  - **Local mode:** CLI imports and runs the same Python modules as the server (no HTTP). Useful for one-machine use.

### 3. Backend (FastAPI)

- **API routes:** Grouped by domain (capture, scan, discovery, attack, alerts, config).
- **Shared core:** Config (env + file), DB session (SQLAlchemy async or sync), logging.
- **Background:** Capture and long scans can run in background tasks or a small worker; state in DB or Redis later.

### 4. PostgreSQL

- **Role:** Store capture metadata, optional packet rows, scan results, security findings, alerts, attack audit, honeypot events.
- **Size:** Kept small with retention (e.g. drop old packets, aggregate old scans).
- **Connection:** Single connection pool from the app; URL from env in Docker.

### 5. PCAP & Files

- **PCAP:** Stored on a volume (e.g. `./data/pcap`); DB stores path and metadata.
- **Config:** Optional `config.json` or env-only; overridable via API/CLI.

---

## Data Flow Examples

### Capture

1. User starts capture (Web or CLI) → API creates DB row and starts sniffer task.
2. Sniffer writes PCAP to disk and optionally pushes packet metadata (or samples) to Postgres.
3. User stops capture → API stops task, updates DB row, closes PCAP.

### Port scan

1. User submits target + range (Web or CLI) → API enqueues or runs scan.
2. Scanner runs TCP/UDP checks, writes results to `scan_results` (and related).
3. Web/CLI polls or gets result by ID; history and diff use same tables.

### Traffic visualization

1. Data source: live (sniffer → WebSocket) or historical (DB queries).
2. Backend aggregates (e.g. packets per second, top IPs) and sends to frontend.
3. Charts and tables render in the single web UI.

---

## Docker

- **Images:**
  - **App:** Dockerfile based on Python; Poetry install (or exported `requirements.txt`); run `uvicorn` + optional worker.
  - **Postgres:** Official `postgres:16-alpine` (or similar); one database, one user.
- **Compose:**
  - Services: `app`, `postgres`.
  - App depends on `postgres`; env: `DATABASE_URL`, optional `REDIS_URL`, feature flags.
  - Volumes: Postgres data, PCAP output, optional config.
- **Network:** Host or bridge; capture may need `network_mode: host` or capability `NET_RAW` for raw sockets (document security implications).

---

## Poetry

- **Root:** Single `pyproject.toml` at repo root.
- **Dependencies:** FastAPI, uvicorn, SQLAlchemy, psycopg2 (or async), scapy (or raw socket), typer/click for CLI, and dev (pytest, ruff, etc.).
- **Scripts:**
  - `gotzi` → `udp_probe.main:app`.
  - Optional: `run-web` → `uvicorn udp_probe.api:app`.
- **No global install:** Use `poetry install` and `poetry run probe` (or activate shell).

---

## Security Considerations

- **Attack features:** Only for authorized targets; clear warnings in UI/CLI; audit log in DB.
- **Network:** Raw capture and attack tools often need elevated caps or root; document and limit exposure (e.g. no unnecessary host network in prod).
- **Secrets:** DB password and API keys in env (or secret manager); not in repo.
- **Auth (future):** If added, same auth for Web and API; CLI can use API key or local-only mode.

---

## Optional Later

- **Redis:** For job queue (Celery/RQ) and live pub/sub.
- **Auth:** JWT or session-based for Web + API.
- **Multi-tenant:** Separate DB or schema per “workspace” if needed.
