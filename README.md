# Gotzi

A **Wireshark-like** toolkit for **security, scanning, and traffic analysis** — one **web UI** and one **CLI**. Capture, digest, visualize, scan, discover; optional attack simulation (authorized only). Data stored in PostgreSQL when needed. Dockerized, Python via Poetry.

## Features

- **Capture** — Live packet capture (UDP), optional DB stream; probe server/client for RTT.
- **Scan** — Port scanner (TCP/UDP), scan history, diff between scans.
- **Discovery** — Ping sweep + port scan on CIDR/IP/range; optional HTTP titles.
- **Digest** — Traffic summary from CSV or capture (packet count, loss, RTT).
- **Web UI** — Single page: Capture, Scan, Discovery, Digest, Sessions, Config.
- **Attack** (Tier 3) — Flood, port-knock, slowloris, replay; audit-logged.
- **Rules** — IDS-style rules (payload regex, port); list/add/delete/matches.
- **Honeypot** — Fake open ports; log connection attempts.

## Quick start

### Poetry (local)

```bash
cd udp-probe
poetry install
# Start Postgres (e.g. docker run -d -p 5432:5432 -e POSTGRES_USER=probe -e POSTGRES_PASSWORD=probe -e POSTGRES_DB=probe postgres:16-alpine)
poetry run gotzi init          # Create DB tables (if applicable)
poetry run gotzi serve         # Web API + UI at http://0.0.0.0:8000
```

### CLI (same backend)

```bash
poetry run gotzi scan 127.0.0.1 --ports 1-1024
poetry run gotzi discover 192.168.1.0/24
poetry run gotzi digest udp_session.csv
poetry run gotzi config
poetry run gotzi scan-history
poetry run gotzi attack flood 192.168.1.1 --port 80 --duration 5
```

### Docker (app + Postgres)

```bash
cd udp-probe
docker compose -f docker/docker-compose.yml up -d
# Web UI: http://localhost:8000
```

Set `PROBE_DATABASE_URL` to your Postgres URL (default in Compose: `postgresql://probe:probe@postgres:5432/probe`).

## Project layout

```
udp-probe/
├── pyproject.toml
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── entrypoint.sh
├── docs/
│   ├── PLAN.md
│   ├── ARCHITECTURE.md
│   └── FEATURES.md
└── src/udp_probe/
    ├── main.py              # CLI (gotzi)
    ├── api/
    │   ├── app.py           # FastAPI app + routes + web UI
    │   ├── routes/          # capture, scan, discovery, digest, config
    │   ├── routers/         # attack, rules, honeypot
    │   └── templates/       # index.html (single-page UI)
    ├── capture/             # sniffer, probe_server, probe_client
    ├── scan/                # port scanner
    ├── discovery/           # network discovery
    ├── digest/              # CSV/capture analyzer
    ├── attack/              # flood, slowloris, replay, audit
    ├── rules/               # IDS rules engine
    ├── honeypot/             # fake ports, log connections
    ├── core/                 # config, database
    └── models/               # SQLAlchemy models
```

## Config

Env (or `.env`): `PROBE_HOST`, `PROBE_PORT`, `PROBE_DATABASE_URL`, `PROBE_PROBE_HOST`, `PROBE_PROBE_PORT`, etc. See `udp_probe.core.config.Settings`.

## Requirements

- Python 3.10+
- PostgreSQL (for persistence)
- Root/cap_net_raw for raw packet capture

See `pyproject.toml` and `docs/PLAN.md` for the full roadmap and tiers.
