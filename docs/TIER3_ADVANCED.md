# Tier 3 — Advanced Features (PLAN.md bottom-up)

Integrated per **docs/PLAN.md** Tier 3: security-oriented scan, attack simulation, IDS-style rules, honeypot. All attack features are **audit-logged** and must be used only on **authorized targets**.

## New models (PostgreSQL)

- **rules** / **rule_matches** — IDS rules (payload_regex, port, protocol) and match log
- **honeypot_events** — connection attempts to fake ports
- **security_findings** — open dangerous ports / security scan results
- **attack_sessions** — already existed; used for all attack audit logs

Run `init_db()` (or migrations) so these tables exist.

## Packages

- **`udp_probe.attack`** — `run_udp_flood`, `run_tcp_flood`, `run_port_knock`, `run_slowloris`, `run_replay_file`, `run_replay_pcap` (scapy optional). All call `log_attack_session` / `end_attack_session`.
- **`udp_probe.rules`** — `list_rules`, `add_rule`, `delete_rule`, `enable_rule`, `run_rules_on_packet`, `list_rule_matches`. Engine matches on payload regex, port, protocol.
- **`udp_probe.honeypot`** — `run_honeypot(ports, protocols)`, `stop_honeypot`. Fake TCP/UDP listeners log to `honeypot_events`.
- **`udp_probe.scan`** — `run_security_scan(target, port_range?, scan_id?)`. TCP connect check on dangerous ports; writes `security_findings`.

## API (FastAPI)

- **`udp_probe.api.create_app()`** — includes routers:
  - **`/attack`** — POST `/flood`, `/port-knock`, `/slowloris`, `/replay`; GET `/sessions`
  - **`/rules`** — GET/POST/DELETE/PATCH rules; GET `/matches`
  - **`/honeypot`** — POST `/start`, `/stop`; GET `/events`

Mount `create_app()` in the main web app (e.g. `from udp_probe.api import create_app; app = create_app()` or include these routers in an existing app).

## CLI (`probe`)

- **`probe attack flood`** — `--port`, `--duration`, `--protocol` (udp/tcp)
- **`probe attack port-knock`** — `--ports 1000,1001,1002`, `--protocol`, `--delay`
- **`probe attack slowloris`** — `--port`, `--duration`, `--sockets`
- **`probe attack replay`** — target + replay file path, `--delay`
- **`probe rules list|add|delete|enable|matches`**
- **`probe honeypot start|stop|events`** — ports as comma-separated
- **`probe scan-security <target>`** — run security scan, print findings

Warnings are printed for attack commands (authorized use only).

## Integration with the rest of the app (implemented)

- **Capture pipeline:** When `store_in_db=True` and `run_rules=True`, the sniffer (`udp_probe.capture.sniffer`) calls `run_rules_on_packet(...)` after each packet is stored, so IDS rules run on every captured packet. Enable via API: `POST /api/capture/start` with `run_rules=true` and `store_in_db=true`.
- **Web UI:** Root `web/` is a full tabbed UI: **Capture** (packet list, detail, hex), **Attack** (flood, port knock, slowloris, audit list), **Rules** (add rule, list rules, list matches), **Honeypot** (start/stop, events table), **Security** (target + run scan, findings table). Root `web_server.py` mounts Tier 3 routers and calls `init_db()` when `udp_probe` is available and DB is configured.
- **DB init:** `create_app()` (src) uses a lifespan that runs `init_db()`. Root `web_server.py` calls `init_db()` before including Tier 3 routers when the package is importable.

## Legal / ethical

All attack and interception features require **explicit target authorization** and **clear warnings** in UI and CLI. Attack sessions are stored in `attack_sessions` for audit.
