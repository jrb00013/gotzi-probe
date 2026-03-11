# Feature Specification & API Surface

Detailed feature list and how they are exposed on **Web** and **CLI**, and what is stored in **DB**.

---

## Tier 1 — Foundation

### 1.1 Live packet capture

- **Behavior:** Sniff packets (UDP first; extend to TCP/ICMP) with optional BPF-style filter (e.g. `udp`, `port 53`, `host 192.168.1.1`). Output: live log and/or PCAP file.
- **Web:** Form: interface, filter string, “Start” / “Stop”. Status and packet count; optional live tail.
- **CLI:** `probe capture --interface eth0 --filter "udp port 53" [--output session_01] [--db]`
- **DB:** Optional: `captures` row (name, started_at, filter, pcap_path, packet_count); `packets` only if `--db`.

### 1.2 Port scanner

- **Behavior:** TCP connect scan and UDP probe (single host or small range, e.g. 1–1024 or 1–10000). Result: open/closed/filtered per port.
- **Web:** Form: target (IP/host), port range (e.g. `1-1024`), scan type (TCP/UDP/both). Button “Run”; results table + “Save” to DB.
- **CLI:** `probe scan --target 192.168.1.1 [--ports 1-1024] [--tcp] [--udp] [--save]`
- **DB:** `scans` (id, target, port_range, type, started_at, finished_at), `scan_results` (scan_id, port, state, service optional).

### 1.3 Traffic digest / summary

- **Behavior:** From live capture or PCAP: packet count, byte count, top N source/dest IPs and ports, basic RTT/loss (for probe traffic). Reuse existing analyzer logic.
- **Web:** “Digest” panel: upload PCAP or select live session; show summary and top talkers.
- **CLI:** `probe digest [--pcap file.pcap] [--live capture_id] [--json]`
- **DB:** Optional summary rows (e.g. `capture_summaries`: capture_id, packet_count, byte_count, top_ips json).

### 1.4 Config & targets

- **Behavior:** Manage config: default interface, default port range, log paths, DB store on/off. Optional “targets” list (friendly names + IP/ranges).
- **Web:** Settings page: key-value or form; optional target list (name, host, tags).
- **CLI:** `probe config set key value`, `probe config get key`, `probe config list`
- **DB:** Optional `settings` table or keep in file/env only.

---

## Tier 2 — Monitoring & Storage

### 2.1 Persistent capture (PCAP + DB)

- **Behavior:** Same as 1.1 but always write PCAP; optionally stream packet metadata (and optionally payload snippet) to Postgres for querying.
- **Web:** “Save to DB” checkbox; after stop, session appears in “Captures” list with download PCAP link.
- **CLI:** `probe capture ... --output name --db [--sample 0.1]` (e.g. 10% to DB).
- **DB:** `captures`; `packets` (capture_id, ts, src_ip, dst_ip, src_port, dst_port, protocol, length, payload_snippet or hash).

### 2.2 Traffic monitoring dashboard

- **Behavior:** Real-time (and short-term historical) charts: packets/s, bytes/s, top IPs, top ports, protocol breakdown. Data from live sniffer (WebSocket) or from DB.
- **Web:** Dashboard tab: time-series charts (e.g. Chart.js), tables for top N.
- **CLI:** No direct equivalent; optional `probe stats --live` text output.
- **DB:** Read from `packets` (aggregated) or in-memory ring buffer for “last N minutes”.

### 2.3 Scan history & diff

- **Behavior:** Every scan (when saved) stored; UI to pick two scans and diff (new open, newly closed, unchanged).
- **Web:** “Scan history” list; “Compare” pick two → diff view.
- **CLI:** `probe scan history [--target x]`, `probe scan diff <id1> <id2>`
- **DB:** `scans`, `scan_results`; diff computed on read.

### 2.4 Simple alerting

- **Behavior:** Threshold or pattern: e.g. “port scan” (many ports in short time), “> N failed TCP connections/min”. Write to alert log and optional DB.
- **Web:** “Alerts” tab: list recent; “Rules” subpage to add/edit threshold rules.
- **CLI:** `probe alerts list`, `probe alerts rules add ...`
- **DB:** `alert_rules`, `alerts` (time, rule_id, message, metadata).

### 2.5 Network discovery

- **Behavior:** ARP and/or ping sweep over a subnet; optional OS/service hints. Build on existing `discover_network_devices.py`.
- **Web:** “Discovery” tab: subnet input, “Run”; device table (IP, MAC, hostname, status).
- **CLI:** `probe discover --range 192.168.1.0/24 [--arp] [--ping]`
- **DB:** `discovery_runs`, `hosts` (run_id, ip, mac, hostname, last_seen).

---

## Tier 3 — Security & Attack Simulation

### 3.1 Security-oriented scan

- **Behavior:** Deeper scan: service/version probe, script-like checks (e.g. weak TLS, default creds risk, dangerous open ports). Output: list of “findings” with severity.
- **Web:** “Security scan” mode: target + profile (quick/full); results as findings table with severity.
- **CLI:** `probe scan --security [--profile full] --target x.x.x.x`
- **DB:** `security_scans`, `security_findings` (scan_id, port, type, severity, detail).

### 3.2 Traffic replay / attack simulation

- **Behavior:** Replay PCAP; or synthetic: UDP/TCP flood, slowloris-style, port-knock sequence. **Warnings:** authorized targets only; audit log.
- **Web:** “Attack” tab: disclaimer; form: type (flood/replay/…), target, port, duration; “Run” → audit logged.
- **CLI:** `probe attack flood --target x --port y [--duration 60]`, `probe attack replay --pcap f.pcap`
- **DB:** `attack_sessions` (id, type, target, port, started_at, ended_at, params, operator).

### 3.3 Traffic interception (proxy)

- **Behavior:** HTTP/HTTPS proxy; decrypt with local CA; show request/response (and optionally modify). Lab use only; clear warning.
- **Web:** “Proxy” tab: port, CA info; request/response list and body viewer.
- **CLI:** `probe proxy start --port 8080 [--ssl-inspect]`
- **DB:** Optional `requests` (url, method, time, request_size, response_size).

### 3.4 IDS-style rules

- **Behavior:** Simple rules: match packet (e.g. port, IP, regex on payload) → alert or tag. Run against live capture or PCAP.
- **Web:** Rule editor (add/edit/disable); “Run rules” on capture or upload; matches listed.
- **CLI:** `probe rules add "udp and port 53" --tag dns`, `probe rules run --pcap f.pcap`
- **DB:** `rules` (name, expression, tag, enabled), `rule_matches` (rule_id, capture_id, packet_ref, time).

### 3.5 Honeypot mode

- **Behavior:** Bind to ports (e.g. 22, 80); accept connections and log (IP, port, timestamp, optional payload). No real services.
- **Web:** “Honeypot” config: port list, “Start”/“Stop”; connection log table.
- **CLI:** `probe honeypot start --ports 22,80,443`
- **DB:** `honeypot_events` (port, src_ip, time, payload_snippet).

---

## API Surface (REST, high-level)

| Area | Methods | Endpoints (examples) |
|------|---------|----------------------|
| Capture | POST, GET, DELETE | `POST /capture/start`, `POST /capture/stop`, `GET /capture/sessions`, `GET /capture/{id}/stats` |
| Scan | POST, GET | `POST /scan/run`, `GET /scan/history`, `GET /scan/{id}`, `GET /scan/diff?id1=&id2=` |
| Discovery | POST, GET | `POST /discovery/run`, `GET /discovery/hosts` |
| Digest | POST, GET | `POST /digest` (body: pcap or capture_id), `GET /digest/{id}` |
| Alerts | GET, POST | `GET /alerts`, `GET /alerts/rules`, `POST /alerts/rules` |
| Attack | POST, GET | `POST /attack/run` (body: type, target, params), `GET /attack/sessions` |
| Config | GET, PUT | `GET /config`, `PUT /config` |
| Export | GET | `GET /capture/{id}/pcap`, `GET /scan/{id}/csv` |

---

## DB Schema (Core Tables)

- **captures** — id, name, interface, filter, started_at, stopped_at, pcap_path, packet_count, store_in_db (bool)
- **packets** — id, capture_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, payload_snippet
- **scans** — id, target, port_range, scan_type (tcp/udp/both), started_at, finished_at
- **scan_results** — scan_id, port, state (open/closed/filtered), service (optional)
- **security_findings** — id, scan_id, port, finding_type, severity, detail
- **alert_rules** — id, name, condition (e.g. threshold), params, enabled
- **alerts** — id, rule_id, triggered_at, message, metadata (json)
- **attack_sessions** — id, type, target, port, params (json), started_at, ended_at, operator
- **discovery_runs** — id, subnet, started_at
- **hosts** — id, discovery_run_id, ip, mac, hostname, last_seen
- **honeypot_events** — id, port, src_ip, timestamp, payload_snippet
- **rules** (IDS) — id, name, expression, tag, enabled
- **rule_matches** — id, rule_id, capture_id, packet_id_or_offset, matched_at

All controllable from **one web UI** and **one CLI**, with optional storage in this **small PostgreSQL** DB, **Dockerized** and **Poetry**-based as in the Plan and Architecture.
