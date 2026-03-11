"""CLI entrypoint: probe <command> — scan, discover, digest, serve, attack, rules, honeypot."""

from __future__ import annotations

import json
from typing import Optional

import typer
import httpx

from udp_probe import __version__
from udp_probe.core.config import get_config
from udp_probe.core.database import init_db, get_session
from udp_probe.models.scan import Scan, ScanResult
from udp_probe.models.discovery import DiscoveryRun, Host

app = typer.Typer(name="gotzi", help="Gotzi — scan, discover, digest, serve, attack, rules, honeypot")
attack_app = typer.Typer(help="Attack simulation. Authorized targets only. Audit-logged.")
rules_app = typer.Typer(help="IDS-style rules.")
honeypot_app = typer.Typer(help="Honeypot: fake ports, log connections.")

app.add_typer(attack_app, name="attack")
app.add_typer(rules_app, name="rules")
app.add_typer(honeypot_app, name="honeypot")
alerts_app = typer.Typer(help="Threshold alerts: list alerts, manage rules.")
app.add_typer(alerts_app, name="alerts")

ATTACK_WARNING = "Use only on targets you are authorized to test. All sessions are audit-logged."


# ---------- Tier 1: scan, discover, digest, config, init, serve ----------

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    ports: str = typer.Option("1-1024", "--ports", "-p"),
    tcp: bool = typer.Option(True, "--tcp", help="Scan TCP"),
    udp: bool = typer.Option(False, "--udp", help="Scan UDP"),
    save: bool = typer.Option(True, "--save", help="Save to DB"),
    security: bool = typer.Option(False, "--security", "-s", help="Run security-oriented scan (dangerous ports, etc.)"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Run port scan or security scan."""
    if security:
        if api_url:
            with httpx.Client() as client:
                r = client.get(f"{api_url.rstrip('/')}/api/security-scan", params=dict(target=target))
                r.raise_for_status()
                j = r.json()
                typer.echo(f"Findings: {j.get('count', 0)}")
                for f in j.get("findings") or []:
                    typer.echo(f"  {f}")
        else:
            from udp_probe.scan import run_security_scan
            findings = run_security_scan(target)
            typer.echo(f"Findings: {len(findings)}")
            for f in findings:
                typer.echo(f"  {f}")
        return
    if api_url:
        with httpx.Client() as client:
            r = client.post(
                f"{api_url.rstrip('/')}/api/scan/run",
                params=dict(target=target, port_spec=ports, scan_tcp=tcp, scan_udp=udp, save=save),
            )
            r.raise_for_status()
            j = r.json()
            typer.echo(f"Scan ID: {j.get('scan_id')}, open: {j.get('open_count')}/{j.get('total_ports')}")
            for x in (j.get("results") or []):
                if x.get("state") in ("open", "open|filtered"):
                    typer.echo(f"  {x['port']} {x['state']} {x.get('service') or ''}")
        return
    from datetime import datetime
    from udp_probe.scan.scanner import run_port_scan
    results = run_port_scan(target, ports, scan_tcp=tcp, scan_udp=udp)
    open_list = [r for r in results if r["state"] in ("open", "open|filtered")]
    if save:
        session = get_session()
        try:
            rec = Scan(target=target, port_range=ports, scan_type="tcp" if tcp and not udp else "udp" if udp else "both")
            session.add(rec)
            session.commit()
            session.refresh(rec)
            for r in results:
                session.add(ScanResult(scan_id=rec.id, port=r["port"], state=r["state"], service=r.get("service")))
            rec.finished_at = datetime.utcnow()
            session.commit()
            typer.echo(f"Saved as scan ID {rec.id}")
        finally:
            session.close()
    typer.echo(f"Open: {len(open_list)}/{len(results)}")
    for r in open_list:
        typer.echo(f"  {r['port']} {r['state']} {r.get('service') or ''}")


@app.command("scan-history")
def scan_history(
    limit: int = typer.Option(20, "--limit", "-n"),
    target: Optional[str] = typer.Option(None, "--target"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """List scan history."""
    if api_url:
        with httpx.Client() as client:
            r = client.get(f"{api_url.rstrip('/')}/api/scan/history", params=dict(limit=limit, target=target or ""))
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    session = get_session()
    try:
        q = session.query(Scan).order_by(Scan.started_at.desc()).limit(limit)
        if target:
            q = q.filter(Scan.target == target)
        for rec in q:
            typer.echo(f"{rec.id}  {rec.target}  {rec.port_range}  {rec.started_at}")
    finally:
        session.close()


@app.command("scan-diff")
def scan_diff(
    id1: int = typer.Argument(...),
    id2: int = typer.Argument(...),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Compare two scans."""
    if api_url:
        with httpx.Client() as client:
            r = client.get(f"{api_url.rstrip('/')}/api/scan/diff/{id1}/{id2}")
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    session = get_session()
    try:
        s1, s2 = session.get(Scan, id1), session.get(Scan, id2)
        if not s1 or not s2:
            typer.echo("Scan not found.", err=True)
            raise typer.Exit(1)
        open1 = {r.port for r in s1.results if r.state in ("open", "open|filtered")}
        open2 = {r.port for r in s2.results if r.state in ("open", "open|filtered")}
        typer.echo("New open:", sorted(open2 - open1))
        typer.echo("Newly closed:", sorted(open1 - open2))
    finally:
        session.close()


@app.command()
def discover(
    targets: str = typer.Argument("", help="CIDR or IP(s); default = auto-detect subnet"),
    ports: str = typer.Option("80,443,22,8080", "--ports"),
    no_ping: bool = typer.Option(False, "--no-ping"),
    save: bool = typer.Option(True, "--save", help="Save to DB"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Discover hosts (ping + port scan)."""
    if api_url:
        with httpx.Client(timeout=60.0) as client:
            r = client.post(
                f"{api_url.rstrip('/')}/api/discovery/run",
                params=dict(targets=targets, ports=ports, no_ping=no_ping, save=save),
            )
            r.raise_for_status()
            j = r.json()
            typer.echo(f"Hosts: {j.get('host_count')}")
            for h in j.get("hosts") or []:
                typer.echo(f"  {h.get('ip')}  {h.get('hostname') or '-'}  {h.get('open_ports')}")
        return
    from udp_probe.discovery.runner import run_discovery, get_default_subnet
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    if not target_list:
        default = get_default_subnet()
        if not default:
            typer.echo("No targets and could not auto-detect subnet.", err=True)
            raise typer.Exit(1)
        target_list = [default]
    port_list = tuple(int(p.strip()) for p in ports.split(",") if p.strip())
    results = run_discovery(target_list, ports=port_list, no_ping=no_ping)
    if save and results:
        session = get_session()
        try:
            run_rec = DiscoveryRun(subnet=",".join(target_list))
            session.add(run_rec)
            session.commit()
            session.refresh(run_rec)
            for r in results:
                session.add(Host(discovery_run_id=run_rec.id, ip=r["ip"], hostname=r.get("hostname"), open_ports=",".join(map(str, r.get("open_ports", []))) if r.get("open_ports") else None))
            session.commit()
            typer.echo(f"Saved as discovery run ID {run_rec.id}")
        finally:
            session.close()
    for r in results:
        typer.echo(f"  {r['ip']}  {r.get('hostname') or '-'}  {r.get('open_ports')}")


@app.command()
def digest(
    file_path: str = typer.Argument("udp_session.csv", help="Probe session CSV or use --live"),
    live: Optional[int] = typer.Option(None, "--live", "-l", help="Capture ID to digest from DB"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Digest probe session CSV or capture by ID."""
    if live is not None:
        if api_url:
            with httpx.Client() as client:
                r = client.get(f"{api_url.rstrip('/')}/api/digest/capture/{live}")
                r.raise_for_status()
                typer.echo(json.dumps(r.json(), indent=2))
        else:
            from udp_probe.digest.analyzer import digest_packets
            from udp_probe.core.database import get_session
            from udp_probe.models.capture import Packet
            session = get_session()
            try:
                packets = session.query(Packet).filter(Packet.capture_id == live).all()
                packet_dicts = [{"src_ip": p.src_ip, "dst_ip": p.dst_ip, "src_port": p.src_port, "dst_port": p.dst_port, "length": p.length} for p in packets]
                typer.echo(json.dumps(digest_packets(packet_dicts), indent=2))
            finally:
                session.close()
        return
    if api_url:
        with httpx.Client() as client:
            r = client.post(f"{api_url.rstrip('/')}/api/digest/csv", params=dict(file_path=file_path))
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    from udp_probe.digest.analyzer import digest_csv
    out = digest_csv(file_path)
    if "error" in out:
        typer.echo(out["error"], err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(out, indent=2))


@app.command("config")
def config_get(
    key: Optional[str] = typer.Argument(None, help="Key to get (omit to list all)"),
    set_value: Optional[str] = typer.Option(None, "--set", "-s", help="Value to set (with key)"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Show config, or config set KEY VALUE."""
    if api_url and not set_value:
        with httpx.Client() as client:
            r = client.get(f"{api_url.rstrip('/')}/api/config")
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    cfg = get_config()
    if set_value is not None and key:
        import os
        env_key = "PROBE_" + key.upper()
        typer.echo(f"Set {env_key}={set_value} in environment or .env to persist.")
        return
    if key:
        val = getattr(cfg, key, None)
        typer.echo(f"{key}={val}")
    else:
        typer.echo(f"host={cfg.host} port={cfg.port} probe_host={cfg.probe_host} probe_port={cfg.probe_port} database_url=...")


@app.command()
def capture(
    name: str = typer.Option("session", "--output", "-o", help="Session name"),
    interface: str = typer.Option("", "--interface", "-i"),
    filter_expr: str = typer.Option("", "--filter", "-f"),
    store_in_db: bool = typer.Option(False, "--db"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Start packet capture (stop with Ctrl+C or via API/UI)."""
    if api_url:
        with httpx.Client() as client:
            r = client.post(
                f"{api_url.rstrip('/')}/api/capture/start",
                params=dict(name=name, filter_expr=filter_expr, store_in_db=store_in_db),
            )
            r.raise_for_status()
            j = r.json()
            typer.echo(f"Capture started. ID: {j.get('capture_id')}. Stop via API POST /api/capture/stop or Web UI.")
        return
    typer.echo("Run with --api-url or start server (gotzi serve) and use Web UI to start/stop capture.")

@app.command()
def stats(
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """Show live and recent traffic stats (dashboard)."""
    if api_url:
        with httpx.Client() as client:
            r = client.get(f"{api_url.rstrip('/')}/api/dashboard/stats")
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    from udp_probe.core.database import get_session
    from udp_probe.models.capture import Packet
    from collections import Counter
    session = get_session()
    try:
        packets = session.query(Packet).order_by(Packet.timestamp.desc()).limit(1000).all()
        total_bytes = sum(p.length for p in packets)
        src_ips = Counter(p.src_ip for p in packets)
        typer.echo(f"Recent packets: {len(packets)}, bytes: {total_bytes}")
        typer.echo("Top source IPs: " + str(src_ips.most_common(5)))
    finally:
        session.close()


@app.command("init")
def init_cmd() -> None:
    """Create DB tables."""
    init_db()
    typer.echo("DB tables created.")


@app.command()
def serve(
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
) -> None:
    """Run the web API server."""
    cfg = get_config()
    h = host or cfg.host
    p = port or cfg.port
    typer.echo(f"Serving on http://{h}:{p}")
    import uvicorn
    from udp_probe.api.app import create_app
    uvicorn.run(create_app(), host=h, port=p)


# ---------- Attack, rules, honeypot ----------

@attack_app.command("flood")
def attack_flood(
    target: str = typer.Argument(..., help="Target IP"),
    port: int = typer.Option(..., "--port", "-p"),
    duration: float = typer.Option(10.0, "--duration", "-d"),
    protocol: str = typer.Option("udp", "--protocol"),
) -> None:
    typer.echo(typer.style(ATTACK_WARNING, fg=typer.colors.YELLOW))
    from udp_probe.attack import run_udp_flood, run_tcp_flood
    sid = run_tcp_flood(target, port, duration) if protocol.lower() == "tcp" else run_udp_flood(target, port, duration)
    typer.echo(f"Attack session id: {sid}")


@attack_app.command("port-knock")
def attack_port_knock(
    target: str = typer.Argument(...),
    ports: str = typer.Option(..., "--ports", "-p"),
    protocol: str = typer.Option("udp", "--protocol"),
    delay: float = typer.Option(0.2, "--delay"),
) -> None:
    typer.echo(typer.style(ATTACK_WARNING, fg=typer.colors.YELLOW))
    from udp_probe.attack import run_port_knock
    port_list = [int(p.strip()) for p in ports.split(",")]
    sid = run_port_knock(target, port_list, protocol, delay)
    typer.echo(f"Attack session id: {sid}")


@attack_app.command("slowloris")
def attack_slowloris(
    target: str = typer.Argument(...),
    port: int = typer.Option(80, "--port", "-p"),
    duration: float = typer.Option(60.0, "--duration", "-d"),
    num_sockets: int = typer.Option(200, "--sockets"),
) -> None:
    typer.echo(typer.style(ATTACK_WARNING, fg=typer.colors.YELLOW))
    from udp_probe.attack import run_slowloris
    sid = run_slowloris(target, port, duration, num_sockets)
    typer.echo(f"Attack session id: {sid}")


@attack_app.command("replay")
def attack_replay(
    target: str = typer.Argument(...),
    replay_path: str = typer.Argument(...),
    delay: float = typer.Option(0.0, "--delay"),
) -> None:
    typer.echo(typer.style(ATTACK_WARNING, fg=typer.colors.YELLOW))
    from udp_probe.attack import run_replay_file
    sid = run_replay_file(target, replay_path, delay)
    typer.echo(f"Attack session id: {sid}")


@rules_app.command("list")
def rules_list(enabled_only: bool = typer.Option(False, "--enabled", "-e")) -> None:
    from udp_probe.rules import list_rules
    from rich.console import Console
    from rich.table import Table
    console = Console()
    rows = list_rules(enabled_only=enabled_only)
    table = Table(title="Rules")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Port")
    table.add_column("Protocol")
    table.add_column("Payload regex")
    table.add_column("Enabled")
    for r in rows:
        table.add_row(str(r["id"]), r["name"], str(r["port"]) if r.get("port") else "any", r.get("protocol") or "any", (r.get("payload_regex") or "")[:40], "yes" if r.get("enabled") else "no")
    console.print(table)


@rules_app.command("add")
def rules_add(
    name: str = typer.Argument(...),
    payload_regex: Optional[str] = typer.Option(None, "--payload", "-p"),
    port: Optional[int] = typer.Option(None, "--port"),
    protocol: Optional[str] = typer.Option(None, "--protocol"),
) -> None:
    from udp_probe.rules import add_rule
    rid = add_rule(name, payload_regex=payload_regex, port=port, protocol=protocol)
    typer.echo(f"Rule created with id: {rid}")


@rules_app.command("delete")
def rules_delete(rule_id: int = typer.Argument(...)) -> None:
    from udp_probe.rules import delete_rule
    if not delete_rule(rule_id):
        typer.echo("Rule not found", err=True)
        raise typer.Exit(1)
    typer.echo("Deleted.")


@rules_app.command("enable")
def rules_enable(rule_id: int = typer.Argument(...), disable: bool = typer.Option(False, "--disable", help="Disable instead of enable")) -> None:
    from udp_probe.rules import enable_rule
    if not enable_rule(rule_id, enabled=not disable):
        typer.echo("Rule not found", err=True)
        raise typer.Exit(1)
    typer.echo("Disabled." if disable else "Enabled.")


@rules_app.command("matches")
def rules_matches(rule_id: Optional[int] = typer.Option(None, "--rule", "-r"), limit: int = typer.Option(100, "--limit", "-n")) -> None:
    from udp_probe.rules import list_rule_matches
    from rich.console import Console
    from rich.table import Table
    console = Console()
    rows = list_rule_matches(rule_id=rule_id, limit=limit)
    table = Table(title="Rule matches")
    table.add_column("ID")
    table.add_column("Rule ID")
    table.add_column("Time")
    table.add_column("Source")
    table.add_column("Dest")
    table.add_column("Snippet")
    for r in rows:
        table.add_row(str(r["id"]), str(r["rule_id"]), str(r.get("matched_at", "")), f"{r.get('src_ip', '')}:{r.get('src_port', '')}", f"{r.get('dst_ip', '')}:{r.get('dst_port', '')}", (r.get("payload_snippet") or "")[:30])
    console.print(table)


@honeypot_app.command("start")
def honeypot_start(ports: str = typer.Argument(..., help="e.g. 22,80,443")) -> None:
    from udp_probe.honeypot import run_honeypot
    port_list = [int(p.strip()) for p in ports.split(",")]
    run_honeypot(port_list)
    typer.echo(f"Honeypot started on ports: {port_list}")


@honeypot_app.command("stop")
def honeypot_stop() -> None:
    from udp_probe.honeypot import stop_honeypot
    stop_honeypot()
    typer.echo("Honeypot stopped.")


@honeypot_app.command("events")
def honeypot_events(limit: int = typer.Option(100, "--limit", "-n"), port: Optional[int] = typer.Option(None, "--port", "-p")) -> None:
    from udp_probe.core.database import get_session
    from udp_probe.models.honeypot import HoneypotEvent
    from rich.console import Console
    from rich.table import Table
    session = get_session()
    try:
        q = session.query(HoneypotEvent).order_by(HoneypotEvent.received_at.desc()).limit(limit)
        if port is not None:
            q = q.filter(HoneypotEvent.port == port)
        rows = q.all()
    finally:
        session.close()
    console = Console()
    table = Table(title="Honeypot events")
    table.add_column("ID")
    table.add_column("Port")
    table.add_column("Protocol")
    table.add_column("Source")
    table.add_column("Time")
    table.add_column("Snippet")
    for e in rows:
        table.add_row(str(e.id), str(e.port), e.protocol or "", f"{e.src_ip}:{e.src_port}", e.received_at.isoformat() if e.received_at else "", (e.payload_snippet or "")[:40])
    console.print(table)


@alerts_app.command("list")
def alerts_list_cmd(
    limit: int = typer.Option(50, "--limit", "-n"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """List recent alerts."""
    if api_url:
        with httpx.Client() as client:
            r = client.get(f"{api_url.rstrip('/')}/api/alerts", params=dict(limit=limit))
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    from udp_probe.core.database import get_session
    from udp_probe.models.alert import Alert
    session = get_session()
    try:
        rows = session.query(Alert).order_by(Alert.triggered_at.desc()).limit(limit).all()
        for r in rows:
            typer.echo(f"{r.triggered_at} [{r.rule_id}] {r.message}")
    finally:
        session.close()


@alerts_app.command("rules")
def alerts_rules_cmd(
    add: bool = typer.Option(False, "--add", "-a"),
    name: Optional[str] = typer.Option(None, "--name", "-n"),
    condition: str = typer.Option("threshold", "--condition", "-c"),
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="PROBE_API_URL"),
) -> None:
    """List alert rules, or add one with --add --name NAME."""
    if add and name:
        if api_url:
            with httpx.Client() as client:
                r = client.post(f"{api_url.rstrip('/')}/api/alerts/rules", params=dict(name=name, condition=condition))
                r.raise_for_status()
                typer.echo(json.dumps(r.json(), indent=2))
        else:
            from udp_probe.core.database import get_session
            from udp_probe.models.alert import AlertRule
            session = get_session()
            try:
                rec = AlertRule(name=name, condition=condition)
                session.add(rec)
                session.commit()
                session.refresh(rec)
                typer.echo(f"Rule created: id={rec.id}")
            finally:
                session.close()
        return
    if api_url:
        with httpx.Client() as client:
            r = client.get(f"{api_url.rstrip('/')}/api/alerts/rules")
            r.raise_for_status()
            typer.echo(json.dumps(r.json(), indent=2))
        return
    from udp_probe.core.database import get_session
    from udp_probe.models.alert import AlertRule
    session = get_session()
    try:
        for r in session.query(AlertRule).all():
            typer.echo(f"{r.id}  {r.name}  {r.condition}  enabled={r.enabled}")
    finally:
        session.close()


@app.callback()
def main_callback() -> None:
    pass


@app.command("version")
def version_cmd() -> None:
    """Show version."""
    typer.echo(__version__)


