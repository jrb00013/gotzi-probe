#!/usr/bin/env python3
"""
Discover devices on any network — no hardcoded IPs or subnets.

Accepts any target(s): CIDR (e.g. 10.0.0.0/8), single IP, or range (e.g. 192.168.1.1-50).
If no target is given, uses your default route subnet (Linux).
Pings hosts in parallel, port-scans live hosts, optionally fetches HTTP titles.

Usage:
  gotzi discover   (or python -m udp_probe discover)
  gotzi discover 192.168.1.0/24
  gotzi discover 10.0.0.1 10.0.0.0/24
  gotzi discover 192.168.1.1-192.168.1.50
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import sys
from typing import List, Optional, Tuple

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

DEFAULT_PORTS = (
    80, 443, 81, 8080, 8443, 8000, 8008, 8081, 8888, 9080, 9443, 9081,
    3000, 4000, 5000, 5001, 7080, 8880, 9000, 9090, 10000, 10443,
    22, 23, 2368, 3456, 5900, 8082, 8083, 8084, 8085, 8444,
    6080, 8001, 8002, 9001, 9002, 34567, 5353,
)

PING_TIMEOUT = 1.2
PORT_TIMEOUT = 0.8
HTTP_TIMEOUT = 2.0


def parse_target(target: str) -> List[str]:
    """Parse a target into a list of IP strings (CIDR, single IP, or range)."""
    target = target.strip()
    if "-" in target and "/" not in target:
        low, high = target.split("-", 1)
        low, high = low.strip(), high.strip()
        try:
            start = ipaddress.ip_address(low)
            if "." in high:
                end = ipaddress.ip_address(high)
            else:
                last = int(high)
                if not (0 <= last <= 255):
                    raise ValueError("Last octet must be 0-255")
                parts = start.exploded.rsplit(".", 1)
                end = ipaddress.ip_address(f"{parts[0]}.{last}")
            if end < start:
                start, end = end, start
            return [str(ipaddress.ip_address(a)) for a in range(int(start), int(end) + 1)]
        except (ValueError, ipaddress.AddressValueError):
            pass
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(h) for h in net.hosts()]
        addr = ipaddress.ip_address(target)
        return [str(addr)]
    except (ValueError, ipaddress.AddressValueError):
        return []


def get_default_subnet() -> Optional[str]:
    """Get primary IPv4 subnet (CIDR) from default route on Linux."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        match = re.search(r"\bsrc\s+(\S+)", out.stdout)
        if not match:
            return None
        src = match.group(1)
        out2 = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out2.returncode != 0:
            return None
        for line in out2.stdout.splitlines():
            if "inet " in line and src in line:
                m = re.search(r"inet\s+(\S+)", line)
                if m:
                    return m.group(1)
        return f"{src.rsplit('.', 1)[0]}.0/24"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def ping_host(ip: str) -> bool:
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip],
            capture_output=True,
            timeout=PING_TIMEOUT + 1,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def fetch_http_title(ip: str, port: int, use_ssl: bool) -> Optional[str]:
    try:
        import urllib.request
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "UDPProbe/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = resp.read(4096).decode("utf-8", errors="ignore")
        m = re.search(r"<title[^>]*>([^<]+)</title>", data, re.I)
        if m:
            return m.group(1).strip()[:80]
        return data[:120].strip() or None
    except Exception:
        return None


def resolve_hostname(ip: str) -> str:
    try:
        name, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        return name if name != ip else ""
    except (socket.gaierror, OSError):
        return ""


def run_with_tui(
    hosts_sorted: List[str],
    ports_tuple: tuple,
    no_ping: bool,
    no_http: bool,
    console: "Console",
) -> List[Tuple[str, str, list, Optional[str]]]:
    """Run discovery with rich Live TUI."""
    live_ips: List[str]
    total = len(hosts_sorted)
    n_hosts = len(hosts_sorted)
    n_ports = len(ports_tuple)
    header = Panel(
        f"[bold cyan]Discovering devices[/]\n[dim]{n_hosts} IPs × {n_ports} ports[/]",
        border_style="cyan",
        box=box.ROUNDED,
    )

    with Live(console=console, refresh_per_second=10, screen=False) as live:
        if no_ping:
            live_ips = hosts_sorted
            live.update(Group(header, Panel("[bold green]Port-scanning[/] (no ping) — all IPs", border_style="green")))
        else:
            live_ips = []
            ping_progress = Progress(
                SpinnerColumn(style="bold cyan"),
                TextColumn("[bold blue]Ping sweep[/]"),
                BarColumn(bar_width=40, style="cyan", complete_style="green"),
                TaskProgressColumn(),
                console=console,
            )
            ping_task = ping_progress.add_task("hosts", total=total)
            live.update(Group(header, ping_progress))
            with concurrent.futures.ThreadPoolExecutor(max_workers=120) as ex:
                fut = {ex.submit(ping_host, ip): ip for ip in hosts_sorted}
                for f in concurrent.futures.as_completed(fut):
                    ping_progress.update(ping_task, advance=1)
                    if f.result():
                        live_ips.append(fut[f])
            live_ips.sort(key=lambda x: ipaddress.ip_address(x))

        if not live_ips:
            live.update(Group(header, Panel("[yellow]No hosts responded to ping.[/] Try [bold]--no-ping[/] to port-scan every IP.", border_style="yellow")))
            return []

        total_checks = len(live_ips) * len(ports_tuple)
        open_by_ip: dict = {}
        port_progress = Progress(
            SpinnerColumn(style="bold magenta"),
            TextColumn("[bold magenta]Port scan[/]"),
            BarColumn(bar_width=40, style="magenta", complete_style="green"),
            TaskProgressColumn(),
            console=console,
        )
        port_task = port_progress.add_task("ports", total=total_checks)
        live.update(Group(header, port_progress))
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
            fut = {ex.submit(lambda i, p: (i, p) if port_open(i, p) else None, ip, port): (ip, port)
                   for ip in live_ips for port in ports_tuple}
            for f in concurrent.futures.as_completed(fut):
                port_progress.update(port_task, advance=1)
                r = f.result()
                if r:
                    ip, port = r
                    open_by_ip.setdefault(ip, []).append(port)

        live.update(Group(header, Panel("[bold green]Resolving hostnames & fetching HTTP…[/]", border_style="green")))
        results: List[Tuple[str, str, list, Optional[str]]] = []
        for ip in live_ips:
            hostname = resolve_hostname(ip)
            open_ports = sorted(open_by_ip.get(ip, []))
            http_port = None
            for p, ssl in [(80, False), (8080, False), (8000, False), (443, True), (8443, True)]:
                if p in open_ports:
                    http_port = (p, ssl)
                    break
            snippet = None
            if not no_http and http_port:
                port_num, ssl = http_port
                snippet = fetch_http_title(ip, port_num, ssl)
            results.append((ip, hostname, open_ports, snippet))

    return results


def run_plain(
    hosts_sorted: List[str],
    ports_tuple: tuple,
    no_ping: bool,
    no_http: bool,
) -> List[Tuple[str, str, list, Optional[str]]]:
    """Run without rich (fallback)."""
    if no_ping:
        live_ips = hosts_sorted
    else:
        live_ips = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=120) as ex:
            fut = {ex.submit(ping_host, ip): ip for ip in hosts_sorted}
            for f in concurrent.futures.as_completed(fut):
                if f.result():
                    live_ips.append(fut[f])
        live_ips.sort(key=lambda x: ipaddress.ip_address(x))

    if not live_ips:
        return []

    open_by_ip: dict = {}
    total_checks = len(live_ips) * len(ports_tuple)
    if total_checks > 500:
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
            fut = {ex.submit(lambda i, p: (i, p) if port_open(i, p) else None, ip, port): (ip, port)
                   for ip in live_ips for port in ports_tuple}
            for f in concurrent.futures.as_completed(fut):
                r = f.result()
                if r:
                    ip, port = r
                    open_by_ip.setdefault(ip, []).append(port)
    else:
        for ip in live_ips:
            for port in ports_tuple:
                if port_open(ip, port):
                    open_by_ip.setdefault(ip, []).append(port)

    results = []
    for ip in live_ips:
        hostname = resolve_hostname(ip)
        open_ports = sorted(open_by_ip.get(ip, []))
        http_port = None
        for p, ssl in [(80, False), (8080, False), (8000, False), (443, True), (8443, True)]:
            if p in open_ports:
                http_port = (p, ssl)
                break
        snippet = None
        if not no_http and http_port:
            port_num, ssl = http_port
            snippet = fetch_http_title(ip, port_num, ssl)
        results.append((ip, hostname, open_ports, snippet))
    return results


def pick_http_port(ports: list) -> Optional[Tuple[int, bool]]:
    for p in (80, 8080, 8000, 8008, 9080, 8888, 3000, 5000):
        if p in ports:
            return (p, False)
    for p in (443, 8443, 9443):
        if p in ports:
            return (p, True)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover devices on any network. Pass CIDR, IP(s), or range. No hardcoded subnets."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target(s): CIDR (e.g. 10.0.0.0/24), single IP, or range (e.g. 192.168.1.1-50). Default: auto-detect subnet.",
    )
    parser.add_argument("--no-ping", action="store_true", help="Port-scan every IP (finds hosts that block ping).")
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP fetch (faster).")
    parser.add_argument("--ports", type=str, default=None, help="Ports to scan, e.g. 80,443,8080.")
    parser.add_argument("--no-tui", action="store_true", help="Plain output (no rich TUI).")
    args = parser.parse_args()

    all_ips: set = set()
    if args.targets:
        for t in args.targets:
            ips = parse_target(t)
            if not ips:
                print(f"Invalid target: {t}", file=sys.stderr)
                return 1
            all_ips.update(ips)
    else:
        default = get_default_subnet()
        if not default:
            print("Could not auto-detect subnet. Pass a target: CIDR, IP, or range (e.g. 192.168.1.0/24).", file=sys.stderr)
            return 1
        for ip in parse_target(default):
            all_ips.add(ip)

    hosts_sorted = sorted(all_ips, key=lambda x: ipaddress.ip_address(x))

    if args.ports:
        try:
            ports_tuple = tuple(int(p.strip()) for p in args.ports.split(",") if p.strip())
        except ValueError:
            print("Invalid --ports; use e.g. 80,443,8080", file=sys.stderr)
            return 1
    else:
        ports_tuple = DEFAULT_PORTS

    console = Console() if RICH else None
    if RICH and not args.no_tui:
        results = run_with_tui(hosts_sorted, ports_tuple, args.no_ping, args.no_http, console)
    else:
        if not args.no_tui and not RICH:
            print("Install 'rich' for TUI: pip install rich", file=sys.stderr)
        results = run_plain(hosts_sorted, ports_tuple, args.no_ping, args.no_http)

    if not results:
        if RICH and console and not args.no_tui:
            console.print(Panel("[yellow]No hosts to show.[/]", border_style="yellow"))
        return 0

    HTTP_PORTS = (80, 443, 8080, 8443, 8000, 8008, 9080, 8888, 9443, 3000, 5000, 9000)

    if RICH and console and not args.no_tui:
        table = Table(title="Discovered hosts", box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("IP", style="green", no_wrap=True)
        table.add_column("Hostname", style="dim")
        table.add_column("Open ports")
        table.add_column("Web / title")
        for ip, hostname, ports, snippet in results:
            port_str = ",".join(str(p) for p in ports) if ports else "-"
            if len(port_str) > 32:
                port_str = port_str[:29] + "..."
            snip = (snippet or "")[:44].replace("\n", " ")
            if snippet and "dronespotter" in snippet.lower():
                snip = Text(snip, style="bold yellow") + Text("  ← DroneSpotter?", style="bold yellow")
            table.add_row(ip, (hostname or "-")[:20], port_str, snip)
        console.print()
        console.print(table)
        candidates = [r for r in results if r[3] and "dronespotter" in (r[3] or "").lower()]
        if candidates:
            console.print()
            console.print(Panel("[bold]Possible DroneSpotter / config UIs[/]", border_style="yellow"))
            for ip, _, ports, _ in candidates:
                pp = pick_http_port(ports)
                if pp:
                    p, ssl = pp
                    console.print(f"  [link https://{ip}:{p}/]{'https' if ssl else 'http'}://{ip}:{p}/[/]")
        else:
            web_hosts = [r for r in results if r[2] and any(port in r[2] for port in HTTP_PORTS)]
            if web_hosts:
                console.print()
                console.print(Panel("[bold]Hosts with HTTP(S)[/]", border_style="blue"))
                for ip, _, ports, _ in web_hosts:
                    pp = pick_http_port(ports)
                    if pp:
                        p, ssl = pp
                        console.print(f"  {'https' if ssl else 'http'}://{ip}:{p}/")
    else:
        print(f"\n{'IP':<16} {'Hostname':<22} {'Open ports':<36} Web / title")
        print("-" * 95)
        for ip, hostname, ports, snippet in results:
            port_str = ",".join(str(p) for p in ports) if ports else "-"
            if len(port_str) > 34:
                port_str = port_str[:31] + "..."
            snip_str = (snippet or "")[:48].replace("\n", " ")
            maybe = " *** DroneSpotter? ***" if snippet and "dronespotter" in (snippet or "").lower() else ""
            print(f"{ip:<16} {(hostname or '-')[:22]:<22} {port_str:<36} {snip_str}{maybe}")
        candidates = [r for r in results if r[3] and "dronespotter" in (r[3] or "").lower()]
        if candidates:
            print("\nPossible DroneSpotter / config UIs:")
            for ip, _, ports, _ in candidates:
                pp = pick_http_port(ports)
                if pp:
                    p, ssl = pp
                    print(f"  {'https' if ssl else 'http'}://{ip}:{p}/")
        else:
            web_hosts = [r for r in results if r[2] and any(port in r[2] for port in HTTP_PORTS)]
            if web_hosts:
                print("\nHosts with HTTP(S):")
                for ip, _, ports, _ in web_hosts:
                    pp = pick_http_port(ports)
                    if pp:
                        p, ssl = pp
                        print(f"  {'https' if ssl else 'http'}://{ip}:{p}/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
