"""Network discovery: ping sweep + port scan. Reuses logic from discover_network_devices."""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
from typing import Any

DEFAULT_PORTS = (
    80, 443, 81, 8080, 8443, 8000, 22, 23, 5900, 5353,
)
PING_TIMEOUT = 1.2
PORT_TIMEOUT = 0.8


def parse_target(target: str) -> list[str]:
    """Parse CIDR, single IP, or range (e.g. 192.168.1.1-50) into list of IPs."""
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


def get_default_subnet() -> str | None:
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


def _ping_host(ip: str) -> bool:
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip],
            capture_output=True,
            timeout=PING_TIMEOUT + 1,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        name, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        return name if name != ip else ""
    except (socket.gaierror, OSError):
        return ""


def run_discovery(
    targets: list[str],
    ports: tuple[int, ...] = DEFAULT_PORTS,
    no_ping: bool = False,
    max_workers_ping: int = 120,
    max_workers_port: int = 200,
) -> list[dict[str, Any]]:
    """
    Run discovery: resolve IPs from targets, ping (optional), port-scan, resolve hostnames.
    Returns list of {ip, hostname, open_ports, ...}.
    """
    all_ips: set[str] = set()
    for t in targets:
        all_ips.update(parse_target(t))
    hosts_sorted = sorted(all_ips, key=lambda x: ipaddress.ip_address(x))

    if no_ping:
        live_ips = hosts_sorted
    else:
        live_ips = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_ping) as ex:
            fut = {ex.submit(_ping_host, ip): ip for ip in hosts_sorted}
            for f in concurrent.futures.as_completed(fut):
                if f.result():
                    live_ips.append(fut[f])
        live_ips.sort(key=lambda x: ipaddress.ip_address(x))

    if not live_ips:
        return []

    open_by_ip: dict[str, list[int]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_port) as ex:
        fut = {
            ex.submit(lambda i, p: (i, p) if _port_open(i, p) else None, ip, port): (ip, port)
            for ip in live_ips
            for port in ports
        }
        for f in concurrent.futures.as_completed(fut):
            r = f.result()
            if r:
                ip, port = r
                open_by_ip.setdefault(ip, []).append(port)

    results = []
    for ip in live_ips:
        hostname = _resolve_hostname(ip)
        open_ports = sorted(open_by_ip.get(ip, []))
        results.append({"ip": ip, "hostname": hostname or None, "open_ports": open_ports})
    return results
