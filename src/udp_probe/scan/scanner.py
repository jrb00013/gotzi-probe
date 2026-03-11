"""Port scanner: TCP connect and optional UDP probe."""

import socket
from typing import Iterator

# Common service names for display
SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
}


def parse_port_range(spec: str) -> list[int]:
    """Parse '1-1024' or '80,443,8080' or '1-100,443,8080' into list of ports."""
    out: list[int] = []
    for part in spec.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                lo, hi = int(a), int(b)
                if lo > hi:
                    lo, hi = hi, lo
                for p in range(lo, hi + 1):
                    if 0 <= p <= 65535:
                        out.append(p)
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 0 <= p <= 65535:
                    out.append(p)
            except ValueError:
                pass
    return sorted(set(out))


def _tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def _udp_probe(host: str, port: int, timeout: float = 0.5) -> str:
    """UDP probe: send empty packet; 'open' if we get a reply, 'open|filtered' else."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (host, port))
        sock.recvfrom(1024)
        sock.close()
        return "open"
    except socket.timeout:
        return "open|filtered"
    except (socket.error, OSError):
        return "closed"


def run_port_scan(
    target: str,
    port_spec: str = "1-1024",
    scan_tcp: bool = True,
    scan_udp: bool = False,
    timeout: float = 1.0,
) -> list[dict]:
    """Run port scan. Returns list of {port, state, service}."""
    ports = parse_port_range(port_spec)
    if not ports:
        return []
    results: list[dict] = []
    for port in ports:
        state = "closed"
        if scan_tcp:
            if _tcp_connect(target, port, timeout):
                state = "open"
        if scan_udp and state == "closed":
            state = _udp_probe(target, port, timeout)
        service = SERVICE_NAMES.get(port)
        results.append({"port": port, "state": state, "service": service})
    return results


def run_port_scan_open_only(
    target: str,
    port_spec: str = "1-1024",
    scan_tcp: bool = True,
    scan_udp: bool = False,
    timeout: float = 1.0,
) -> list[dict]:
    """Same as run_port_scan but only return open/open|filtered."""
    all_results = run_port_scan(target, port_spec, scan_tcp, scan_udp, timeout)
    return [r for r in all_results if r["state"] in ("open", "open|filtered")]
