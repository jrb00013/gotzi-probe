"""Security-oriented scan: dangerous port checks, optional service/version (Tier 3)."""

import socket
from udp_probe.core.database import get_session
from udp_probe.models.security_finding import SecurityFinding

# Ports often considered high-risk if open without hardening
DANGEROUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}


def run_security_scan(target: str, port_range: range | None = None, scan_id: int | None = None) -> list[dict]:
    """
    TCP connect scan; for any open port in DANGEROUS_PORTS (or all if port_range given), create a SecurityFinding.
    Returns list of findings (as dicts).
    """
    if port_range is None:
        ports_to_check = list(DANGEROUS_PORTS.keys())
    else:
        ports_to_check = list(port_range)
    findings = []
    session = get_session()
    try:
        for port in ports_to_check:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((target, port))
                s.close()
                # Open
                service = DANGEROUS_PORTS.get(port, "unknown")
                severity = "high" if port in (22, 23, 3389, 445) else "medium"
                msg = f"Open port {port} ({service}) — ensure service is hardened and access restricted."
                rec = SecurityFinding(
                    scan_id=scan_id,
                    target=target,
                    port=port,
                    finding_type="open_dangerous_port",
                    severity=severity,
                    message=msg,
                    raw_detail=service,
                )
                session.add(rec)
                session.commit()
                session.refresh(rec)
                findings.append({
                    "id": rec.id,
                    "target": target,
                    "port": port,
                    "finding_type": rec.finding_type,
                    "severity": rec.severity,
                    "message": rec.message,
                })
            except (socket.error, OSError):
                pass
        return findings
    finally:
        session.close()
