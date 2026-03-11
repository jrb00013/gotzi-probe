"""Port knocking sequence — send packets to a sequence of ports. Authorized targets only."""

import socket
import time

from udp_probe.attack.audit import log_attack_session, end_attack_session


def run_port_knock(
    target: str,
    ports: list[int],
    protocol: str = "udp",
    delay_sec: float = 0.2,
    operator: str | None = None,
) -> int:
    """Send a port-knock sequence to target. Returns attack_session id."""
    session_id = log_attack_session(
        "port_knock", target, port=None,
        params={"ports": ports, "protocol": protocol, "delay_sec": delay_sec},
        operator=operator,
    )
    kind = socket.SOCK_DGRAM if protocol.lower() == "udp" else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, kind)
    try:
        for p in ports:
            if kind == socket.SOCK_DGRAM:
                sock.sendto(b"\x00", (target, p))
            else:
                try:
                    sock.connect((target, p))
                    sock.close()
                    sock = socket.socket(socket.AF_INET, kind)
                except (socket.error, OSError):
                    pass
            time.sleep(delay_sec)
    finally:
        sock.close()
        end_attack_session(session_id)
    return session_id
