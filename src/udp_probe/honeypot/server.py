"""Fake TCP/UDP listeners that log connection attempts to honeypot_events."""

import socket
import threading
from typing import Callable

from udp_probe.core.database import get_session
from udp_probe.models.honeypot import HoneypotEvent

_listeners: list[tuple[socket.socket, threading.Thread]] = []
_stop_events: list[threading.Event] = []


def _log_event(port: int, protocol: str, src_ip: str, src_port: int, payload_snippet: str | None) -> None:
    session = get_session()
    try:
        session.add(HoneypotEvent(
            port=port,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            payload_snippet=payload_snippet[:500] if payload_snippet else None,
        ))
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def _udp_listener(port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.bind(("0.0.0.0", port))
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
            _log_event(port, "UDP", addr[0], addr[1], data[:200].decode("utf-8", errors="replace"))
        except socket.timeout:
            continue
        except Exception:
            break
    try:
        sock.close()
    except Exception:
        pass


def _tcp_listener(port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    sock.bind(("0.0.0.0", port))
    sock.listen(50)
    while not stop.is_set():
        try:
            conn, addr = sock.accept()
            try:
                data = conn.recv(1024)
                _log_event(port, "TCP", addr[0], addr[1], data[:200].decode("utf-8", errors="replace") if data else None)
            finally:
                conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    try:
        sock.close()
    except Exception:
        pass


def run_honeypot(ports: list[int], protocols: list[str] | None = None) -> None:
    """
    Start fake listeners on given ports. protocols: list of "tcp" and/or "udp" per port, or None = both.
    If protocols is None, each port gets both TCP and UDP. Else protocols[i] applies to ports[i] (or "both").
    """
    if protocols is None:
        protocols = ["both"] * len(ports)
    while len(protocols) < len(ports):
        protocols.append("both")
    for i, port in enumerate(ports):
        proto = (protocols[i] if i < len(protocols) else "both").lower()
        if proto in ("udp", "both"):
            stop = threading.Event()
            _stop_events.append(stop)
            t = threading.Thread(target=_udp_listener, args=(port, stop), daemon=True)
            t.start()
            _listeners.append((None, t))  # UDP socket is inside thread
        if proto in ("tcp", "both"):
            stop = threading.Event()
            _stop_events.append(stop)
            t = threading.Thread(target=_tcp_listener, args=(port, stop), daemon=True)
            t.start()
            _listeners.append((None, t))


def stop_honeypot() -> None:
    """Stop all honeypot listeners."""
    for e in _stop_events:
        e.set()
    _stop_events.clear()
    for s, t in _listeners:
        if s:
            try:
                s.close()
            except Exception:
                pass
        t.join(timeout=2.0)
    _listeners.clear()
