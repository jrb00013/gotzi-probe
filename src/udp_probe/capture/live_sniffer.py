"""
Background sniffer that feeds PacketStore. Used by TUI and web live-capture UI.
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Optional

from udp_probe.capture.packet_store import PacketStore, parse_raw_packet

logging.basicConfig(
    filename="udp_sniffer.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)


def run_live_sniffer(
    store: PacketStore,
    filter_port: Optional[int] = None,
    on_packet: Optional[Callable] = None,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """Run raw UDP sniffer in current thread; append to store, optionally call on_packet(p) and respect stop_event."""
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    if stop_event is None:
        stop_event = threading.Event()

    try:
        while not stop_event.is_set():
            try:
                sniffer.settimeout(0.5)
                raw_packet = sniffer.recvfrom(65535)[0]
            except socket.timeout:
                continue
            parsed = parse_raw_packet(raw_packet)
            if not parsed:
                continue
            src_ip, dest_ip, src_port, dest_port, length, checksum, payload = parsed
            if filter_port is not None and src_port != filter_port and dest_port != filter_port:
                continue
            packet = store.append(raw_packet)
            if packet and on_packet:
                try:
                    on_packet(packet)
                except Exception:
                    pass
            if packet:
                logging.info(
                    f"{src_ip}:{src_port} -> {dest_ip}:{dest_port} | Payload: {payload[:200]!r}"
                )
    except Exception as e:
        logging.exception("Sniffer error: %s", e)
    finally:
        try:
            sniffer.close()
        except Exception:
            pass


def start_live_sniffer_thread(
    store: PacketStore,
    filter_port: Optional[int] = None,
    on_packet: Optional[Callable] = None,
) -> tuple[threading.Thread, threading.Event]:
    """Start sniffer in a daemon thread; returns (thread, stop_event)."""
    stop = threading.Event()
    thread = threading.Thread(
        target=run_live_sniffer,
        args=(store,),
        kwargs={"filter_port": filter_port, "on_packet": on_packet, "stop_event": stop},
        daemon=True,
    )
    thread.start()
    return thread, stop
