"""Packet sniffer (UDP); can run in thread and optionally stream to DB."""

import socket
import struct
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from udp_probe.models.capture import Capture as CaptureModel, Packet as PacketModel
from udp_probe.core.database import get_session


@dataclass
class CaptureState:
    running: bool = False
    packet_count: int = 0
    byte_count: int = 0
    error: str | None = None
    _stop: bool = False

    def stop(self) -> None:
        self._stop = True


def _parse_udp_packet(raw: bytes) -> tuple[str, str, int, int, int, str] | None:
    if len(raw) < 28:
        return None
    try:
        ip_header = struct.unpack("!BBHHHBBH4s4s", raw[:20])
        udp_header = struct.unpack("!HHHH", raw[20:28])
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        src_port, dest_port, length, _ = udp_header
        payload = raw[28:].decode(errors="replace")[:500]
        return (src_ip, dest_ip, src_port, dest_port, length, payload)
    except Exception:
        return None


def run_sniffer(
    state: CaptureState,
    *,
    filter_port: int | None = None,
    capture_id: int | None = None,
    store_in_db: bool = False,
    run_rules: bool = False,
    on_packet: Optional[Callable[[str, str, int, int, int, str], None]] = None,
) -> None:
    """Sniff UDP packets. Runs until state.stop() or error. Requires root/cap_net_raw for raw socket."""
    state.running = True
    state._stop = False
    state.error = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.settimeout(1.0)
    except OSError as e:
        state.running = False
        state.error = str(e)
        return

    try:
        while not state._stop:
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            parsed = _parse_udp_packet(raw)
            if not parsed:
                continue
            src_ip, dst_ip, src_port, dst_port, length, payload = parsed
            if filter_port is not None and src_port != filter_port and dst_port != filter_port:
                continue

            state.packet_count += 1
            state.byte_count += length

            if on_packet:
                on_packet(src_ip, dst_ip, src_port, dst_port, length, payload)

            if store_in_db and capture_id is not None:
                try:
                    session = get_session()
                    try:
                        pkt = PacketModel(
                            capture_id=capture_id,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol="UDP",
                            length=length,
                            payload_snippet=payload[:256] if payload else None,
                        )
                        session.add(pkt)
                        session.commit()
                    finally:
                        session.close()
                    if run_rules:
                        try:
                            from udp_probe.rules import run_rules_on_packet
                            payload_bytes = payload.encode("utf-8", errors="replace") if isinstance(payload, str) else payload.encode(errors="replace")
                            run_rules_on_packet(
                                src_ip, dst_ip, src_port, dst_port,
                                payload_bytes, protocol="UDP", capture_id=capture_id,
                            )
                        except Exception:
                            pass
                except Exception:
                    pass

    except Exception as e:
        state.error = str(e)
    finally:
        sock.close()
        state.running = False


def start_sniffer_thread(
    state: CaptureState,
    filter_port: int | None = None,
    capture_id: int | None = None,
    store_in_db: bool = False,
    run_rules: bool = False,
) -> threading.Thread:
    t = threading.Thread(
        target=run_sniffer,
        kwargs=dict(
            state=state,
            filter_port=filter_port,
            capture_id=capture_id,
            store_in_db=store_in_db,
            run_rules=run_rules,
        ),
        daemon=True,
    )
    t.start()
    return t
