"""
Shared packet model and thread-safe store for TUI and web UI (Wireshark-like live capture).
"""
from __future__ import annotations

import socket
import struct
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Optional


@dataclass
class ParsedPacket:
    """A single captured UDP packet (IP + UDP headers + payload)."""
    index: int
    timestamp: float
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    length: int
    checksum: int
    payload: bytes
    raw: bytes  # full IP packet for hex dump

    @property
    def summary(self) -> str:
        try:
            return self.payload.decode("utf-8", errors="replace").strip()[:80]
        except Exception:
            return "<binary>"

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "src_port": self.src_port,
            "dest_port": self.dest_port,
            "length": self.length,
            "checksum": self.checksum,
            "payload_hex": self.payload.hex(),
            "payload_preview": self.summary,
            "raw_hex": self.raw.hex(),
            "raw_len": len(self.raw),
        }


class PacketStore:
    """Thread-safe, bounded packet buffer for live capture."""
    _lock = Lock()
    _index = 0

    def __init__(self, max_packets: int = 50_000):
        self._packets: deque[ParsedPacket] = deque(maxlen=max_packets)
        self.max_packets = max_packets

    def append(self, raw_packet: bytes) -> Optional[ParsedPacket]:
        with self._lock:
            try:
                if len(raw_packet) < 28:
                    return None
                ip_header = struct.unpack("!BBHHHBBH4s4s", raw_packet[:20])
                udp_header = struct.unpack("!HHHH", raw_packet[20:28])
                src_ip = socket.inet_ntoa(ip_header[8])
                dest_ip = socket.inet_ntoa(ip_header[9])
                src_port, dest_port, length, checksum = udp_header
                payload = raw_packet[28:]
                PacketStore._index += 1
                p = ParsedPacket(
                    index=PacketStore._index,
                    timestamp=time.time(),
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    src_port=src_port,
                    dest_port=dest_port,
                    length=length,
                    checksum=checksum,
                    payload=payload,
                    raw=raw_packet,
                )
                self._packets.append(p)
                return p
            except Exception:
                return None

    def get_all(self) -> list[ParsedPacket]:
        with self._lock:
            return list(self._packets)

    def get_by_index(self, index: int) -> Optional[ParsedPacket]:
        with self._lock:
            for p in self._packets:
                if p.index == index:
                    return p
            return None

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()

    def count(self) -> int:
        with self._lock:
            return len(self._packets)


def parse_raw_packet(raw_packet: bytes) -> Optional[tuple]:
    """Parse IP+UDP from raw bytes; returns (src_ip, dest_ip, src_port, dest_port, length, checksum, payload) or None."""
    if len(raw_packet) < 28:
        return None
    try:
        ip_header = struct.unpack("!BBHHHBBH4s4s", raw_packet[:20])
        udp_header = struct.unpack("!HHHH", raw_packet[20:28])
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        src_port, dest_port, length, checksum = udp_header
        payload = raw_packet[28:]
        return (src_ip, dest_ip, src_port, dest_port, length, checksum, payload)
    except Exception:
        return None
