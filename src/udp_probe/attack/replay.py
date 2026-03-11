"""Traffic replay — send packets from a simple replay file or (optional) PCAP. Authorized targets only."""

import json
import time
from pathlib import Path

from udp_probe.attack.audit import log_attack_session, end_attack_session

try:
    from scapy.all import rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def run_replay_file(
    target: str,
    replay_path: str | Path,
    delay_sec: float = 0.0,
    operator: str | None = None,
) -> int:
    """
    Replay packets from a JSON-lines file. Each line: {"payload_b64": "...", "port": 123} or {"port": 123, "payload_hex": "..."}.
    Target IP is overridden by `target`. Returns attack_session id.
    """
    path = Path(replay_path)
    if not path.exists():
        raise FileNotFoundError(f"Replay file not found: {path}")
    session_id = log_attack_session(
        "replay_file", target, port=None,
        params={"replay_path": str(path), "delay_sec": delay_sec},
        operator=operator,
    )
    import base64
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                port = obj.get("port")
                if port is None:
                    continue
                if "payload_b64" in obj:
                    payload = base64.b64decode(obj["payload_b64"])
                elif "payload_hex" in obj:
                    payload = bytes.fromhex(obj["payload_hex"])
                else:
                    payload = obj.get("payload", b"").encode() if isinstance(obj.get("payload"), str) else b""
                sock.sendto(payload, (target, port))
                if delay_sec > 0:
                    time.sleep(delay_sec)
    finally:
        sock.close()
        end_attack_session(session_id)
    return session_id


def run_replay_pcap(
    pcap_path: str | Path,
    target_override: str | None = None,
    delay_sec: float = 0.0,
    operator: str | None = None,
) -> int | None:
    """Replay UDP packets from a PCAP (requires scapy). Optionally override destination IP. Returns attack_session id or None if scapy missing."""
    if not SCAPY_AVAILABLE:
        return None
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")
    session_id = log_attack_session(
        "replay_pcap", target_override or str(path), port=None,
        params={"pcap_path": str(path), "delay_sec": delay_sec},
        operator=operator,
    )
    from scapy.all import IP, UDP, send
    packets = rdpcap(str(path))
    for pkt in packets:
        if UDP in pkt and (IP in pkt or hasattr(pkt, "payload")):
            if target_override and hasattr(pkt, "dst"):
                pkt = pkt.copy()
                pkt.dst = target_override
            send(pkt, verbose=0)
            if delay_sec > 0:
                time.sleep(delay_sec)
    end_attack_session(session_id)
    return session_id
