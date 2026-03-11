"""UDP probe listener: receives probe packets, logs RTT, optional echo."""

import csv
import socket
import time
from pathlib import Path

from udp_probe.core.config import get_config


def extract_probe_info(data: str) -> tuple[int, float]:
    try:
        items = dict(item.split("=") for item in data.strip().split(", "))
        return int(items.get("probe_id", -1)), float(items.get("timestamp", 0.0))
    except Exception:
        return -1, 0.0


def run_probe_server(
    host: str | None = None,
    port: int | None = None,
    echo: bool | None = None,
    csv_path: str | None = None,
    stop_event: object | None = None,
) -> None:
    cfg = get_config()
    host = host or cfg.probe_host
    port = port or cfg.probe_port
    echo = echo if echo is not None else cfg.probe_echo
    csv_path = csv_path or "udp_session.csv"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind((host, port))

    seen_ids: set[int] = set()
    packet_count = 0
    start_time = time.time()

    Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ID", "From", "RTT_ms", "Message"])

        while True:
            if getattr(stop_event, "is_set", lambda: False)():
                break
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            recv_time = time.time()
            msg = data.decode(errors="ignore")
            probe_id, sent_ts = extract_probe_info(msg)
            rtt = (recv_time - sent_ts) * 1000 if sent_ts > 0 else -1.0
            duplicate = probe_id in seen_ids
            if not duplicate:
                seen_ids.add(probe_id)
            packet_count += 1
            writer.writerow([probe_id, addr[0], f"{rtt:.2f}", msg])
            csvfile.flush()
            if echo:
                try:
                    sock.sendto(f"ACK: {probe_id}".encode(), addr)
                except OSError:
                    pass

    duration = time.time() - start_time
    sock.close()
