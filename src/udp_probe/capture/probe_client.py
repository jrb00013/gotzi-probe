"""UDP probe client: send probe packets, optional echo check."""

import socket
import time

from udp_probe.core.config import get_config


def run_probe_client(
    target_ip: str,
    target_port: int,
    interval: float = 1.0,
    count: int = 10,
    echo: bool | None = None,
) -> list[dict]:
    cfg = get_config()
    echo = echo if echo is not None else cfg.probe_echo

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    results = []

    for i in range(1, count + 1):
        payload = f"probe_id={i}, timestamp={time.time()}"
        start = time.time()
        sock.sendto(payload.encode(), (target_ip, target_port))
        rtt_ms = -1.0
        try:
            if echo:
                data, _ = sock.recvfrom(2048)
                rtt_ms = (time.time() - start) * 1000
            results.append({"probe_id": i, "rtt_ms": rtt_ms, "payload": payload})
        except socket.timeout:
            results.append({"probe_id": i, "rtt_ms": -1.0, "payload": payload})
        time.sleep(interval)

    sock.close()
    return results
