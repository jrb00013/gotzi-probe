"""Traffic digest: summarize CSV probe session or packet list."""

import csv
from collections import Counter
from pathlib import Path
from statistics import mean, stdev
from typing import Any


def digest_csv(file_path: str = "udp_session.csv") -> dict[str, Any]:
    """Analyze probe session CSV. Returns summary dict."""
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    probe_ids: list[int] = []
    rtts: list[float] = []
    seen: set[int] = set()
    duplicates = 0

    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                pid = int(row.get("ID", row.get("id", 0)))
                rtt = float(row.get("RTT_ms", row.get("rtt_ms", -1)))
            except (ValueError, KeyError):
                continue
            if pid in seen:
                duplicates += 1
            else:
                seen.add(pid)
                probe_ids.append(pid)
                if rtt >= 0:
                    rtts.append(rtt)

    expected = max(probe_ids) if probe_ids else 0
    lost = expected - len(seen)

    out: dict[str, Any] = {
        "total_packets_received": len(seen),
        "expected_packets": expected,
        "duplicates": duplicates,
        "lost_packets": lost,
    }
    if rtts:
        out["average_rtt_ms"] = round(mean(rtts), 2)
        out["rtt_std_dev_ms"] = round(stdev(rtts), 2)
    return out


def digest_packets(
    packets: list[dict],
) -> dict[str, Any]:
    """Summarize a list of packet dicts (src_ip, dst_ip, src_port, dst_port, length, ...)."""
    if not packets:
        return {"packet_count": 0, "byte_count": 0, "top_src_ips": [], "top_ports": []}

    byte_count = sum(p.get("length", 0) for p in packets)
    src_ips = Counter(p.get("src_ip", "") for p in packets)
    dst_ports = Counter(p.get("dst_port", 0) for p in packets)

    return {
        "packet_count": len(packets),
        "byte_count": byte_count,
        "top_src_ips": src_ips.most_common(10),
        "top_dst_ports": dst_ports.most_common(10),
    }
