"""
Gotzi Web UI — FastAPI backend + Wireshark-like packet browser.
Run: python web_server.py   or   python main.py --web [--port 8080]
Start the sniffer (requires root) and open http://localhost:8080
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles

from packet_store import PacketStore, ParsedPacket
from sniffer_thread import start_sniffer_thread

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"

app = FastAPI(title="Gotzi", description="Wireshark-like packet capture and security toolkit")

# Global store and sniffer control; set by main()
_store: Optional[PacketStore] = None
_stop_event: Optional[object] = None


def format_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"


def hex_dump(data: bytes, bytes_per_line: int = 16) -> list[dict]:
    """Return list of {offset_hex, hex_part, ascii_part} for frontend."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append({"offset": f"{i:04x}", "hex": hex_part, "ascii": ascii_part})
    return lines


def packet_to_list_item(p: ParsedPacket) -> dict:
    return {
        "index": p.index,
        "time": format_ts(p.timestamp),
        "timestamp": p.timestamp,
        "src_ip": p.src_ip,
        "dest_ip": p.dest_ip,
        "src_port": p.src_port,
        "dest_port": p.dest_port,
        "length": p.length,
        "info": p.summary[:80],
    }


def packet_to_detail(p: ParsedPacket) -> dict:
    return {
        **packet_to_list_item(p),
        "checksum": f"0x{p.checksum:04x}",
        "payload_hex": p.payload.hex(),
        "payload_preview": p.summary,
        "hex_dump": hex_dump(p.raw),
        "raw_len": len(p.raw),
    }


@app.get("/api/packets")
def list_packets(
    port: Optional[int] = Query(None),
    ip: Optional[str] = Query(None),
    limit: int = Query(500, le=5000),
) -> dict:
    if _store is None:
        return {"packets": [], "total": 0}
    packets = _store.get_all()
    if port is not None:
        packets = [p for p in packets if p.src_port == port or p.dest_port == port]
    if ip:
        ip_l = ip.strip().lower()
        packets = [
            p
            for p in packets
            if ip_l in p.src_ip.lower() or ip_l in p.dest_ip.lower()
        ]
    packets = packets[-limit:]
    return {
        "packets": [packet_to_list_item(p) for p in packets],
        "total": _store.count(),
    }


@app.get("/api/packets/{index}")
def get_packet(index: int) -> dict | None:
    if _store is None:
        return None
    p = _store.get_by_index(index)
    if p is None:
        return None
    return packet_to_detail(p)


@app.post("/api/clear")
def clear_packets() -> dict:
    if _store is not None:
        _store.clear()
    return {"ok": True}


# Tier 3 API (attack, rules, honeypot, security-scan) — requires udp_probe + DB
try:
    import udp_probe.models  # noqa: F401 — register models
    from udp_probe.core.database import init_db
    from udp_probe.api.routers import attack_router, rules_router, honeypot_router
    from udp_probe.api.routers.security import router as security_router
    init_db()
    app.include_router(attack_router, prefix="/api")
    app.include_router(rules_router, prefix="/api")
    app.include_router(honeypot_router, prefix="/api")
    app.include_router(security_router, prefix="/api")
except Exception:
    pass


if WEB_DIR.is_dir():
    # Serve SPA and assets from root; API routes are matched first
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="frontend")


def run_web(port: int = 8080, filter_port: Optional[int] = None) -> None:
    global _store, _stop_event
    _store = PacketStore(max_packets=30_000)
    try:
        _, _stop_event = start_sniffer_thread(_store, filter_port=filter_port)
    except Exception as e:
        print(f"[!] Sniffer failed (need root?): {e}")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    run_web(port=8080)
