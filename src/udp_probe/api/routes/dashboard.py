"""Traffic dashboard API — live stats and recent packet aggregates."""

from collections import Counter

from fastapi import APIRouter

from udp_probe.core.database import get_session
from udp_probe.models.capture import Packet

router = APIRouter()


def _get_live_status():
    try:
        from udp_probe.api.routes.capture import _active_capture
        if _active_capture and _active_capture.get("state"):
            s = _active_capture["state"]
            return {"running": s.running, "packet_count": s.packet_count, "byte_count": s.byte_count}
    except Exception:
        pass
    return {"running": False, "packet_count": 0, "byte_count": 0}


@router.get("/stats")
def dashboard_stats():
    """Live capture stats plus recent DB packet summary and top IPs/ports."""
    live = _get_live_status()
    session = get_session()
    try:
        packets = session.query(Packet).order_by(Packet.timestamp.desc()).limit(1000).all()
        total_bytes = sum(p.length for p in packets)
        src_ips = Counter(p.src_ip for p in packets)
        dst_ports = Counter(p.dst_port for p in packets)
        return {
            "live": live,
            "recent_packets": len(packets),
            "recent_bytes": total_bytes,
            "top_src_ips": src_ips.most_common(10),
            "top_dst_ports": dst_ports.most_common(10),
        }
    finally:
        session.close()
