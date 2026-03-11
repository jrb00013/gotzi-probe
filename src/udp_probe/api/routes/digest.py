from fastapi import APIRouter, HTTPException

from udp_probe.digest.analyzer import digest_csv, digest_packets
from udp_probe.core.database import get_session
from udp_probe.models.capture import Packet

router = APIRouter()


@router.post("/csv")
def digest_csv_route(file_path: str = "udp_session.csv"):
    result = digest_csv(file_path)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/capture/{capture_id}")
def digest_capture(capture_id: int):
    session = get_session()
    try:
        packets = (
            session.query(Packet)
            .filter(Packet.capture_id == capture_id)
            .order_by(Packet.timestamp)
            .all()
        )
        packet_dicts = [
            {
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "length": p.length,
            }
        for p in packets]
        return digest_packets(packet_dicts)
    finally:
        session.close()
