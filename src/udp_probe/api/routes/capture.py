from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException

from collections import Counter

from udp_probe.capture.sniffer import CaptureState, start_sniffer_thread
from udp_probe.core.database import get_session
from udp_probe.models.capture import Capture as CaptureModel, Packet

router = APIRouter()

# In-memory state for active capture (single active capture per process)
_active_capture: dict[str, Any] = {}  # state, thread, capture_id


@router.post("/start")
def capture_start(
    name: str = "session",
    interface: str = "",
    filter_expr: str = "",
    filter_port: int | None = None,
    store_in_db: bool = False,
    run_rules: bool = False,
):
    if _active_capture:
        raise HTTPException(status_code=409, detail="A capture is already running. Stop it first.")

    session = get_session()
    try:
        rec = CaptureModel(
            name=name,
            interface=interface,
            filter_expr=filter_expr or "",
            store_in_db=store_in_db,
        )
        session.add(rec)
        session.commit()
        session.refresh(rec)
        capture_id = rec.id
    finally:
        session.close()

    state = CaptureState()
    port_filter = filter_port
    if filter_expr.isdigit():
        try:
            port_filter = int(filter_expr)
        except ValueError:
            pass

    thread = start_sniffer_thread(
        state,
        filter_port=port_filter,
        capture_id=capture_id if store_in_db else None,
        store_in_db=store_in_db,
        run_rules=run_rules and store_in_db,
    )
    _active_capture["state"] = state
    _active_capture["thread"] = thread
    _active_capture["capture_id"] = capture_id
    return {"ok": True, "capture_id": capture_id, "message": "Capture started (requires raw socket capability)."}


@router.post("/stop")
def capture_stop():
    if not _active_capture:
        raise HTTPException(status_code=404, detail="No active capture.")
    state: CaptureState = _active_capture["state"]
    capture_id = _active_capture.get("capture_id")
    state.stop()
    _active_capture.get("thread").join(timeout=3.0)
    _active_capture.clear()

    if capture_id:
        session = get_session()
        try:
            rec = session.get(CaptureModel, capture_id)
            if rec:
                rec.stopped_at = datetime.utcnow()
                rec.packet_count = state.packet_count
                session.commit()
        finally:
            session.close()

    return {"ok": True, "packet_count": state.packet_count}


@router.get("/status")
def capture_status():
    if not _active_capture:
        return {"running": False}
    state: CaptureState = _active_capture["state"]
    return {
        "running": state.running,
        "packet_count": state.packet_count,
        "byte_count": state.byte_count,
        "capture_id": _active_capture.get("capture_id"),
        "error": state.error,
    }


@router.get("/sessions")
def capture_sessions(limit: int = 50):
    session = get_session()
    try:
        rows = session.query(CaptureModel).order_by(CaptureModel.started_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "stopped_at": r.stopped_at.isoformat() if r.stopped_at else None,
                "packet_count": r.packet_count,
            }
        for r in rows]
    finally:
        session.close()


@router.get("/sessions/{capture_id}/stats")
def capture_session_stats(capture_id: int):
    """Aggregated stats: byte_count, top_src_ips, top_dst_ports."""
    session = get_session()
    try:
        rec = session.get(CaptureModel, capture_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Capture not found.")
        packets = session.query(Packet).filter(Packet.capture_id == capture_id).all()
        byte_count = sum(p.length for p in packets)
        src_ips = Counter(p.src_ip for p in packets)
        dst_ports = Counter(p.dst_port for p in packets)
        return {
            "capture_id": capture_id,
            "packet_count": len(packets),
            "byte_count": byte_count,
            "top_src_ips": src_ips.most_common(10),
            "top_dst_ports": dst_ports.most_common(10),
        }
    finally:
        session.close()


@router.get("/sessions/{capture_id}/pcap")
def capture_download_pcap(capture_id: int):
    """Download PCAP. 404 if not recorded."""
    session = get_session()
    try:
        rec = session.get(CaptureModel, capture_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Capture not found.")
        if not rec.pcap_path:
            raise HTTPException(status_code=404, detail="PCAP not recorded for this capture.")
        import os
        from fastapi.responses import FileResponse
        if not os.path.isfile(rec.pcap_path):
            raise HTTPException(status_code=404, detail="PCAP file not found.")
        return FileResponse(rec.pcap_path, filename=os.path.basename(rec.pcap_path), media_type="application/vnd.tcpdump.pcap")
    finally:
        session.close()


@router.get("/sessions/{capture_id}")
def capture_session_detail(capture_id: int):
    session = get_session()
    try:
        rec = session.get(CaptureModel, capture_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Capture not found.")
        return {
            "id": rec.id,
            "name": rec.name,
            "interface": rec.interface,
            "filter_expr": rec.filter_expr,
            "started_at": rec.started_at.isoformat() if rec.started_at else None,
            "stopped_at": rec.stopped_at.isoformat() if rec.stopped_at else None,
            "pcap_path": rec.pcap_path,
            "packet_count": rec.packet_count,
        }
    finally:
        session.close()
