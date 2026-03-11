"""Honeypot API: start/stop fake listeners, list connection events."""

from fastapi import APIRouter
from pydantic import BaseModel

from udp_probe.core.database import get_session
from udp_probe.models.honeypot import HoneypotEvent
from udp_probe.honeypot import run_honeypot, stop_honeypot

router = APIRouter(prefix="/honeypot", tags=["honeypot"])


class HoneypotStart(BaseModel):
    ports: list[int]
    protocols: list[str] | None = None  # "tcp", "udp", or "both" per port


@router.post("/start", summary="Start honeypot listeners")
def api_honeypot_start(body: HoneypotStart) -> dict:
    run_honeypot(body.ports, body.protocols)
    return {"message": f"Honeypot started on ports {body.ports}."}


@router.post("/stop", summary="Stop all honeypot listeners")
def api_honeypot_stop() -> dict:
    stop_honeypot()
    return {"message": "Honeypot stopped."}


@router.get("/events", summary="List honeypot connection events")
def api_honeypot_events(limit: int = 100, port: int | None = None) -> list[dict]:
    session = get_session()
    try:
        q = session.query(HoneypotEvent).order_by(HoneypotEvent.received_at.desc()).limit(limit)
        if port is not None:
            q = q.filter(HoneypotEvent.port == port)
        return [
            {
                "id": e.id,
                "port": e.port,
                "protocol": e.protocol,
                "src_ip": e.src_ip,
                "src_port": e.src_port,
                "payload_snippet": e.payload_snippet,
                "received_at": e.received_at.isoformat() if e.received_at else None,
            }
            for e in q.all()
        ]
    finally:
        session.close()
