"""Attack simulation API — requires explicit target authorization. Warnings in responses."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from udp_probe.attack import run_udp_flood, run_tcp_flood, run_port_knock, run_slowloris, run_replay_file, run_replay_pcap
from udp_probe.core.database import get_session
from udp_probe.models.attack import AttackSession

router = APIRouter(prefix="/attack", tags=["attack"])

WARNING = "Use only on targets you are authorized to test. All sessions are audit-logged."


class FloodRequest(BaseModel):
    target: str
    port: int
    duration_sec: float = 10.0
    protocol: str = "udp"


class PortKnockRequest(BaseModel):
    target: str
    ports: list[int]
    protocol: str = "udp"
    delay_sec: float = 0.2


class SlowlorisRequest(BaseModel):
    target: str
    port: int = 80
    duration_sec: float = 60.0
    num_sockets: int = 200


class ReplayRequest(BaseModel):
    target: str
    replay_path: str
    delay_sec: float = 0.0


@router.post("/flood", summary="Run UDP/TCP flood (authorized targets only)")
def attack_flood(body: FloodRequest) -> dict:
    """Run flood. Warning: authorized targets only. Audit-logged."""
    if body.protocol.lower() == "tcp":
        session_id = run_tcp_flood(body.target, body.port, body.duration_sec)
    else:
        session_id = run_udp_flood(body.target, body.port, body.duration_sec)
    return {"warning": WARNING, "attack_session_id": session_id, "message": "Flood started and completed."}


@router.post("/port-knock", summary="Run port knock sequence")
def attack_port_knock(body: PortKnockRequest) -> dict:
    session_id = run_port_knock(body.target, body.ports, body.protocol, body.delay_sec)
    return {"warning": WARNING, "attack_session_id": session_id}


@router.post("/slowloris", summary="Run slowloris (authorized targets only)")
def attack_slowloris(body: SlowlorisRequest) -> dict:
    session_id = run_slowloris(body.target, body.port, body.duration_sec, body.num_sockets)
    return {"warning": WARNING, "attack_session_id": session_id}


@router.post("/replay", summary="Replay from JSON-lines file")
def attack_replay(body: ReplayRequest) -> dict:
    try:
        session_id = run_replay_file(body.target, body.replay_path, body.delay_sec)
        return {"warning": WARNING, "attack_session_id": session_id}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/sessions", summary="List attack sessions (audit log)")
def list_attack_sessions(limit: int = 50) -> list[dict]:
    session = get_session()
    try:
        rows = session.query(AttackSession).order_by(AttackSession.started_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "attack_type": r.attack_type,
                "target": r.target,
                "port": r.port,
                "params_json": r.params_json,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            }
            for r in rows
        ]
    finally:
        session.close()
