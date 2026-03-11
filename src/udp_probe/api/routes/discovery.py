from datetime import datetime

from fastapi import APIRouter, HTTPException

from udp_probe.core.database import get_session
from udp_probe.discovery.runner import run_discovery, parse_target, get_default_subnet
from udp_probe.models.discovery import DiscoveryRun, Host

router = APIRouter()


@router.post("/run")
def discovery_run(
    targets: str = "",  # comma-separated CIDRs or IPs; empty = use default subnet
    ports: str = "80,443,22,8080",
    no_ping: bool = False,
    save: bool = True,
):
    if not targets.strip():
        default = get_default_subnet()
        if not default:
            raise HTTPException(status_code=400, detail="No targets given and could not auto-detect subnet.")
        target_list = [default]
    else:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]
    if not target_list:
        raise HTTPException(status_code=400, detail="No valid targets.")

    try:
        port_list = tuple(int(p.strip()) for p in ports.split(",") if p.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ports.")

    results = run_discovery(target_list, ports=port_list, no_ping=no_ping)
    run_id = None
    if save and results:
        session = get_session()
        try:
            run_rec = DiscoveryRun(subnet=",".join(target_list))
            session.add(run_rec)
            session.commit()
            session.refresh(run_rec)
            run_id = run_rec.id
            for r in results:
                host = Host(
                    discovery_run_id=run_id,
                    ip=r["ip"],
                    hostname=r.get("hostname"),
                    open_ports=",".join(map(str, r.get("open_ports", []))) if r.get("open_ports") else None,
                )
                session.add(host)
            session.commit()
        finally:
            session.close()

    return {"ok": True, "run_id": run_id, "host_count": len(results), "hosts": results}


@router.get("/runs")
def discovery_runs(limit: int = 20):
    session = get_session()
    try:
        rows = session.query(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "subnet": r.subnet,
                "started_at": r.started_at.isoformat() if r.started_at else None,
            }
        for r in rows]
    finally:
        session.close()


@router.get("/runs/{run_id}")
def discovery_run_detail(run_id: int):
    session = get_session()
    try:
        rec = session.get(DiscoveryRun, run_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Discovery run not found.")
        hosts = [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "open_ports": h.open_ports.split(",") if h.open_ports else [],
            }
        for h in rec.hosts]
        return {"id": rec.id, "subnet": rec.subnet, "started_at": rec.started_at.isoformat(), "hosts": hosts}
    finally:
        session.close()
