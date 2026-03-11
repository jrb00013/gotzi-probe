import csv
import io
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from udp_probe.core.database import get_session
from udp_probe.models.scan import Scan, ScanResult
from udp_probe.scan.scanner import run_port_scan, parse_port_range

router = APIRouter()


@router.post("/run")
def scan_run(
    target: str,
    port_spec: str = "1-1024",
    scan_tcp: bool = True,
    scan_udp: bool = False,
    save: bool = True,
):
    ports = parse_port_range(port_spec)
    if not ports:
        raise HTTPException(status_code=400, detail="Invalid port range.")
    results = run_port_scan(target, port_spec, scan_tcp=scan_tcp, scan_udp=scan_udp)

    scan_id = None
    if save:
        session = get_session()
        try:
            scan_rec = Scan(
                target=target,
                port_range=port_spec,
                scan_type="tcp" if scan_tcp and not scan_udp else "udp" if scan_udp else "both",
            )
            session.add(scan_rec)
            session.commit()
            session.refresh(scan_rec)
            scan_id = scan_rec.id
            for r in results:
                session.add(
                    ScanResult(scan_id=scan_id, port=r["port"], state=r["state"], service=r.get("service"))
                )
            scan_rec.finished_at = datetime.utcnow()
            session.commit()
        finally:
            session.close()

    open_ports = [r for r in results if r["state"] in ("open", "open|filtered")]
    return {
        "ok": True,
        "scan_id": scan_id,
        "target": target,
        "total_ports": len(results),
        "open_count": len(open_ports),
        "results": results,
    }


@router.get("/history")
def scan_history(limit: int = 50, target: str | None = None):
    session = get_session()
    try:
        q = session.query(Scan).order_by(Scan.started_at.desc())
        if target:
            q = q.filter(Scan.target == target)
        rows = q.limit(limit).all()
        return [
            {
                "id": r.id,
                "target": r.target,
                "port_range": r.port_range,
                "scan_type": r.scan_type,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
        for r in rows]
    finally:
        session.close()


@router.get("/diff/{id1}/{id2}")
def scan_diff(id1: int, id2: int):
    session = get_session()
    try:
        s1 = session.get(Scan, id1)
        s2 = session.get(Scan, id2)
        if not s1 or not s2:
            raise HTTPException(status_code=404, detail="One or both scans not found.")
        open1 = {r.port for r in s1.results if r.state in ("open", "open|filtered")}
        open2 = {r.port for r in s2.results if r.state in ("open", "open|filtered")}
        new_open = sorted(open2 - open1)
        closed = sorted(open1 - open2)
        return {
            "scan_id_1": id1,
            "scan_id_2": id2,
            "new_open_ports": new_open,
            "newly_closed_ports": closed,
        }
    finally:
        session.close()


@router.get("/{scan_id}/csv")
def scan_export_csv(scan_id: int):
    session = get_session()
    try:
        rec = session.get(Scan, scan_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Scan not found.")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["port", "state", "service"])
        for r in rec.results:
            w.writerow([r.port, r.state, r.service or ""])
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"},
        )
    finally:
        session.close()


@router.get("/{scan_id}")
def scan_detail(scan_id: int):
    session = get_session()
    try:
        rec = session.get(Scan, scan_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Scan not found.")
        results = [{"port": r.port, "state": r.state, "service": r.service} for r in rec.results]
        return {
            "id": rec.id,
            "target": rec.target,
            "port_range": rec.port_range,
            "scan_type": rec.scan_type,
            "started_at": rec.started_at.isoformat() if rec.started_at else None,
            "results": results,
        }
    finally:
        session.close()
