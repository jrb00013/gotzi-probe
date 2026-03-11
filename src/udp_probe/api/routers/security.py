"""Security scan API — run security-oriented scan, list findings."""

from fastapi import APIRouter, Query

from udp_probe.scan import run_security_scan

router = APIRouter(prefix="/security-scan", tags=["security-scan"])


@router.get("")
def api_run_security_scan(target: str = Query(..., description="Target IP or hostname")) -> dict:
    """Run security scan (dangerous ports check). Returns list of findings."""
    findings = run_security_scan(target)
    return {"target": target, "findings": findings, "count": len(findings)}
