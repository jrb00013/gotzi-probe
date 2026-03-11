"""Alerts API — list alerts, list/add alert rules."""

from fastapi import APIRouter, HTTPException

from udp_probe.core.database import get_session
from udp_probe.models.alert import AlertRule, Alert

router = APIRouter()


@router.get("")
def alerts_list(limit: int = 50):
    session = get_session()
    try:
        rows = session.query(Alert).order_by(Alert.triggered_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "triggered_at": r.triggered_at.isoformat() if r.triggered_at else None,
                "message": r.message,
                "metadata_json": r.metadata_json,
            }
            for r in rows
        ]
    finally:
        session.close()


@router.get("/rules")
def alerts_rules_list(enabled_only: bool = False):
    session = get_session()
    try:
        q = session.query(AlertRule).order_by(AlertRule.id)
        if enabled_only:
            q = q.filter(AlertRule.enabled.is_(True))
        rows = q.all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "condition": r.condition,
                "params": r.params,
                "enabled": r.enabled,
            }
            for r in rows
        ]
    finally:
        session.close()


@router.post("/rules")
def alerts_rules_add(
    name: str,
    condition: str = "threshold",
    params: str | None = None,
    enabled: bool = True,
):
    session = get_session()
    try:
        rec = AlertRule(name=name, condition=condition, params=params, enabled=enabled)
        session.add(rec)
        session.commit()
        session.refresh(rec)
        return {"ok": True, "id": rec.id}
    finally:
        session.close()


@router.delete("/rules/{rule_id}")
def alerts_rules_delete(rule_id: int):
    session = get_session()
    try:
        rec = session.get(AlertRule, rule_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Rule not found.")
        session.delete(rec)
        session.commit()
        return {"ok": True}
    finally:
        session.close()
