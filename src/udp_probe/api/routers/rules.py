"""IDS-style rules API: add/list/disable rules, list matches."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from udp_probe.rules import list_rules, add_rule, delete_rule, enable_rule, list_rule_matches

router = APIRouter(prefix="/rules", tags=["rules"])


class RuleCreate(BaseModel):
    name: str
    payload_regex: str | None = None
    port: int | None = None
    protocol: str | None = None
    description: str | None = None
    enabled: bool = True


class RuleUpdate(BaseModel):
    enabled: bool | None = None


@router.get("", summary="List rules")
def api_list_rules(enabled_only: bool = False) -> list[dict]:
    return list_rules(enabled_only=enabled_only)


@router.post("", summary="Create rule")
def api_add_rule(body: RuleCreate) -> dict:
    rid = add_rule(
        body.name,
        payload_regex=body.payload_regex,
        port=body.port,
        protocol=body.protocol,
        description=body.description,
        enabled=body.enabled,
    )
    return {"id": rid, "message": "Rule created."}


@router.delete("/{rule_id}", summary="Delete rule")
def api_delete_rule(rule_id: int) -> dict:
    if not delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"message": "Deleted."}


@router.patch("/{rule_id}", summary="Enable/disable rule")
def api_enable_rule(rule_id: int, body: RuleUpdate) -> dict:
    if body.enabled is None:
        raise HTTPException(status_code=400, detail="enabled required")
    if not enable_rule(rule_id, body.enabled):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"message": "Updated."}


@router.get("/matches", summary="List rule matches")
def api_list_matches(rule_id: int | None = None, limit: int = 100) -> list[dict]:
    return list_rule_matches(rule_id=rule_id, limit=limit)
