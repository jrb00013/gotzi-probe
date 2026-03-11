"""CRUD and run for IDS rules."""

from udp_probe.core.database import get_session
from udp_probe.models.rule import Rule, RuleMatch
from udp_probe.rules.engine import RuleEngine

_engine: RuleEngine | None = None


def _get_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine


def list_rules(enabled_only: bool = False) -> list[dict]:
    """List all rules (or only enabled)."""
    session = get_session()
    try:
        q = session.query(Rule)
        if enabled_only:
            q = q.filter(Rule.enabled.is_(True))
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "payload_regex": r.payload_regex,
                "port": r.port,
                "protocol": r.protocol,
                "enabled": r.enabled,
            }
            for r in q.all()
        ]
    finally:
        session.close()


def add_rule(
    name: str,
    payload_regex: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    description: str | None = None,
    enabled: bool = True,
) -> int:
    """Create a rule; returns id."""
    session = get_session()
    try:
        r = Rule(
            name=name,
            description=description,
            payload_regex=payload_regex,
            port=port,
            protocol=protocol,
            enabled=enabled,
        )
        session.add(r)
        session.commit()
        session.refresh(r)
        return r.id
    finally:
        session.close()


def delete_rule(rule_id: int) -> bool:
    """Delete rule by id. Returns True if deleted."""
    session = get_session()
    try:
        r = session.get(Rule, rule_id)
        if r:
            session.delete(r)
            session.commit()
            return True
        return False
    finally:
        session.close()


def enable_rule(rule_id: int, enabled: bool = True) -> bool:
    """Enable or disable a rule."""
    session = get_session()
    try:
        r = session.get(Rule, rule_id)
        if r:
            r.enabled = enabled
            session.commit()
            return True
        return False
    finally:
        session.close()


def run_rules_on_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    protocol: str = "UDP",
    capture_id: int | None = None,
) -> list[dict]:
    """Run all enabled rules on one packet; store matches and return match list."""
    return _get_engine().run_on_packet(
        src_ip, dst_ip, src_port, dst_port, payload, protocol, capture_id
    )


def list_rule_matches(rule_id: int | None = None, limit: int = 100) -> list[dict]:
    """List recent rule matches, optionally for one rule."""
    session = get_session()
    try:
        q = session.query(RuleMatch).order_by(RuleMatch.matched_at.desc()).limit(limit)
        if rule_id is not None:
            q = q.filter(RuleMatch.rule_id == rule_id)
        return [
            {
                "id": m.id,
                "rule_id": m.rule_id,
                "matched_at": m.matched_at.isoformat() if m.matched_at else None,
                "src_ip": m.src_ip,
                "dst_ip": m.dst_ip,
                "src_port": m.src_port,
                "dst_port": m.dst_port,
                "payload_snippet": m.payload_snippet,
            }
            for m in q.all()
        ]
    finally:
        session.close()
