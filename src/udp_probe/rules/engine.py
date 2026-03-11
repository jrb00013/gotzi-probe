"""Rule engine: match a packet against rule criteria (payload_regex, port, protocol)."""

import re
from typing import Any

# Packet-like: has src_ip, dst_ip, src_port, dst_port, payload (bytes or str), protocol (optional)


def match_packet(
    payload_regex: str | None,
    port: int | None,
    protocol: str | None,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes | str,
    protocol_value: str = "UDP",
) -> bool:
    """Return True if the packet matches the rule criteria."""
    if port is not None and src_port != port and dst_port != port:
        return False
    if protocol is not None and protocol_value.upper() != protocol.upper():
        return False
    if payload_regex:
        try:
            text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
            if not re.search(payload_regex, text):
                return False
        except re.error:
            return False
    return True


class RuleEngine:
    """Apply enabled rules to a packet and record matches."""

    def __init__(self, session_factory=None):
        from udp_probe.core.database import get_session
        self._get_session = session_factory or get_session

    def run_on_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
        protocol: str = "UDP",
        capture_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Match packet against all enabled rules; persist RuleMatch and return list of match info."""
        from udp_probe.models.rule import Rule, RuleMatch

        session = self._get_session()
        matches = []
        try:
            rules = session.query(Rule).filter(Rule.enabled.is_(True)).all()
            payload_snippet = (payload[:200].decode("utf-8", errors="replace") if payload else "")
            for rule in rules:
                if not match_packet(
                    rule.payload_regex,
                    rule.port,
                    rule.protocol,
                    src_ip, dst_ip, src_port, dst_port,
                    payload,
                    protocol,
                ):
                    continue
                rm = RuleMatch(
                    rule_id=rule.id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    payload_snippet=payload_snippet[:500] if payload_snippet else None,
                    capture_id=capture_id,
                )
                session.add(rm)
                matches.append({"rule_id": rule.id, "rule_name": rule.name, "match_id": None})
            session.commit()
            for m in matches:
                # match_id not filled without refresh; optional
                pass
            return matches
        finally:
            session.close()
