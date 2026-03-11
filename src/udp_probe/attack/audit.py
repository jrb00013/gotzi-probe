"""Audit log for attack sessions (attack_sessions table)."""

import json
from datetime import datetime
from typing import Any

from udp_probe.core.database import get_session
from udp_probe.models.attack import AttackSession


def log_attack_session(
    attack_type: str,
    target: str,
    port: int | None = None,
    params: dict[str, Any] | None = None,
    operator: str | None = None,
    ended_at: datetime | None = None,
) -> int:
    """Create an attack_sessions row; returns id."""
    session = get_session()
    try:
        rec = AttackSession(
            attack_type=attack_type,
            target=target,
            port=port,
            params_json=json.dumps(params) if params else None,
            operator=operator,
            ended_at=ended_at,
        )
        session.add(rec)
        session.commit()
        session.refresh(rec)
        return rec.id
    finally:
        session.close()


def end_attack_session(session_id: int) -> None:
    """Set ended_at for an attack session."""
    session = get_session()
    try:
        rec = session.get(AttackSession, session_id)
        if rec:
            rec.ended_at = datetime.utcnow()
            session.commit()
    finally:
        session.close()
