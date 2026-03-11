from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from udp_probe.models.base import Base


class AttackSession(Base):
    __tablename__ = "attack_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    params_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    operator: Mapped[str | None] = mapped_column(String(256), nullable=True)
