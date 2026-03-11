"""Honeypot events — fake open ports / services; log connection attempts (Tier 3)."""

from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from udp_probe.models.base import Base


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # TCP, UDP
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
