"""Security findings from security-oriented scans (Tier 3)."""

from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from udp_probe.models.base import Base


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. weak_tls, open_dangerous_port, service_version
    severity: Mapped[str] = mapped_column(String(32), default="medium")  # low, medium, high, critical
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
