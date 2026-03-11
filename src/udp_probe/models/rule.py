"""IDS-style rules and rule matches (Tier 3)."""

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from udp_probe.models.base import Base


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Match: payload_regex (regex on payload), port (exact or "any"), protocol (UDP/TCP/any)
    payload_regex: Mapped[str | None] = mapped_column(String(512), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = any
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)  # UDP, TCP, or None = any
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    matches: Mapped[list["RuleMatch"]] = relationship(
        "RuleMatch", back_populates="rule", cascade="all, delete-orphan"
    )


class RuleMatch(Base):
    __tablename__ = "rule_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), nullable=False, index=True)
    matched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    capture_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    rule: Mapped["Rule"] = relationship("Rule", back_populates="matches")
