from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from udp_probe.models.base import Base


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    interface: Mapped[str] = mapped_column(String(64), default="")
    filter_expr: Mapped[str] = mapped_column(String(256), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    pcap_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    store_in_db: Mapped[bool] = mapped_column(Boolean, default=False)

    packets: Mapped[list["Packet"]] = relationship("Packet", back_populates="capture", cascade="all, delete-orphan")


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="UDP")
    length: Mapped[int] = mapped_column(Integer, default=0)
    payload_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    capture: Mapped["Capture"] = relationship("Capture", back_populates="packets")
