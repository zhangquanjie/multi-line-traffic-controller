import os
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow


class SystemSetting(Base):
    __tablename__ = "system_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    firewall_host: Mapped[str] = mapped_column(String(255), default="")
    firewall_port: Mapped[int] = mapped_column(Integer, default=22)
    firewall_username: Mapped[str] = mapped_column(String(128), default="")
    firewall_password: Mapped[str] = mapped_column(Text, default="")
    snmp_host: Mapped[str] = mapped_column(String(255), default="")
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)
    snmp_version: Mapped[str] = mapped_column(String(16), default="v2c")
    snmp_community: Mapped[str] = mapped_column(Text, default="public")
    snmp_v3_username: Mapped[str] = mapped_column(String(128), default="")
    snmp_v3_security_level: Mapped[str] = mapped_column(String(32), default="authPriv")
    snmp_v3_auth_protocol: Mapped[str] = mapped_column(String(16), default="SHA")
    snmp_v3_auth_password: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_priv_protocol: Mapped[str] = mapped_column(String(16), default="AES")
    snmp_v3_priv_password: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_context: Mapped[str] = mapped_column(String(128), default="")
    poll_seconds: Mapped[int] = mapped_column(Integer, default=300)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    timezone: Mapped[str] = mapped_column(String(64), default=lambda: os.getenv("TZ", "Asia/Shanghai"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Firewall(Base):
    __tablename__ = "firewalls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    firewall_host: Mapped[str] = mapped_column(String(255), default="")
    firewall_port: Mapped[int] = mapped_column(Integer, default=22)
    firewall_username: Mapped[str] = mapped_column(String(128), default="")
    firewall_password: Mapped[str] = mapped_column(Text, default="")
    snmp_host: Mapped[str] = mapped_column(String(255), default="")
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)
    snmp_version: Mapped[str] = mapped_column(String(16), default="v3")
    snmp_community: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_username: Mapped[str] = mapped_column(String(128), default="")
    snmp_v3_security_level: Mapped[str] = mapped_column(String(32), default="authPriv")
    snmp_v3_auth_protocol: Mapped[str] = mapped_column(String(16), default="SHA")
    snmp_v3_auth_password: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_priv_protocol: Mapped[str] = mapped_column(String(16), default="AES")
    snmp_v3_priv_password: Mapped[str] = mapped_column(Text, default="")
    snmp_v3_context: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    lines: Mapped[list["Line"]] = relationship(back_populates="firewall")


class Line(Base):
    __tablename__ = "lines"
    __table_args__ = (UniqueConstraint("firewall_id", "interface", name="uq_firewall_interface"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    firewall_id: Mapped[int | None] = mapped_column(ForeignKey("firewalls.id"), nullable=True, index=True)
    interface: Mapped[str] = mapped_column(String(128))
    if_index: Mapped[int] = mapped_column(Integer)
    quota_gb: Mapped[float] = mapped_column(Float)
    billing_day: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_shutdown: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    last_in_counter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_out_counter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rx_bps: Mapped[float] = mapped_column(Float, default=0)
    tx_bps: Mapped[float] = mapped_column(Float, default=0)
    snmp_admin_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snmp_oper_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    firewall: Mapped[Firewall | None] = relationship(back_populates="lines")
    readings: Mapped[list["Reading"]] = relationship(back_populates="line", cascade="all, delete-orphan")
    adjustments: Mapped[list["Adjustment"]] = relationship(back_populates="line", cascade="all, delete-orphan")


class Reading(Base):
    __tablename__ = "readings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    line_id: Mapped[int] = mapped_column(ForeignKey("lines.id"), index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    bytes_delta: Mapped[int] = mapped_column(Integer, default=0)
    in_counter: Mapped[int] = mapped_column(Integer)
    out_counter: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), default="snmp")
    line: Mapped[Line] = relationship(back_populates="readings")


class Adjustment(Base):
    __tablename__ = "adjustments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    line_id: Mapped[int] = mapped_column(ForeignKey("lines.id"), index=True)
    effective_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    target_total_bytes: Mapped[int] = mapped_column(Integer)
    measured_total_bytes: Mapped[int] = mapped_column(Integer)
    delta_bytes: Mapped[int] = mapped_column(Integer)
    note: Mapped[str] = mapped_column(String(500), default="")
    line: Mapped[Line] = relationship(back_populates="adjustments")


class ActionLog(Base):
    __tablename__ = "action_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    line_id: Mapped[int | None] = mapped_column(ForeignKey("lines.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    action: Mapped[str] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str] = mapped_column(Text, default="")

