import asyncio
import calendar
import re
import time
from datetime import datetime, timezone
from typing import Any

import paramiko
from pysnmp.hlapi.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
    UdpTransportTarget, UsmUserData, get_cmd, usmAesCfb128Protocol,
    usmAesCfb192Protocol, usmAesCfb256Protocol, usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import SessionLocal, local_time_text, to_local, utcnow
from .models import ActionLog, Adjustment, Firewall, Line, Reading, SystemSetting

OCTETS_64_IN = "1.3.6.1.2.1.31.1.1.1.6"
OCTETS_64_OUT = "1.3.6.1.2.1.31.1.1.1.10"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*\s*[0-9/]+(?:\.[0-9]+)?$")


def setting(db: Session) -> SystemSetting:
    row = db.get(SystemSetting, 1)
    if not row:
        row = SystemSetting(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def cycle_bounds(billing_day: int, now: datetime | None = None) -> tuple[datetime, datetime]:
    local = to_local(now or utcnow())
    assert local is not None
    this_day = min(billing_day, calendar.monthrange(local.year, local.month)[1])
    this_start = datetime(local.year, local.month, this_day, tzinfo=local.tzinfo)
    if local >= this_start:
        start_local = this_start
        y, m = (local.year + 1, 1) if local.month == 12 else (local.year, local.month + 1)
    else:
        y0, m0 = (local.year - 1, 12) if local.month == 1 else (local.year, local.month - 1)
        start_local = datetime(y0, m0, min(billing_day, calendar.monthrange(y0, m0)[1]), tzinfo=local.tzinfo)
        y, m = local.year, local.month
    end_local = datetime(y, m, min(billing_day, calendar.monthrange(y, m)[1]), tzinfo=local.tzinfo)
    start = start_local.astimezone(timezone.utc).replace(tzinfo=None)
    end = end_local.astimezone(timezone.utc).replace(tzinfo=None)
    return start, end


def measured_bytes(db: Session, line: Line, start: datetime, end: datetime) -> int:
    value = db.scalar(select(func.coalesce(func.sum(Reading.bytes_delta), 0)).where(
        Reading.line_id == line.id, Reading.recorded_at >= start, Reading.recorded_at < end
    ))
    return int(value or 0)


def usage_bytes(db: Session, line: Line, now: datetime | None = None) -> int:
    start, end = cycle_bounds(line.billing_day, now)
    measured = measured_bytes(db, line, start, end)
    latest = db.scalar(select(Adjustment).where(
        Adjustment.line_id == line.id,
        Adjustment.effective_at >= start,
        Adjustment.effective_at < end,
    ).order_by(Adjustment.effective_at.desc(), Adjustment.id.desc()).limit(1))
    if not latest:
        return max(0, measured)
    since = db.scalar(select(func.coalesce(func.sum(Reading.bytes_delta), 0)).where(
        Reading.line_id == line.id,
        Reading.recorded_at > latest.effective_at,
        Reading.recorded_at < end,
    ))
    return max(0, int(latest.target_total_bytes + int(since or 0)))


def line_view(db: Session, line: Line) -> dict[str, Any]:
    start, end = cycle_bounds(line.billing_day)
    used = usage_bytes(db, line)
    quota = int(line.quota_gb * 1_000_000_000)
    if line.snmp_admin_status is None or line.snmp_oper_status is None:
        actual_status = "unknown"
    elif line.snmp_admin_status == 2:
        actual_status = "admin_down"
    elif line.snmp_oper_status == 1:
        actual_status = "up"
    else:
        actual_status = "link_down"
    start_local, end_local = to_local(start), to_local(end)
    return {
        "id": line.id, "name": line.name, "interface": line.interface,
        "firewall_id": line.firewall_id,
        "firewall_name": line.firewall.name if line.firewall else "未分配设备",
        "if_index": line.if_index, "quota_gb": line.quota_gb,
        "billing_day": line.billing_day, "enabled": line.enabled,
        "auto_shutdown": line.auto_shutdown, "status": actual_status,
        "control_status": line.status,
        "snmp_admin_status": line.snmp_admin_status,
        "snmp_oper_status": line.snmp_oper_status,
        "used_gb": round(used / 1_000_000_000, 3),
        "remaining_gb": round(max(0, quota - used) / 1_000_000_000, 3),
        "percent": round((used / quota * 100) if quota else 0, 2),
        "rx_mbps": round((line.rx_bps or 0) / 1_000_000, 3),
        "tx_mbps": round((line.tx_bps or 0) / 1_000_000, 3),
        "total_mbps": round(((line.rx_bps or 0) + (line.tx_bps or 0)) / 1_000_000, 3),
        "cycle_start": start_local.date().isoformat(), "cycle_end": end_local.date().isoformat(),
        "last_polled_at": line.last_polled_at.isoformat() if line.last_polled_at else None,
        "last_polled_display": local_time_text(line.last_polled_at),
    }


AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol, "SHA512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol, "AES": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol, "AES256": usmAesCfb256Protocol,
}


def snmp_credentials(cfg: Firewall | SystemSetting):
    if cfg.snmp_version == "v2c":
        if not cfg.snmp_community:
            raise RuntimeError("SNMP v2c Community 未配置")
        return CommunityData(cfg.snmp_community, mpModel=1)
    if not cfg.snmp_v3_username:
        raise RuntimeError("SNMP v3 用户名未配置")
    level = cfg.snmp_v3_security_level
    if level in ("authNoPriv", "authPriv") and not cfg.snmp_v3_auth_password:
        raise RuntimeError("SNMP v3 认证密码未配置")
    if level == "authPriv" and not cfg.snmp_v3_priv_password:
        raise RuntimeError("SNMP v3 加密密码未配置")
    auth_key = cfg.snmp_v3_auth_password if level != "noAuthNoPriv" else None
    priv_key = cfg.snmp_v3_priv_password if level == "authPriv" else None
    auth_protocol = AUTH_PROTOCOLS[cfg.snmp_v3_auth_protocol] if auth_key else usmNoAuthProtocol
    priv_protocol = PRIV_PROTOCOLS[cfg.snmp_v3_priv_protocol] if priv_key else usmNoPrivProtocol
    return UsmUserData(cfg.snmp_v3_username, authKey=auth_key, privKey=priv_key,
                       authProtocol=auth_protocol, privProtocol=priv_protocol)


async def snmp_counters(cfg: Firewall | SystemSetting, if_index: int) -> tuple[int, int, int, int]:
    target = await UdpTransportTarget.create((cfg.snmp_host, cfg.snmp_port), timeout=3, retries=1)
    engine = SnmpEngine()
    try:
        result = await get_cmd(
            engine, snmp_credentials(cfg), target, ContextData(contextName=cfg.snmp_v3_context or ""),
            ObjectType(ObjectIdentity(f"{OCTETS_64_IN}.{if_index}")),
            ObjectType(ObjectIdentity(f"{OCTETS_64_OUT}.{if_index}")),
            ObjectType(ObjectIdentity(f"{IF_ADMIN_STATUS}.{if_index}")),
            ObjectType(ObjectIdentity(f"{IF_OPER_STATUS}.{if_index}")),
        )
    finally:
        # A new engine owns an asyncio transport dispatcher. Not closing it leaks
        # callbacks and sockets on every poll and eventually stalls the web process.
        engine.close_dispatcher()
    error_indication, error_status, error_index, var_binds = result
    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        raise RuntimeError(f"{error_status.prettyPrint()} at {error_index}")
    values = [int(v) for _, v in var_binds]
    return values[0], values[1], values[2], values[3]


def _ssh_commands(cfg: dict, interface: str, shutdown: bool) -> str:
    if not INTERFACE_RE.fullmatch(interface):
        raise ValueError("接口名称格式不安全")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(cfg["host"], port=cfg["port"], username=cfg["username"],
                   password=cfg["password"], timeout=10, auth_timeout=10,
                   banner_timeout=10, look_for_keys=False, allow_agent=False)
    channel = client.invoke_shell(width=160, height=48)
    channel.settimeout(5)
    commands = ["system-view", f"interface {interface}", "shutdown" if shutdown else "undo shutdown", "return"]
    output = ""
    try:
        time.sleep(0.5)
        if channel.recv_ready(): output += channel.recv(65535).decode("utf-8", "ignore")
        for command in commands:
            channel.send(command + "\n")
            time.sleep(0.6)
            while channel.recv_ready(): output += channel.recv(65535).decode("utf-8", "ignore")
    finally:
        channel.close(); client.close()
    return output[-4000:]


async def set_interface_state(db: Session, line: Line, shutdown: bool, reason: str) -> None:
    global_cfg = setting(db)
    cfg = line.firewall
    action = "shutdown" if shutdown else "undo_shutdown"
    if global_cfg.dry_run:
        line.status = "simulated_shutdown" if shutdown else "active"
        db.add(ActionLog(line_id=line.id, action=action, success=True, message=f"模拟执行：{reason}"))
        db.commit(); return
    if not cfg or not cfg.firewall_host or not cfg.firewall_username:
        raise RuntimeError("防火墙 SSH 配置不完整")
    try:
        output = await asyncio.to_thread(_ssh_commands, {
            "host": cfg.firewall_host, "port": cfg.firewall_port,
            "username": cfg.firewall_username, "password": cfg.firewall_password,
        }, line.interface, shutdown)
        line.status = "shutdown" if shutdown else "active"
        db.add(ActionLog(line_id=line.id, action=action, success=True, message=f"{reason}\n{output}"))
        db.commit()
    except Exception as exc:
        db.rollback()
        db.add(ActionLog(line_id=line.id, action=action, success=False, message=f"{reason}: {exc}"))
        db.commit()
        raise


async def poll_line(db: Session, line: Line) -> dict[str, Any]:
    cfg = line.firewall
    if not cfg or not cfg.snmp_host:
        raise RuntimeError("SNMP 主机未配置")
    in_count, out_count, admin_status, oper_status = await snmp_counters(cfg, line.if_index)
    in_delta = out_delta = 0
    now = utcnow()
    if line.last_in_counter is not None and line.last_out_counter is not None:
        # 64-bit counters normally do not wrap in practice. A smaller value indicates device reboot/counter reset.
        in_delta = max(0, in_count - line.last_in_counter)
        out_delta = max(0, out_count - line.last_out_counter)
        elapsed = max(0.001, (now - line.last_polled_at).total_seconds()) if line.last_polled_at else 0
        line.rx_bps = in_delta * 8 / elapsed if elapsed else 0
        line.tx_bps = out_delta * 8 / elapsed if elapsed else 0
    else:
        line.rx_bps = line.tx_bps = 0
    delta = in_delta + out_delta
    line.last_in_counter, line.last_out_counter, line.last_polled_at = in_count, out_count, now
    line.snmp_admin_status, line.snmp_oper_status = admin_status, oper_status
    db.add(Reading(line_id=line.id, recorded_at=now, bytes_delta=delta,
                   in_counter=in_count, out_counter=out_count))
    db.commit(); db.refresh(line)
    used = usage_bytes(db, line, now)
    quota = int(line.quota_gb * 1_000_000_000)
    if line.auto_shutdown and line.status not in ("shutdown", "simulated_shutdown") and used >= quota:
        await set_interface_state(db, line, True, f"流量达到限额：{used / 1e9:.3f} GB / {line.quota_gb:.3f} GB")
    return line_view(db, line)


async def poll_all() -> None:
    with SessionLocal() as db:
        lines = db.scalars(select(Line).where(Line.enabled.is_(True))).all()
        for line in lines:
            try:
                await poll_line(db, line)
            except Exception as exc:
                db.rollback()
                db.add(ActionLog(line_id=line.id, action="poll", success=False, message=str(exc)))
                db.commit()

