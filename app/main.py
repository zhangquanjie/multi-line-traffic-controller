import asyncio
import base64
import hmac
import os
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import (Base, SessionLocal, engine, get_db, local_now,
                 local_time_text, set_app_timezone, utcnow)
from .models import ActionLog, Adjustment, Firewall, Line, SystemSetting
from .schemas import AdjustmentIn, CycleIn, FirewallIn, LineIn, SettingsIn
from .services import (cycle_bounds, line_view, measured_bytes, poll_all, poll_line,
                       set_interface_state, setting, usage_bytes)


async def scheduler(stop: asyncio.Event):
    while not stop.is_set():
        with next(get_db()) as db:
            seconds = setting(db).poll_seconds
        try:
            await asyncio.wait_for(stop.wait(), timeout=max(30, seconds))
        except asyncio.TimeoutError:
            await poll_all()


def migrate_schema():
    """Upgrade older SQLite databases without discarding collected traffic."""
    columns = {x["name"] for x in inspect(engine).get_columns("system_settings")}
    additions = {
        "snmp_version": "VARCHAR(16) NOT NULL DEFAULT 'v2c'",
        "snmp_v3_username": "VARCHAR(128) NOT NULL DEFAULT ''",
        "snmp_v3_security_level": "VARCHAR(32) NOT NULL DEFAULT 'authPriv'",
        "snmp_v3_auth_protocol": "VARCHAR(16) NOT NULL DEFAULT 'SHA'",
        "snmp_v3_auth_password": "TEXT NOT NULL DEFAULT ''",
        "snmp_v3_priv_protocol": "VARCHAR(16) NOT NULL DEFAULT 'AES'",
        "snmp_v3_priv_password": "TEXT NOT NULL DEFAULT ''",
        "snmp_v3_context": "VARCHAR(128) NOT NULL DEFAULT ''",
        "timezone": "VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai'",
    }
    missing = [(name, definition) for name, definition in additions.items() if name not in columns]
    if missing:
        with engine.begin() as connection:
            for name, definition in missing:
                connection.exec_driver_sql(f"ALTER TABLE system_settings ADD COLUMN {name} {definition}")
    line_columns = {x["name"] for x in inspect(engine).get_columns("lines")}
    line_additions = {
        "firewall_id": "INTEGER REFERENCES firewalls(id)",
        "rx_bps": "FLOAT NOT NULL DEFAULT 0",
        "tx_bps": "FLOAT NOT NULL DEFAULT 0",
        "snmp_admin_status": "INTEGER",
        "snmp_oper_status": "INTEGER",
    }
    with engine.begin() as connection:
        for name, definition in line_additions.items():
            if name not in line_columns:
                connection.exec_driver_sql(f"ALTER TABLE lines ADD COLUMN {name} {definition}")
    # The original release made interface names globally unique. Rebuild only that
    # legacy SQLite table so two firewalls may both have GigabitEthernet 1/0/1.
    legacy_unique = any(set(item.get("column_names") or []) == {"interface"}
                        for item in inspect(engine).get_unique_constraints("lines"))
    if engine.dialect.name == "sqlite" and legacy_unique:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.exec_driver_sql("""CREATE TABLE lines_v2 (
                id INTEGER NOT NULL PRIMARY KEY,
                name VARCHAR(128) NOT NULL UNIQUE,
                firewall_id INTEGER REFERENCES firewalls(id),
                interface VARCHAR(128) NOT NULL,
                if_index INTEGER NOT NULL,
                quota_gb FLOAT NOT NULL,
                billing_day INTEGER NOT NULL,
                enabled BOOLEAN NOT NULL,
                auto_shutdown BOOLEAN NOT NULL,
                status VARCHAR(32) NOT NULL,
                last_in_counter INTEGER,
                last_out_counter INTEGER,
                last_polled_at DATETIME,
                rx_bps FLOAT NOT NULL DEFAULT 0,
                tx_bps FLOAT NOT NULL DEFAULT 0,
                snmp_admin_status INTEGER,
                snmp_oper_status INTEGER,
                created_at DATETIME NOT NULL,
                CONSTRAINT uq_firewall_interface UNIQUE (firewall_id, interface)
            )""")
            connection.exec_driver_sql("""INSERT INTO lines_v2
                (id,name,firewall_id,interface,if_index,quota_gb,billing_day,enabled,
                 auto_shutdown,status,last_in_counter,last_out_counter,last_polled_at,
                 rx_bps,tx_bps,snmp_admin_status,snmp_oper_status,created_at)
                SELECT id,name,firewall_id,interface,if_index,quota_gb,billing_day,enabled,
                 auto_shutdown,status,last_in_counter,last_out_counter,last_polled_at,
                 rx_bps,tx_bps,snmp_admin_status,snmp_oper_status,created_at FROM lines""")
            connection.exec_driver_sql("DROP TABLE lines")
            connection.exec_driver_sql("ALTER TABLE lines_v2 RENAME TO lines")
            connection.exec_driver_sql("CREATE INDEX ix_lines_firewall_id ON lines (firewall_id)")
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def migrate_default_firewall():
    """Move the former single-device settings into the first managed firewall."""
    with SessionLocal() as db:
        device = db.scalar(select(Firewall).order_by(Firewall.id).limit(1))
        if not device:
            old = setting(db)
            device = Firewall(
                name="默认防火墙", firewall_host=old.firewall_host,
                firewall_port=old.firewall_port, firewall_username=old.firewall_username,
                firewall_password=old.firewall_password, snmp_host=old.snmp_host,
                snmp_port=old.snmp_port, snmp_version=old.snmp_version,
                snmp_community=old.snmp_community, snmp_v3_username=old.snmp_v3_username,
                snmp_v3_security_level=old.snmp_v3_security_level,
                snmp_v3_auth_protocol=old.snmp_v3_auth_protocol,
                snmp_v3_auth_password=old.snmp_v3_auth_password,
                snmp_v3_priv_protocol=old.snmp_v3_priv_protocol,
                snmp_v3_priv_password=old.snmp_v3_priv_password,
                snmp_v3_context=old.snmp_v3_context,
            )
            db.add(device); db.flush()
        for line in db.scalars(select(Line).where(Line.firewall_id.is_(None))).all():
            line.firewall_id = device.id
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    migrate_schema()
    with SessionLocal() as db:
        set_app_timezone(setting(db).timezone)
    migrate_default_firewall()
    with next(get_db()) as db:
        cfg = setting(db)
        if os.getenv("POLL_SECONDS") and cfg.poll_seconds == 300:
            cfg.poll_seconds = max(30, int(os.environ["POLL_SECONDS"])); db.commit()
    stop = asyncio.Event(); task = asyncio.create_task(scheduler(stop))
    yield
    stop.set(); task.cancel()
    with suppress(asyncio.CancelledError): await task


app = FastAPI(title="多线路流量限额控制器", version="2.0.0", lifespan=lifespan)
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def basic_auth(request, call_next):
    if request.url.path == "/api/health":
        return await call_next(request)
    expected_user = os.getenv("ADMIN_USERNAME", "admin")
    expected_password = os.getenv("ADMIN_PASSWORD", "change-me-now")
    supplied = request.headers.get("Authorization", "")
    valid = False
    if supplied.startswith("Basic "):
        try:
            user, password = base64.b64decode(supplied[6:]).decode().split(":", 1)
            valid = hmac.compare_digest(user, expected_user) and hmac.compare_digest(password, expected_password)
        except (ValueError, UnicodeDecodeError):
            pass
    if not valid:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "需要登录"}, status_code=401,
                            headers={"WWW-Authenticate": 'Basic realm="Traffic Controller"'})
    return await call_next(request)


@app.get("/")
def index(): return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health(): return {"ok": True, "time": utcnow().isoformat()}


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)):
    lines = db.scalars(select(Line).order_by(Line.id)).all()
    cfg = setting(db)
    return {"lines": [line_view(db, x) for x in lines], "dry_run": cfg.dry_run,
            "poll_seconds": cfg.poll_seconds}


@app.post("/api/lines")
def create_line(payload: LineIn, db: Session = Depends(get_db)):
    if not db.get(Firewall, payload.firewall_id): raise HTTPException(400, "所选防火墙不存在")
    row = Line(**payload.model_dump())
    db.add(row)
    try: db.commit(); db.refresh(row)
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "线路名称或接口已存在")
    return line_view(db, row)


@app.put("/api/lines/{line_id}")
def update_line(line_id: int, payload: LineIn, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    if not db.get(Firewall, payload.firewall_id): raise HTTPException(400, "所选防火墙不存在")
    for k, v in payload.model_dump().items(): setattr(row, k, v)
    try: db.commit(); db.refresh(row)
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "线路名称或接口已存在")
    return line_view(db, row)


@app.delete("/api/lines/{line_id}")
def delete_line(line_id: int, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    db.delete(row); db.commit(); return {"ok": True}


@app.post("/api/lines/{line_id}/poll")
async def manual_poll(line_id: int, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    try: return await poll_line(db, row)
    except Exception as exc: raise HTTPException(502, f"采集失败：{exc}")


@app.post("/api/poll")
async def manual_poll_all():
    await poll_all(); return {"ok": True}


@app.post("/api/lines/{line_id}/adjust")
def adjust(line_id: int, payload: AdjustmentIn, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    now = utcnow(); start, end = cycle_bounds(row.billing_day, now)
    measured = measured_bytes(db, row, start, end)
    target = int(payload.total_gb * 1_000_000_000)
    db.add(Adjustment(line_id=row.id, effective_at=now, target_total_bytes=target,
                      measured_total_bytes=measured, delta_bytes=target - measured, note=payload.note))
    db.add(ActionLog(line_id=row.id, action="adjust", success=True,
                     message=f"人工校准为 {payload.total_gb:.3f} GB；{payload.note}"))
    db.commit(); return line_view(db, row)


@app.post("/api/lines/{line_id}/cycle")
def set_cycle(line_id: int, payload: CycleIn, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    row.billing_day = payload.billing_day
    db.add(ActionLog(line_id=row.id, action="cycle_change", success=True,
                     message=f"计费起始日改为每月 {payload.billing_day} 日"))
    db.commit(); return line_view(db, row)


@app.post("/api/lines/{line_id}/shutdown")
async def shutdown(line_id: int, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    try: await set_interface_state(db, row, True, "人工关停")
    except Exception as exc: raise HTTPException(502, f"SSH 执行失败：{exc}")
    return line_view(db, row)


@app.post("/api/lines/{line_id}/restore")
async def restore(line_id: int, db: Session = Depends(get_db)):
    row = db.get(Line, line_id)
    if not row: raise HTTPException(404, "线路不存在")
    try: await set_interface_state(db, row, False, "人工恢复")
    except Exception as exc: raise HTTPException(502, f"SSH 执行失败：{exc}")
    return line_view(db, row)


@app.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    x = setting(db)
    return {"poll_seconds": x.poll_seconds, "dry_run": x.dry_run,
            "timezone": x.timezone,
            "current_time": local_now().strftime("%Y/%m/%d %H:%M:%S")}


@app.put("/api/settings")
def save_settings(payload: SettingsIn, db: Session = Depends(get_db)):
    x = setting(db)
    x.poll_seconds = payload.poll_seconds; x.dry_run = payload.dry_run
    x.timezone = payload.timezone
    set_app_timezone(payload.timezone)
    db.commit(); return get_settings(db)


def firewall_view(x: Firewall):
    return {"id": x.id, "name": x.name, "firewall_host": x.firewall_host,
            "firewall_port": x.firewall_port, "firewall_username": x.firewall_username,
            "firewall_password": "", "snmp_host": x.snmp_host, "snmp_port": x.snmp_port,
            "snmp_version": x.snmp_version, "snmp_community": "",
            "snmp_v3_username": x.snmp_v3_username,
            "snmp_v3_security_level": x.snmp_v3_security_level,
            "snmp_v3_auth_protocol": x.snmp_v3_auth_protocol, "snmp_v3_auth_password": "",
            "snmp_v3_priv_protocol": x.snmp_v3_priv_protocol, "snmp_v3_priv_password": "",
            "snmp_v3_context": x.snmp_v3_context,
            "has_firewall_password": bool(x.firewall_password),
            "has_snmp_community": bool(x.snmp_community),
            "has_snmp_v3_auth_password": bool(x.snmp_v3_auth_password),
            "has_snmp_v3_priv_password": bool(x.snmp_v3_priv_password),
            "line_count": len(x.lines)}


@app.get("/api/firewalls")
def list_firewalls(db: Session = Depends(get_db)):
    return [firewall_view(x) for x in db.scalars(select(Firewall).order_by(Firewall.id)).all()]


@app.post("/api/firewalls")
def create_firewall(payload: FirewallIn, db: Session = Depends(get_db)):
    row = Firewall(**payload.model_dump())
    db.add(row)
    try: db.commit(); db.refresh(row)
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "防火墙名称已存在")
    return firewall_view(row)


@app.put("/api/firewalls/{firewall_id}")
def update_firewall(firewall_id: int, payload: FirewallIn, db: Session = Depends(get_db)):
    row = db.get(Firewall, firewall_id)
    if not row: raise HTTPException(404, "防火墙不存在")
    data = payload.model_dump()
    for secret in ("firewall_password", "snmp_community", "snmp_v3_auth_password", "snmp_v3_priv_password"):
        if not data[secret]: data.pop(secret)
    for key, value in data.items(): setattr(row, key, value)
    try: db.commit(); db.refresh(row)
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "防火墙名称已存在")
    return firewall_view(row)


@app.delete("/api/firewalls/{firewall_id}")
def delete_firewall(firewall_id: int, db: Session = Depends(get_db)):
    row = db.get(Firewall, firewall_id)
    if not row: raise HTTPException(404, "防火墙不存在")
    if row.lines: raise HTTPException(409, "该设备仍有关联线路，请先移动或删除线路")
    db.delete(row); db.commit(); return {"ok": True}


@app.get("/api/logs")
def logs(limit: int = 100, db: Session = Depends(get_db)):
    rows = db.scalars(select(ActionLog).order_by(ActionLog.id.desc()).limit(min(500, limit))).all()
    names = {x.id: x.name for x in db.scalars(select(Line)).all()}
    return [{"id": x.id, "line": names.get(x.line_id, "系统"), "created_at": x.created_at.isoformat(),
             "created_at_display": local_time_text(x.created_at),
             "action": x.action, "success": x.success, "message": x.message} for x in rows]


