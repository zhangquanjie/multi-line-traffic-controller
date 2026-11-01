import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./traffic.db")
try:
    APP_TIMEZONE = ZoneInfo(os.getenv("TZ", "Asia/Shanghai"))
except Exception:
    APP_TIMEZONE = ZoneInfo("UTC")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def set_app_timezone(name: str) -> None:
    global APP_TIMEZONE
    APP_TIMEZONE = ZoneInfo(name)


def local_now() -> datetime:
    return datetime.now(APP_TIMEZONE)


def to_local(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    source = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return source.astimezone(APP_TIMEZONE)


def local_time_text(value: datetime | None) -> str | None:
    converted = to_local(value)
    return converted.strftime("%Y/%m/%d %H:%M:%S") if converted else None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


