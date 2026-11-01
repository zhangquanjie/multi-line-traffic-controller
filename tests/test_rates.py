"""Verify receive/transmit rate calculation from SNMP counter deltas."""
import asyncio
import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()
db_path = Path(tmp.name)
os.environ["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import Base, SessionLocal, engine, utcnow  # noqa: E402
from app.models import Firewall, Line  # noqa: E402
import app.services as services  # noqa: E402


async def fake_counters(_cfg, _if_index):
    return 1_001_000, 2_002_000, 1, 1


try:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        firewall = Firewall(name="FW", snmp_host="10.0.0.1", snmp_version="v2c",
                            snmp_community="public")
        db.add(firewall); db.flush()
        line = Line(name="L", firewall_id=firewall.id, interface="GigabitEthernet 1/0/1.1",
                    if_index=1, quota_gb=100, billing_day=1,
                    last_in_counter=1000, last_out_counter=2000,
                    last_polled_at=utcnow() - timedelta(seconds=10))
        db.add(line); db.commit(); db.refresh(line)
        original = services.snmp_counters
        services.snmp_counters = fake_counters
        try:
            result = asyncio.run(services.poll_line(db, line))
        finally:
            services.snmp_counters = original
        assert 0.79 < result["rx_mbps"] < 0.81
        assert 1.59 < result["tx_mbps"] < 1.61
        assert result["status"] == "up"
        line.snmp_admin_status, line.snmp_oper_status = 2, 2
        assert services.line_view(db, line)["status"] == "admin_down"
        line.snmp_admin_status, line.snmp_oper_status = 1, 2
        assert services.line_view(db, line)["status"] == "link_down"
    print("real-time rate calculation test passed")
finally:
    engine.dispose()
    db_path.unlink(missing_ok=True)
