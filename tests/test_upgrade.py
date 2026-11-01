"""Regression check for upgrading a deployed single-firewall SQLite database."""
import os
import sqlite3
import sys
import tempfile
from pathlib import Path


tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()
db_path = Path(tmp.name)
connection = sqlite3.connect(db_path)
connection.executescript("""
CREATE TABLE system_settings (
 id INTEGER PRIMARY KEY, firewall_host VARCHAR(255) NOT NULL, firewall_port INTEGER NOT NULL,
 firewall_username VARCHAR(128) NOT NULL, firewall_password TEXT NOT NULL,
 snmp_host VARCHAR(255) NOT NULL, snmp_port INTEGER NOT NULL, snmp_version VARCHAR(16) NOT NULL,
 snmp_community TEXT NOT NULL, snmp_v3_username VARCHAR(128) NOT NULL,
 snmp_v3_security_level VARCHAR(32) NOT NULL, snmp_v3_auth_protocol VARCHAR(16) NOT NULL,
 snmp_v3_auth_password TEXT NOT NULL, snmp_v3_priv_protocol VARCHAR(16) NOT NULL,
 snmp_v3_priv_password TEXT NOT NULL, snmp_v3_context VARCHAR(128) NOT NULL,
 poll_seconds INTEGER NOT NULL, dry_run BOOLEAN NOT NULL, updated_at DATETIME NOT NULL
);
INSERT INTO system_settings VALUES
 (1,'10.1.1.1',22,'admin','ssh','10.1.1.1',161,'v3','','snmp','authPriv','SHA',
  'auth','AES','priv','',300,1,'2026-10-31 10:00:00');
CREATE TABLE lines (
 id INTEGER PRIMARY KEY, name VARCHAR(128) NOT NULL UNIQUE,
 interface VARCHAR(128) NOT NULL UNIQUE, if_index INTEGER NOT NULL,
 quota_gb FLOAT NOT NULL, billing_day INTEGER NOT NULL, enabled BOOLEAN NOT NULL,
 auto_shutdown BOOLEAN NOT NULL, status VARCHAR(32) NOT NULL,
 last_in_counter INTEGER, last_out_counter INTEGER, last_polled_at DATETIME,
 created_at DATETIME NOT NULL
);
INSERT INTO lines VALUES
 (1,'Existing','GigabitEthernet 1/0/1.100',100,100,1,1,1,'active',NULL,NULL,NULL,
  '2026-10-31 10:00:00');
CREATE TABLE readings (
 id INTEGER PRIMARY KEY, line_id INTEGER NOT NULL REFERENCES lines(id),
 recorded_at DATETIME NOT NULL, bytes_delta INTEGER NOT NULL,
 in_counter INTEGER NOT NULL, out_counter INTEGER NOT NULL, source VARCHAR(32) NOT NULL
);
INSERT INTO readings VALUES (1,1,'2026-10-31 10:01:00',1234,1000,234,'snmp');
""")
connection.commit()
connection.close()

os.environ["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Firewall, Line, Reading  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

try:
    with TestClient(app):
        with SessionLocal() as session:
            firewall = session.query(Firewall).one()
            line = session.query(Line).one()
            assert firewall.snmp_host == "10.1.1.1"
            assert line.firewall_id == firewall.id
            assert line.rx_bps == 0 and line.tx_bps == 0
            assert line.snmp_admin_status is None and line.snmp_oper_status is None
            assert session.query(Reading).one().bytes_delta == 1234
    print("legacy database migration test passed")
finally:
    engine.dispose()
    db_path.unlink(missing_ok=True)

