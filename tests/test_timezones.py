from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db import local_time_text, set_app_timezone  # noqa: E402

set_app_timezone("Asia/Shanghai")
assert local_time_text(datetime(2026, 10, 31, 1, 22, 39)) == "2026/10/31 09:22:39"
set_app_timezone("Asia/Dushanbe")
assert local_time_text(datetime(2026, 10, 31, 1, 22, 39)) == "2026/10/31 06:22:39"
print("web timezone conversion test passed")
