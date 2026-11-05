"""Verify billing boundaries and the inclusive range displayed in the UI."""
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import set_app_timezone, to_local  # noqa: E402
from app.services import cycle_bounds, cycle_display_dates  # noqa: E402


set_app_timezone("Asia/Shanghai")

# The internal end is exclusive: 12 December 00:00 starts the next cycle.
start, end = cycle_bounds(12, datetime(2026, 11, 20, 4, 0, 0))
assert to_local(start).strftime("%Y-%m-%d %H:%M:%S") == "2026-11-12 00:00:00"
assert to_local(end).strftime("%Y-%m-%d %H:%M:%S") == "2026-12-12 00:00:00"
assert cycle_display_dates(start, end) == ("2026-11-12", "2026-12-11")

# At the exact boundary, the new cycle is shown as 12 December to 11 January.
start, end = cycle_bounds(12, datetime(2026, 12, 11, 16, 0, 0))
assert cycle_display_dates(start, end) == ("2026-12-12", "2027-01-11")

print("billing cycle display test passed")
