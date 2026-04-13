"""
Timezone utility — all timestamps in Asia/Kolkata (IST, UTC+5:30)
"""
from datetime import datetime
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


def now_ist() -> datetime:
    """Return current datetime in IST (timezone-aware)."""
    return datetime.now(IST)
