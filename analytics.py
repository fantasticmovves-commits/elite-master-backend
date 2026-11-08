import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

BOT_RE = re.compile(r"bot|spider|crawler|slurp|bingpreview|facebookexternal|whatsapp|telegrambot|pingdom|uptime", re.I)
MAX_PAGES_PER_SESSION = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def client_ip(request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_bot(ua: str) -> bool:
    return bool(BOT_RE.search(ua or ""))


def parse_device(ua: str) -> dict:
    ua = ua or ""
    low = ua.lower()
    if "ipad" in low or "tablet" in low:
        dtype = "tablet"
    elif "mobile" in low or "iphone" in low or "android" in low:
        dtype = "mobile"
    else:
        dtype = "desktop"

    if "windows" in low:
        os_name = "Windows"
    elif "android" in low:
        os_name = "Android"
    elif "iphone" in low or "ipad" in low:
        os_name = "iOS"
    elif "mac os" in low or "macintosh" in low:
        os_name = "macOS"
    elif "linux" in low:
        os_name = "Linux"
    else:
        os_name = "інша ОС"

    if "edg/" in low or "edge" in low:
        browser = "Edge"
    elif "opr/" in low or "opera" in low:
        browser = "Opera"
    elif "chrome" in low and "chromium" not in low:
        browser = "Chrome"
    elif "safari" in low and "chrome" not in low:
        browser = "Safari"
    elif "firefox" in low:
        browser = "Firefox"
    else:
        browser = "інший"

    return {"type": dtype, "os": os_name, "browser": browser}


async def track_pageview(db, *, sid: str, path: str, ip: str, ua: str, lang: str = "") -> None:
    now = _now()
    update = {
        "$setOnInsert": {
            "id": sid,
            "ip": ip,
            "ua": ua[:300],
            "device": parse_device(ua),
            "started_at": now,
            "duration_sec": 0,
            "lang": lang,
        },
        "$set": {"last_seen": now},
        "$push": {"pages": {"$each": [{"path": path[:200], "at": now}], "$slice": -MAX_PAGES_PER_SESSION}},
    }
    await db.analytics_sessions.update_one({"id": sid}, update, upsert=True)


async def track_beat(db, *, sid: str, seconds: int) -> None:
    await db.analytics_sessions.update_one(
        {"id": sid},
        {"$set": {"last_seen": _now()}, "$max": {"duration_sec": max(0, min(seconds, 24 * 3600))}},
    )
