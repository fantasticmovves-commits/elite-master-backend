import os
import re
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from authlib import get_current_user
from database import db
from security import approve_baseline, record_event, run_scan, scan_upload_content
from storage import APP_NAME, put_object

logger = logging.getLogger(__name__)

admin_router = APIRouter(prefix="/api/admin", dependencies=[Depends(get_current_user)])

SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(/[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


async def verify_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    allowed = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
    if allowed and "*" not in allowed and origin not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden origin")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def normalize_seo(seo):
    """Accept legacy field-keyed seo {title: {ua,ru}, description: {ua,ru}} and return lang-keyed seo."""
    if not isinstance(seo, dict):
        return {}
    if "ua" in seo or "ru" in seo:
        return {"ua": seo.get("ua", {}), "ru": seo.get("ru", {})}
    title = seo.get("title") or {}
    desc = seo.get("description") or {}
    if isinstance(title, dict) or isinstance(desc, dict):
        return {
            "ua": {"title": title.get("ua", ""), "description": desc.get("ua", "")},
            "ru": {"title": title.get("ru", ""), "description": desc.get("ru", "")},
        }
    return seo


# ---------- Pages ----------

class PageModel(BaseModel):
    slug: str
    title: Dict[str, str] = Field(default_factory=dict)
    navLabel: Dict[str, str] = Field(default_factory=dict)
    inNav: bool = False
    order: int = 0
    published: bool = True
    seo: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    blocks: List[dict] = Field(default_factory=list)


@admin_router.get("/pages")
async def admin_list_pages():
    docs = await db.pages.find({}, {"_id": 0}).sort([("order", 1), ("title", 1)]).to_list(500)
    for d in docs:
        d["seo"] = normalize_seo(d.get("seo"))
    return docs


@admin_router.get("/pages/{page_id}")
async def admin_get_page(page_id: str):
    doc = await db.pages.find_one({"id": page_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Сторінку не знайдено")
    doc["seo"] = normalize_seo(doc.get("seo"))
    return doc


@admin_router.post("/pages")
async def admin_create_page(page: PageModel):
    slug = page.slug.strip("/").lower()
    if not re.match(SLUG_RE, slug):
        raise HTTPException(status_code=400, detail="Некоректний URL (slug)")
    if await db.pages.find_one({"slug": slug}):
        raise HTTPException(status_code=400, detail="Сторінка з таким URL вже існує")
    doc = {**page.model_dump(), "slug": slug, "id": str(uuid.uuid4()), "created_at": _now(), "updated_at": _now()}
    await db.pages.insert_one(doc)
    return _clean(doc)


@admin_router.put("/pages/{page_id}")
async def admin_update_page(page_id: str, page: PageModel):
    slug = page.slug.strip("/").lower()
    if not re.match(SLUG_RE, slug):
        raise HTTPException(status_code=400, detail="Некоректний URL (slug)")
    existing = await db.pages.find_one({"id": page_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Сторінку не знайдено")
    if slug != existing["slug"] and await db.pages.find_one({"slug": slug}):
        raise HTTPException(status_code=400, detail="Сторінка з таким URL вже існує")
    doc = {**page.model_dump(), "slug": slug, "updated_at": _now()}
    await db.pages.update_one({"id": page_id}, {"$set": doc})
    return {"ok": True}


@admin_router.delete("/pages/{page_id}")
async def admin_delete_page(page_id: str):
    res = await db.pages.delete_one({"id": page_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Сторінку не знайдено")
    return {"ok": True}


# ---------- Settings ----------

class SettingsModel(BaseModel):
    brand: Dict[str, str] = Field(default_factory=dict)
    tagline: Dict[str, str] = Field(default_factory=dict)
    phones: List[str] = Field(default_factory=list)
    email: str = ""
    support_email: str = ""
    notify_email: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    theme_mode: str = "summer"
    admin_bg: str = "light"
    address: Dict[str, str] = Field(default_factory=dict)
    hours: Dict[str, str] = Field(default_factory=dict)
    viber: str = ""
    telegram: str = ""


@admin_router.get("/settings")
async def admin_get_settings():
    doc = await db.settings.find_one({"_key": "site"}, {"_id": 0})
    return doc or {}


@admin_router.put("/settings")
async def admin_update_settings(settings: SettingsModel):
    await db.settings.update_one(
        {"_key": "site"},
        {"$set": {**settings.model_dump(), "updated_at": _now()}},
        upsert=True,
    )
    return {"ok": True}


# ---------- Leads ----------

@admin_router.get("/leads")
async def admin_list_leads(status: Optional[str] = None):
    q = {"status": status} if status in ("new", "done") else {}
    docs = await db.leads.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


class LeadStatus(BaseModel):
    status: str


@admin_router.put("/leads/{lead_id}")
async def admin_update_lead(lead_id: str, payload: LeadStatus):
    if payload.status not in ("new", "done"):
        raise HTTPException(status_code=400, detail="Невірний статус")
    res = await db.leads.update_one({"id": lead_id}, {"$set": {"status": payload.status}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Заявку не знайдено")
    return {"ok": True}


@admin_router.delete("/leads/{lead_id}")
async def admin_delete_lead(lead_id: str):
    res = await db.leads.delete_one({"id": lead_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Заявку не знайдено")
    return {"ok": True}


# ---------- Media ----------

ALLOWED_IMAGE_EXT = ("jpg", "jpeg", "png", "webp", "gif", "svg", "avif")


@admin_router.post("/upload")
async def admin_upload(file: UploadFile = File(...)):
    filename = file.filename or "image"
    ext = (filename.split(".")[-1] if "." in filename else "").lower()
    if ext not in ALLOWED_IMAGE_EXT:
        raise HTTPException(status_code=400, detail="Дозволені лише зображення (jpg, png, webp, gif, svg, avif)")
    data = await file.read()
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Максимальний розмір файлу — 8 МБ")
    ok, reason = scan_upload_content(ext, data)
    if not ok:
        await record_event(db, kind="blocked_upload", path=filename, detail=reason, severity="high")
        raise HTTPException(status_code=400, detail=f"Файл відхилено системою безпеки: {reason}")
    path = f"{APP_NAME}/uploads/{uuid.uuid4()}.{ext}"
    result = put_object(path, data, file.content_type or "application/octet-stream")
    rec = {
        "id": str(uuid.uuid4()),
        "storage_path": result.get("path", path),
        "original_filename": filename,
        "content_type": file.content_type or "application/octet-stream",
        "size": result.get("size", len(data)),
        "is_deleted": False,
        "created_at": _now(),
    }
    await db.media.insert_one(rec)
    return {"id": rec["id"], "url": f"/api/media/file/{rec['id']}"}


@admin_router.get("/media")
async def admin_list_media():
    docs = await db.media.find({"is_deleted": False}, {"_id": 0}).sort("created_at", -1).to_list(300)
    return docs


@admin_router.delete("/media/{media_id}")
async def admin_delete_media(media_id: str):
    res = await db.media.update_one({"id": media_id}, {"$set": {"is_deleted": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Файл не знайдено")
    return {"ok": True}


# ---------- Blog ----------

class PostModel(BaseModel):
    slug: str
    title: Dict[str, str] = Field(default_factory=dict)
    excerpt: Dict[str, str] = Field(default_factory=dict)
    body: Dict[str, str] = Field(default_factory=dict)
    image: str = ""
    published: bool = True
    seo: Dict[str, Dict[str, str]] = Field(default_factory=dict)


@admin_router.get("/posts")
async def admin_list_posts():
    docs = await db.posts.find({}, {"_id": 0}).sort("created_at", -1).to_list(300)
    return docs


@admin_router.get("/posts/{post_id}")
async def admin_get_post(post_id: str):
    doc = await db.posts.find_one({"id": post_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Статтю не знайдено")
    return doc


@admin_router.post("/posts")
async def admin_create_post(post: PostModel):
    slug = post.slug.strip("/").lower()
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", slug):
        raise HTTPException(status_code=400, detail="Некоректний URL (slug)")
    if await db.posts.find_one({"slug": slug}):
        raise HTTPException(status_code=400, detail="Стаття з таким URL вже існує")
    doc = {**post.model_dump(), "slug": slug, "id": str(uuid.uuid4()), "created_at": _now(), "updated_at": _now()}
    await db.posts.insert_one(doc)
    return _clean(doc)


@admin_router.put("/posts/{post_id}")
async def admin_update_post(post_id: str, post: PostModel):
    slug = post.slug.strip("/").lower()
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", slug):
        raise HTTPException(status_code=400, detail="Некоректний URL (slug)")
    existing = await db.posts.find_one({"id": post_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Статтю не знайдено")
    if slug != existing["slug"] and await db.posts.find_one({"slug": slug}):
        raise HTTPException(status_code=400, detail="Стаття з таким URL вже існує")
    await db.posts.update_one({"id": post_id}, {"$set": {**post.model_dump(), "slug": slug, "updated_at": _now()}})
    return {"ok": True}


@admin_router.delete("/posts/{post_id}")
async def admin_delete_post(post_id: str):
    res = await db.posts.delete_one({"id": post_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Статтю не знайдено")
    return {"ok": True}


# ---------- Review submissions ----------

@admin_router.get("/review-submissions")
async def admin_list_review_submissions():
    docs = await db.review_submissions.find({}, {"_id": 0}).sort("created_at", -1).to_list(300)
    return docs


@admin_router.post("/review-submissions/{sub_id}/publish")
async def admin_publish_review(sub_id: str):
    sub = await db.review_submissions.find_one({"id": sub_id})
    if not sub:
        raise HTTPException(status_code=404, detail="Відгук не знайдено")
    page = await db.pages.find_one({"slug": "reviews"})
    if not page:
        raise HTTPException(status_code=404, detail="Сторінку /reviews не знайдено")
    item = {
        "name": sub.get("name", ""),
        "meta": datetime.now(timezone.utc).strftime("%d.%m.%Y"),
        "text": {"ua": sub.get("text", ""), "ru": sub.get("text", "")},
    }
    if sub.get("rating"):
        item["rating"] = sub["rating"]
    updated = False
    for block in page.get("blocks", []):
        if block.get("type") == "reviews":
            block.setdefault("items", []).append(item)
            updated = True
    if not updated:
        page.setdefault("blocks", []).append({"id": str(uuid.uuid4()), "type": "reviews", "title": {"ua": "Відгуки клієнтів", "ru": "Отзывы клиентов"}, "items": [item]})
    await db.pages.update_one({"slug": "reviews"}, {"$set": {"blocks": page["blocks"], "updated_at": _now()}})
    await db.review_submissions.update_one({"id": sub_id}, {"$set": {"status": "published"}})
    return {"ok": True}


@admin_router.delete("/review-submissions/{sub_id}")
async def admin_delete_review_submission(sub_id: str):
    res = await db.review_submissions.delete_one({"id": sub_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Відгук не знайдено")
    return {"ok": True}


# ---------- Security ----------

KIND_LABELS = {
    "new_file": "Новий файл",
    "changed_file": "Змінений файл",
    "deleted_file": "Видалений файл",
    "malware_pattern": "Підозрілий код",
    "blocked_upload": "Заблоковане завантаження",
}


@admin_router.get("/security/status")
async def security_status():
    meta = await db.security_meta.find_one({"_key": "scan"}, {"_id": 0}) or {}
    open_events = await db.security_events.count_documents({"resolved": False})
    high_open = await db.security_events.count_documents({"resolved": False, "severity": "high"})
    by_kind_raw = await db.security_events.aggregate(
        [{"$match": {"resolved": False}}, {"$group": {"_id": "$kind", "count": {"$sum": 1}}}]
    ).to_list(20)
    return {
        "last_scan": meta.get("last_scan"),
        "files_count": meta.get("files_count", 0),
        "open_events": open_events,
        "high_open": high_open,
        "by_kind": {row["_id"]: row["count"] for row in by_kind_raw},
    }


@admin_router.get("/security/events")
async def security_events():
    docs = await db.security_events.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    for d in docs:
        d["kind_label"] = KIND_LABELS.get(d.get("kind"), d.get("kind"))
    return docs


@admin_router.post("/security/scan")
async def security_scan_now():
    return await run_scan(db, trigger="manual")


@admin_router.post("/security/approve")
async def security_approve():
    return await approve_baseline(db)


@admin_router.post("/security/events/{event_id}/resolve")
async def security_resolve_event(event_id: str):
    event = await db.security_events.find_one({"id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Подію не знайдено")
    now = _now()
    if event["kind"] == "malware_pattern":
        await db.security_allow.update_one(
            {"path": event["path"], "detail": event["detail"]},
            {"$set": {"path": event["path"], "detail": event["detail"], "created_at": now}},
            upsert=True,
        )
    elif event["kind"] in ("new_file", "changed_file"):
        import security as sec

        full = os.path.join(sec.APP_ROOT, event["path"])
        if os.path.isfile(full):
            await db.security_baseline.update_one(
                {"path": event["path"]},
                {"$set": {"path": event["path"], "sha256": sec._sha256(full), "size": os.path.getsize(full), "scanned_at": now}},
                upsert=True,
            )
    elif event["kind"] == "deleted_file":
        await db.security_baseline.delete_one({"path": event["path"]})
    await db.security_events.update_one({"id": event_id}, {"$set": {"resolved": True, "resolved_at": now}})
    return {"ok": True}


# ---------- Analytics ----------

@admin_router.get("/analytics/overview")
async def analytics_overview():
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    week_start = (now - timedelta(days=7)).isoformat()
    month_start = (now - timedelta(days=30)).isoformat()
    online_threshold = (now - timedelta(minutes=3)).isoformat()

    total = await db.analytics_sessions.count_documents({})
    today = await db.analytics_sessions.count_documents({"started_at": {"$gte": today_start}})
    week = await db.analytics_sessions.count_documents({"started_at": {"$gte": week_start}})
    online = await db.analytics_sessions.count_documents({"last_seen": {"$gte": online_threshold}})

    agg = await db.analytics_sessions.aggregate(
        [{"$match": {"started_at": {"$gte": month_start}}}, {"$group": {"_id": None, "avg": {"$avg": "$duration_sec"}, "pages": {"$sum": {"$size": {"$ifNull": ["$pages", []]}}}}}]
    ).to_list(1)
    avg_duration = round(agg[0]["avg"]) if agg and agg[0].get("avg") else 0
    pageviews = agg[0]["pages"] if agg else 0

    top_pages_raw = await db.analytics_sessions.aggregate(
        [
            {"$match": {"started_at": {"$gte": month_start}}},
            {"$unwind": "$pages"},
            {"$group": {"_id": "$pages.path", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 8},
        ]
    ).to_list(8)

    return {
        "total": total,
        "today": today,
        "week": week,
        "online": online,
        "avg_duration": avg_duration,
        "pageviews_month": pageviews,
        "top_pages": [{"path": r["_id"], "count": r["count"]} for r in top_pages_raw],
    }


@admin_router.get("/analytics/visitors")
async def analytics_visitors():
    docs = await db.analytics_sessions.find(
        {},
        {"_id": 0, "id": 1, "ip": 1, "device": 1, "started_at": 1, "last_seen": 1, "duration_sec": 1, "pages": 1, "lang": 1},
    ).sort("last_seen", -1).to_list(100)
    for d in docs:
        d["pages_count"] = len(d.get("pages") or [])
    return docs


@admin_router.get("/analytics/visitors/{sid}")
async def analytics_visitor_detail(sid: str):
    doc = await db.analytics_sessions.find_one({"id": sid}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Сесію не знайдено")
    return doc


VALID_TILE_KEYS = {"leads", "analytics", "pages", "blog", "media", "security", "settings"}


class TileOrderModel(BaseModel):
    order: List[str] = Field(default_factory=list)


@admin_router.patch("/settings/tile-order")
async def settings_tile_order(payload: TileOrderModel):
    order = [k for k in payload.order if k in VALID_TILE_KEYS]
    await db.settings.update_one({"_key": "site"}, {"$set": {"admin_tile_order": order}}, upsert=True)
    return {"ok": True, "admin_tile_order": order}
