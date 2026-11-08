import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, APIRouter, BackgroundTasks, HTTPException, Request, Response
from pydantic import BaseModel, Field
from starlette.middleware.cors import CORSMiddleware
from typing import Optional

from admin_routes import admin_router, normalize_seo
from analytics import client_ip, is_bot, track_beat, track_pageview
from authlib import (
    get_current_user,
    seed_admin,
    set_auth_cookies,
    verify_password,
)
from database import db
from emailer import lead_notification_html, send_email
from seed_data import ensure_seed
from seed_posts import ensure_posts_seed
from storage import get_object, init_storage
from telegram import lead_telegram_text, send_telegram

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# CORS: explicit frontend origins (wildcard is incompatible with credentials)
_origins = [o.strip() for o in os.environ.get('CORS_ORIGINS', '').split(',') if o.strip() and o.strip() != '*']
if not _origins:
    _origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


# ---------- Public: pages & settings ----------

@api_router.get("/")
async def root():
    return {"message": "Elite Master API"}


@api_router.get("/pages")
async def list_pages():
    docs = await db.pages.find({"published": True}, {"_id": 0}).sort("order", 1).to_list(500)
    return [
        {k: p[k] for k in ("slug", "title", "navLabel", "inNav", "order") if k in p}
        for p in docs
    ]


@api_router.get("/pages/by-slug/{slug:path}")
async def get_page(slug: str):
    slug = slug.strip("/")
    page = await db.pages.find_one({"slug": slug, "published": True}, {"_id": 0})
    if not page:
        raise HTTPException(status_code=404, detail="Сторінку не знайдено")
    page["seo"] = normalize_seo(page.get("seo"))
    return page


@api_router.get("/settings")
async def get_settings():
    doc = await db.settings.find_one(
        {"_key": "site"},
        {"_id": 0, "notify_email": 0, "telegram_bot_token": 0, "telegram_chat_id": 0},
    )
    return doc or {}


# ---------- Public: sitemap ----------

@api_router.get("/sitemap.xml")
async def sitemap(request: Request):
    pages = await db.pages.find({"published": True}, {"_id": 0, "slug": 1, "updated_at": 1}).to_list(500)
    posts = await db.posts.find({"published": True}, {"_id": 0, "slug": 1, "updated_at": 1}).to_list(500)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    proto = request.headers.get("x-forwarded-proto") or "https"
    base = f"{proto}://{host}".rstrip("/")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    urls = []
    for p in pages:
        loc = base + ("/" if p["slug"] == "home" else f"/{p['slug']}")
        lastmod = str(p.get("updated_at", ""))[:10] or today
        urls.append(f"  <url><loc>{loc}</loc><lastmod>{lastmod}</lastmod></url>")
    urls.append(f"  <url><loc>{base}/blog</loc><lastmod>{today}</lastmod></url>")
    for p in posts:
        lastmod = str(p.get("updated_at", ""))[:10] or today
        urls.append(f"  <url><loc>{base}/blog/{p['slug']}</loc><lastmod>{lastmod}</lastmod></url>")
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    xml += "\n".join(urls) + "\n</urlset>\n"
    return Response(content=xml, media_type="application/xml")


# ---------- Public: blog ----------

@api_router.get("/blog")
async def list_blog():
    docs = await db.posts.find(
        {"published": True},
        {"_id": 0, "id": 1, "slug": 1, "title": 1, "excerpt": 1, "image": 1, "created_at": 1},
    ).sort("created_at", -1).to_list(300)
    return docs


@api_router.get("/blog/{slug}")
async def get_blog_post(slug: str):
    slug = slug.strip("/")
    post = await db.posts.find_one({"slug": slug, "published": True}, {"_id": 0})
    if not post:
        raise HTTPException(status_code=404, detail="Статтю не знайдено")
    return post


# ---------- Public: leads ----------

class LeadCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = Field(min_length=7, max_length=30)
    appliance: Optional[str] = ""
    message: Optional[str] = ""


async def notify_new_lead(lead: dict):
    settings = await db.settings.find_one({"_key": "site"}) or {}
    to = settings.get("notify_email")
    if to:
        try:
            await send_email(to=to, subject="Нова заявка з сайту Elite Master", html=lead_notification_html(lead))
            logger.info(f"Lead email sent for lead {lead.get('id')}")
        except Exception as e:
            logger.warning(f"Lead email failed: {e}")
    tg_token = settings.get("telegram_bot_token")
    tg_chat = settings.get("telegram_chat_id")
    if tg_token and tg_chat:
        result = await send_telegram(tg_token, tg_chat, lead_telegram_text(lead))
        if result and result.get("ok"):
            logger.info(f"Lead telegram sent for lead {lead.get('id')}")


@api_router.post("/leads")
async def create_lead(payload: LeadCreate, background_tasks: BackgroundTasks):
    lead = {
        "id": str(uuid.uuid4()),
        **payload.model_dump(),
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.leads.insert_one(lead)
    background_tasks.add_task(notify_new_lead, lead)
    return {"ok": True}


# ---------- Public: reviews ----------

class ReviewCreate(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    text: str = Field(min_length=10, max_length=1000)
    rating: Optional[int] = None


async def notify_new_review(review: dict):
    try:
        settings = await db.settings.find_one({"_key": "site"})
        to = (settings or {}).get("notify_email")
        if not to:
            return
        from emailer import review_notification_html

        await send_email(to=to, subject="Новий відгук на сайті Elite Master", html=review_notification_html(review))
        logger.info(f"Review email sent for review {review.get('id')}")
    except Exception as e:
        logger.warning(f"Review email failed: {e}")


@api_router.post("/reviews")
async def create_review(payload: ReviewCreate, background_tasks: BackgroundTasks):
    if payload.rating is not None and not 1 <= payload.rating <= 5:
        raise HTTPException(status_code=400, detail="Оцінка має бути від 1 до 5")
    review = {
        "id": str(uuid.uuid4()),
        **payload.model_dump(),
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.review_submissions.insert_one(review)
    background_tasks.add_task(notify_new_review, review)
    return {"ok": True}


# ---------- Admin: telegram test ----------

@api_router.post("/admin/telegram-test")
async def telegram_test(user: dict = Depends(get_current_user)):
    settings = await db.settings.find_one({"_key": "site"}) or {}
    token = settings.get("telegram_bot_token")
    chat_id = settings.get("telegram_chat_id")
    if not token or not chat_id:
        raise HTTPException(status_code=400, detail="Спочатку вкажіть токен бота та chat ID у налаштуваннях")
    result = await send_telegram(token, chat_id, "✅ Тестове повідомлення Elite Master — Telegram-сповіщення працюють.")
    if not result or not result.get("ok"):
        raise HTTPException(status_code=502, detail="Telegram не прийняв повідомлення. Перевірте токен бота та chat ID")
    return {"ok": True}


# ---------- Public: visitor analytics ----------

class TrackPageview(BaseModel):
    sid: str = Field(min_length=8, max_length=64)
    path: str = Field(min_length=1, max_length=200)
    lang: Optional[str] = ""


class TrackBeat(BaseModel):
    sid: str = Field(min_length=8, max_length=64)
    seconds: int = Field(default=0, ge=0)


@api_router.post("/track/pageview")
async def track_pageview_ep(payload: TrackPageview, request: Request, background_tasks: BackgroundTasks):
    if not payload.path.startswith("/") or payload.path.startswith("/admin"):
        return {"ok": True}
    ua = request.headers.get("user-agent", "")
    if is_bot(ua):
        return {"ok": True}
    background_tasks.add_task(
        track_pageview, db, sid=payload.sid, path=payload.path, ip=client_ip(request), ua=ua, lang=payload.lang or ""
    )
    return {"ok": True}


@api_router.post("/track/beat")
async def track_beat_ep(payload: TrackBeat, request: Request, background_tasks: BackgroundTasks):
    ua = request.headers.get("user-agent", "")
    if is_bot(ua):
        return {"ok": True}
    background_tasks.add_task(track_beat, db, sid=payload.sid, seconds=payload.seconds)
    return {"ok": True}


# ---------- Public: media ----------

@api_router.get("/media/file/{media_id}")
async def media_file(media_id: str):
    rec = await db.media.find_one({"id": media_id, "is_deleted": False})
    if not rec:
        raise HTTPException(status_code=404, detail="Файл не знайдено")
    try:
        data, content_type = get_object(rec["storage_path"])
    except Exception as e:
        logger.error(f"Media fetch failed: {e}")
        raise HTTPException(status_code=404, detail="Файл недоступний")
    return Response(
        content=data,
        media_type=rec.get("content_type") or content_type,
        headers={"Cache-Control": "public, max-age=31536000"},
    )


# ---------- Auth ----------

class LoginReq(BaseModel):
    email: str
    password: str


@api_router.post("/auth/login")
async def login(payload: LoginReq, request: Request, response: Response):
    email = payload.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    ident = f"{ip}:{email}"
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"identifier": ident})
    if attempt and attempt.get("locked_until"):
        locked_until = datetime.fromisoformat(attempt["locked_until"])
        if locked_until > now:
            raise HTTPException(status_code=429, detail="Забагато спроб. Спробуйте за 15 хвилин")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        fails = 1
        if attempt:
            fails = attempt.get("fails", 0) + 1
        update = {"$inc": {"fails": 1}, "$set": {"updated_at": now.isoformat()}}
        if fails >= 5:
            update["$set"]["locked_until"] = (now + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": ident}, update, upsert=True)
        raise HTTPException(status_code=401, detail="Невірний email або пароль")

    await db.login_attempts.delete_many({"identifier": ident})
    set_auth_cookies(response, user.get("id") or str(user["_id"]), user["email"])
    return {"id": user.get("id"), "email": user["email"], "name": user.get("name", ""), "role": user.get("role", "")}


@api_router.post("/auth/logout")
async def logout(response: Response, user: dict = Depends(get_current_user)):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api_router.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="Не авторизовано")
    import jwt as pyjwt

    try:
        payload = pyjwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Недійсний токен")
    except Exception:
        raise HTTPException(status_code=401, detail="Недійсний токен")
    user = await db.users.find_one({"id": payload.get("sub")})
    if not user:
        raise HTTPException(status_code=401, detail="Користувача не знайдено")
    set_auth_cookies(response, user.get("id") or str(user["_id"]), user["email"])
    return {"id": user.get("id"), "email": user["email"], "name": user.get("name", ""), "role": user.get("role", "")}


app.include_router(api_router)
app.include_router(admin_router)


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")
    await db.security_events.create_index("resolved")
    await db.security_events.create_index("created_at")
    await db.analytics_sessions.create_index("id", unique=True)
    await db.analytics_sessions.create_index("last_seen")
    await seed_admin(db)
    await ensure_seed(db)
    await ensure_posts_seed(db)
    try:
        init_storage()
        logger.info("Storage initialized")
    except Exception as e:
        logger.error(f"Storage init failed: {e}")
    import asyncio

    async def _bg_scan():
        try:
            from security import run_scan

            summary = await run_scan(db, trigger="startup")
            logger.info(f"Security scan at startup: {summary}")
        except Exception as e:
            logger.error(f"Startup security scan failed: {e}")

    asyncio.create_task(_bg_scan())


@app.on_event("shutdown")
async def shutdown_db_client():
    from database import client

    client.close()
