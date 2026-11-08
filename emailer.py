import ipaddress
import logging
import os
import re
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import HTTPException

load_dotenv()
logger = logging.getLogger(__name__)

# Emergent managed email proxy. Constant — never read from environment.
EMAIL_BASE_URL = "https://integrations.emergentagent.com"
EMAIL_KEY = os.environ["EMERGENT_EMAIL_KEY"]
EMAIL_FROM_NAME = os.environ["EMAIL_FROM_NAME"]
EMAIL_REPLY_TO = os.environ.get("EMAIL_REPLY_TO")

_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)


class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan()
    scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks the recipient for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links/assets must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Shortened, numeric-host or credential-bearing URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text {m.group(1)!r} != real link host {real!r} (G3)")


async def send_email(*, to: str, subject: str, html: str, reply_to: str | None = None) -> str | None:
    _assert_safe_email(subject, html)
    payload = {"to": [to], "subject": subject, "html": html, "from_name": EMAIL_FROM_NAME}
    if reply_to or EMAIL_REPLY_TO:
        payload["contact_email"] = reply_to or EMAIL_REPLY_TO
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{EMAIL_BASE_URL}/api/v1/email/send",
                headers={"X-Email-Key": EMAIL_KEY},
                json=payload,
            )
        resp.raise_for_status()
        return resp.json().get("id")
    except httpx.HTTPStatusError as e:
        try:
            code = e.response.json().get("code", "")
        except ValueError:
            code = ""
        if code in ("insufficient_credits", "integration_disabled", "daily_limit_reached"):
            logger.warning(f"Email paused: {code} ({e.response.status_code}): {e.response.json().get('message', '')}")
            raise HTTPException(status_code=503, detail="Email is temporarily unavailable")
        logger.error(f"Email send failed: {e.response.status_code} {e.response.text}")
        raise HTTPException(status_code=502, detail="Failed to send email")
    except Exception as e:
        logger.error(f"Email send error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send email")


def lead_notification_html(lead: dict) -> str:
    rows = [
        ("Ім'я", lead.get("name", "")),
        ("Телефон", lead.get("phone", "")),
        ("Техніка", lead.get("appliance", "") or "—"),
        ("Проблема", lead.get("message", "") or "—"),
    ]
    cells = "".join(
        f'<tr><td style="padding:8px 16px 8px 0;color:#5C5D60;font-size:14px">{escape(label)}</td>'
        f'<td style="padding:8px 0;color:#1C1D20;font-size:14px;font-weight:600">{escape(value)}</td></tr>'
        for label, value in rows
    )
    return (
        '<table role="presentation" width="100%" style="background:#F9F8F6;padding:24px">'
        '<tr><td><table role="presentation" width="560" style="background:#ffffff;border-radius:12px;padding:32px">'
        f'<tr><td style="font-family:Arial,sans-serif;font-size:18px;font-weight:700;color:#1C1D20;padding-bottom:16px">'
        f'Нова заявка — {escape(EMAIL_FROM_NAME)}</td></tr>'
        f'<tr><td><table role="presentation" style="font-family:Arial,sans-serif">{cells}</table></td></tr>'
        f'<tr><td style="font-family:Arial,sans-serif;font-size:12px;color:#8A8B8D;padding-top:24px">'
        f'Заявку також збережено в адмін-панелі сайту. Лист надіслано сервісом {escape(EMAIL_FROM_NAME)}.</td></tr>'
        '</table></td></tr></table>'
    )


def review_notification_html(review: dict) -> str:
    rating = review.get("rating")
    rating_row = ""
    if rating:
        rating_row = (
            f'<tr><td style="padding:8px 16px 8px 0;color:#5C5D60;font-size:14px">Оцінка</td>'
            f'<td style="padding:8px 0;color:#1C1D20;font-size:14px;font-weight:600">{int(rating)} з 5</td></tr>'
        )
    return (
        '<table role="presentation" width="100%" style="background:#F9F8F6;padding:24px">'
        '<tr><td><table role="presentation" width="560" style="background:#ffffff;border-radius:12px;padding:32px">'
        f'<tr><td style="font-family:Arial,sans-serif;font-size:18px;font-weight:700;color:#1C1D20;padding-bottom:16px">'
        f'Новий відгук — {escape(EMAIL_FROM_NAME)}</td></tr>'
        f'<tr><td><table role="presentation" style="font-family:Arial,sans-serif">'
        f'<tr><td style="padding:8px 16px 8px 0;color:#5C5D60;font-size:14px">Ім\'я</td>'
        f'<td style="padding:8px 0;color:#1C1D20;font-size:14px;font-weight:600">{escape(review.get("name", ""))}</td></tr>'
        f'{rating_row}'
        f'<tr><td style="padding:8px 16px 8px 0;color:#5C5D60;font-size:14px;vertical-align:top">Відгук</td>'
        f'<td style="padding:8px 0;color:#1C1D20;font-size:14px">{escape(review.get("text", ""))}</td></tr>'
        f'</table></td></tr>'
        f'<tr><td style="font-family:Arial,sans-serif;font-size:12px;color:#8A8B8D;padding-top:24px">'
        f'Відгук чекає на модерацію в адмін-панелі (розділ «Заявки» → «Відгуки»). Лист надіслано сервісом {escape(EMAIL_FROM_NAME)}.</td></tr>'
        '</table></td></tr></table>'
    )
