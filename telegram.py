import logging
from html import escape

import httpx

logger = logging.getLogger(__name__)


def lead_telegram_text(lead: dict) -> str:
    lines = [
        "<b>Нова заявка — Elite Master</b>",
        "",
        f"Ім'я: {escape(lead.get('name', ''))}",
        f"Телефон: {escape(lead.get('phone', ''))}",
    ]
    if lead.get("appliance"):
        lines.append(f"Техніка: {escape(lead['appliance'])}")
    if lead.get("message"):
        lines.append(f"Проблема: {escape(lead['message'])}")
    return "\n".join(lines)


async def send_telegram(bot_token: str, chat_id: str, text: str):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )
        data = resp.json()
        if not data.get("ok"):
            logger.warning(f"Telegram rejected message: {data.get('description')}")
        return data
    except Exception as e:
        logger.warning(f"Telegram send failed: {e}")
        return None
