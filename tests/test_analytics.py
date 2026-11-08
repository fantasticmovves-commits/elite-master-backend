"""Visitor analytics API tests."""
import os
import time
import pytest
import requests
from pymongo import MongoClient

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://domtech-repair.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@elite-master.org.ua"
ADMIN_PASSWORD = "EliteMaster2026!"
QA_SID = "qa-visitor-0001"
QA_SID2 = "qa-visitor-bot-0001"

IPHONE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@pytest.fixture(scope="module")
def admin_session():
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return s


@pytest.fixture(scope="module", autouse=True)
def cleanup():
    yield
    try:
        client = MongoClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
        db_name = os.environ.get("DB_NAME", "test_database")
        client[db_name].analytics_sessions.delete_many({"id": {"$in": [QA_SID, QA_SID2]}})
    except Exception as e:
        print(f"cleanup error: {e}")


def test_pageview_validation_short_sid():
    r = requests.post(f"{BASE_URL}/api/track/pageview", json={"sid": "short", "path": "/"})
    assert r.status_code == 422


def test_admin_overview_requires_auth():
    r = requests.get(f"{BASE_URL}/api/admin/analytics/overview")
    assert r.status_code == 401


def test_admin_visitors_requires_auth():
    r = requests.get(f"{BASE_URL}/api/admin/analytics/visitors")
    assert r.status_code == 401


def test_pageview_and_beat_flow(admin_session):
    # Simulate iPhone visitor via X-Forwarded-For
    headers = {
        "User-Agent": IPHONE_UA,
        "X-Forwarded-For": "176.38.20.15",
    }
    for path in ["/", "/reviews", "/remont/refrigerator-kiev"]:
        r = requests.post(f"{BASE_URL}/api/track/pageview",
                          json={"sid": QA_SID, "path": path, "lang": "ru"}, headers=headers)
        assert r.status_code == 200, r.text
    r = requests.post(f"{BASE_URL}/api/track/beat",
                      json={"sid": QA_SID, "seconds": 45}, headers=headers)
    assert r.status_code == 200
    time.sleep(1.5)  # background tasks

    # Fetch visitor detail
    r = admin_session.get(f"{BASE_URL}/api/admin/analytics/visitors/{QA_SID}")
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["ip"] == "176.38.20.15"
    assert v["device"]["type"] == "mobile"
    assert v["device"]["os"] == "iOS"
    assert v["device"]["browser"] == "Safari"
    assert v["duration_sec"] == 45
    assert v["lang"] == "ru"
    paths = [p["path"] for p in v.get("pages", [])]
    assert paths == ["/", "/reviews", "/remont/refrigerator-kiev"]

    # Visitors list includes our SID
    r = admin_session.get(f"{BASE_URL}/api/admin/analytics/visitors")
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert QA_SID in ids


def test_admin_tracking_ignored():
    headers = {"User-Agent": IPHONE_UA, "X-Forwarded-For": "176.38.20.15"}
    r = requests.post(f"{BASE_URL}/api/track/pageview",
                      json={"sid": QA_SID, "path": "/admin/pages"}, headers=headers)
    assert r.status_code == 200
    time.sleep(1)
    # verify /admin not added to pages
    from pymongo import MongoClient
    client = MongoClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    db_name = os.environ.get("DB_NAME", "test_database")
    doc = client[db_name].analytics_sessions.find_one({"id": QA_SID})
    assert doc is not None
    assert not any(p["path"].startswith("/admin") for p in doc.get("pages", []))


def test_bot_ignored(admin_session):
    headers = {"User-Agent": BOT_UA, "X-Forwarded-For": "66.249.66.1"}
    r = requests.post(f"{BASE_URL}/api/track/pageview",
                      json={"sid": QA_SID2, "path": "/"}, headers=headers)
    assert r.status_code == 200
    time.sleep(1)
    r = admin_session.get(f"{BASE_URL}/api/admin/analytics/visitors/{QA_SID2}")
    assert r.status_code == 404


def test_overview_has_data(admin_session):
    r = admin_session.get(f"{BASE_URL}/api/admin/analytics/overview")
    assert r.status_code == 200
    data = r.json()
    for k in ["online", "today", "week", "avg_duration", "top_pages"]:
        assert k in data
    assert data["today"] >= 1
