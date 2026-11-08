import hashlib
import html as html_mod
import logging
import os
import re
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(BACKEND_DIR)

WATCH_DIRS = [
    (BACKEND_DIR, {".py"}),
    (os.path.join(APP_ROOT, "frontend", "src"), {".js", ".jsx", ".ts", ".tsx", ".css", ".html"}),
    (os.path.join(APP_ROOT, "frontend", "public"), None),
]
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "build", "dist", ".next", ".emergent"}
SKIP_FILES = {".env", "yarn.lock", "package-lock.json"}
PATTERN_SKIP_PATHS = {os.path.join("backend", "security.py")}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".css", ".html", ".txt", ".json", ".svg", ".md"}
MAX_PATTERN_FILE_SIZE = 2 * 1024 * 1024

SUSPICIOUS_PATTERNS = [
    (re.compile(r"<\?php"), "PHP-код у файлі сайту (типовий бекдор)", "high"),
    (re.compile(r"base64_decode\s*\("), "base64_decode — типовий прийом приховування бекдорів", "high"),
    (re.compile(r"\beval\s*\("), "Виконання довільного коду — eval()", "high"),
    (re.compile(r"new\s+Function\s*\("), "Динамічне створення функції — new Function()", "high"),
    (re.compile(r"\b(os\.system|shell_exec|passthru)\s*\("), "Запуск системних команд", "high"),
    (re.compile(r"\bsubprocess\b"), "Запуск системних процесів (subprocess)", "high"),
    (re.compile(r"\bchild_process\b"), "Запуск системних процесів (child_process)", "high"),
    (re.compile(r"\bexec\s*\("), "Виконання довільного коду — exec()", "high"),
    (re.compile(r"\b(wget|curl)\s+http"), "Завантаження зовнішнього коду з мережі", "high"),
    (re.compile(r"document\.cookie"), "Читання cookies (можлива крадіжка сесій)", "high"),
    (re.compile(r"coinhive|cryptonight|minergate|webminepool", re.I), "Ознаки криптомайнера", "high"),
    (re.compile(r"\batob\s*\("), "Декодування прихованого payload (atob)", "medium"),
    (re.compile(r"String\.fromCharCode"), "Обфускація коду (String.fromCharCode)", "medium"),
    (re.compile(r"<iframe"), "Прихований iframe", "medium"),
    (re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"), "Великий base64-блок (можливий прихований payload)", "medium"),
]

MAGIC_BYTES = {
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "gif": [b"GIF87a", b"GIF89a"],
    "avif": [],
}
DANGEROUS_CONTENT = [b"<?php", b"<?=", b"\x7fELF", b"MZ\x90\x00"]
SVG_DANGEROUS = re.compile(rb"<\s*script|javascript\s*:|\son[a-z]+\s*=", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_upload_content(ext: str, data: bytes) -> tuple[bool, str]:
    """Validate uploaded file content. Returns (ok, reason)."""
    if not data:
        return False, "порожній файл"
    head = data[:16]
    for sig in DANGEROUS_CONTENT:
        if data.find(sig) != -1:
            return False, "файл містить виконуваний код або ознаки бекдора"
    if ext == "svg":
        if SVG_DANGEROUS.search(data):
            return False, "SVG містить скрипти або обробники подій (XSS)"
        if b"<svg" not in data[:1024].lower():
            return False, "файл не є справжнім SVG"
        return True, ""
    if ext == "webp":
        if not (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
            return False, "вміст файлу не відповідає формату WebP"
        return True, ""
    if ext == "avif":
        if b"ftyp" not in head:
            return False, "вміст файлу не відповідає формату AVIF"
        return True, ""
    sigs = MAGIC_BYTES.get(ext, [])
    if sigs and not any(data.startswith(s) for s in sigs):
        return False, f"вміст файлу не відповідає розширенню .{ext} (можлива маскування шкідливого файлу)"
    if b"<script" in data[:8192].lower():
        return False, "файл містить скрипт (XSS)"
    return True, ""


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_files() -> dict:
    files = {}
    for base, exts in WATCH_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in names:
                if name in SKIP_FILES:
                    continue
                ext = os.path.splitext(name)[1].lower()
                if exts is not None and ext not in exts:
                    continue
                full = os.path.join(root, name)
                rel = os.path.relpath(full, APP_ROOT)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                files[rel] = {"abs": full, "size": st.st_size, "mtime": st.st_mtime, "ext": ext}
    return files


def _pattern_scan(path: str, ext: str) -> list:
    if ext not in TEXT_EXT:
        return []
    try:
        if os.path.getsize(path) > MAX_PATTERN_FILE_SIZE:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []
    findings = []
    for rx, label, severity in SUSPICIOUS_PATTERNS:
        m = rx.search(content)
        if m:
            line_no = content.count("\n", 0, m.start()) + 1
            findings.append({"label": label, "severity": severity, "line": line_no})
    return findings


async def record_event(db, *, kind: str, path: str, detail: str, severity: str) -> bool:
    existing = await db.security_events.find_one({"kind": kind, "path": path, "detail": detail, "resolved": False})
    if existing:
        return False
    doc = {
        "id": str(uuid.uuid4()),
        "kind": kind,
        "path": path,
        "detail": detail,
        "severity": severity,
        "resolved": False,
        "created_at": _now(),
    }
    await db.security_events.insert_one(doc)
    if severity == "high":
        try:
            await _send_alert_email(db, doc)
        except Exception as e:
            logger.error(f"Security alert email failed: {e}")
    return True


async def _send_alert_email(db, event: dict) -> None:
    from emailer import send_email

    settings = await db.settings.find_one({"_key": "site"}) or {}
    to = settings.get("notify_email")
    if not to:
        return
    kind_label = {
        "malware_pattern": "Підозрілий код",
        "blocked_upload": "Заблоковане завантаження",
        "new_file": "Новий файл",
        "changed_file": "Змінений файл",
        "deleted_file": "Видалений файл",
    }.get(event["kind"], event["kind"])
    path = html_mod.escape(event["path"])
    detail = html_mod.escape(event["detail"])
    await send_email(
        to=to,
        subject=f"⚠️ Elite Master Security: {kind_label}",
        html=(
            "<h2 style='color:#B91C1C'>Сигнал системи безпеки сайту</h2>"
            f"<p><b>Тип:</b> {kind_label}</p>"
            f"<p><b>Файл:</b> <code>{path}</code></p>"
            f"<p><b>Деталі:</b> {detail}</p>"
            f"<p><b>Час:</b> {html_mod.escape(event['created_at'])}</p>"
            "<p>Відкрийте адмін-панель → розділ «Безпека», щоб переглянути деталі.</p>"
        ),
    )


async def run_scan(db, trigger: str = "manual") -> dict:
    files = _collect_files()
    baseline_docs = await db.security_baseline.find({}, {"_id": 0}).to_list(10000)
    baseline = {d["path"]: d for d in baseline_docs}
    first_run = len(baseline) == 0
    allow = await db.security_allow.find({}, {"_id": 0}).to_list(1000)
    allowed = {(a["path"], a["detail"]) for a in allow}

    created = {"new_file": 0, "changed_file": 0, "deleted_file": 0, "malware_pattern": 0}
    for rel, info in files.items():
        digest = _sha256(info["abs"])
        old = baseline.get(rel)
        if not first_run:
            if old is None:
                if await record_event(db, kind="new_file", path=rel, detail="Файл з'явився після останнього затвердження", severity="medium"):
                    created["new_file"] += 1
            elif old.get("sha256") != digest:
                if await record_event(db, kind="changed_file", path=rel, detail="Вміст файлу змінено після останнього затвердження", severity="medium"):
                    created["changed_file"] += 1
        if rel not in PATTERN_SKIP_PATHS:
            for f in _pattern_scan(info["abs"], info["ext"]):
                detail = f"{f['label']} (рядок {f['line']})"
                if (rel, detail) in allowed:
                    continue
                if await record_event(db, kind="malware_pattern", path=rel, detail=detail, severity=f["severity"]):
                    created["malware_pattern"] += 1
        if first_run:
            await db.security_baseline.update_one(
                {"path": rel},
                {"$set": {"path": rel, "sha256": digest, "size": info["size"], "scanned_at": _now()}},
                upsert=True,
            )

    if not first_run:
        for rel in baseline:
            if rel not in files:
                if await record_event(db, kind="deleted_file", path=rel, detail="Файл зник після останнього затвердження", severity="medium"):
                    created["deleted_file"] += 1

    await db.security_meta.update_one(
        {"_key": "scan"},
        {"$set": {"_key": "scan", "last_scan": _now(), "files_count": len(files), "trigger": trigger}},
        upsert=True,
    )
    return {"ok": True, "files_count": len(files), "first_run": first_run, "new_events": created, "scanned_at": _now()}


async def approve_baseline(db) -> dict:
    """Accept current file tree as the new trusted baseline; resolve diff events."""
    files = _collect_files()
    now = _now()
    await db.security_baseline.delete_many({})
    docs = [{"path": rel, "sha256": _sha256(info["abs"]), "size": info["size"], "scanned_at": now} for rel, info in files.items()]
    if docs:
        await db.security_baseline.insert_many(docs)
    res = await db.security_events.update_many(
        {"resolved": False, "kind": {"$in": ["new_file", "changed_file", "deleted_file"]}},
        {"$set": {"resolved": True, "resolved_at": now}},
    )
    return {"ok": True, "baseline_files": len(docs), "resolved_events": res.modified_count}
