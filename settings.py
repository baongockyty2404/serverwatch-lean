"""
Runtime-configurable settings (thay thế .env cho các giá trị cần đổi nóng).

Thiết kế:
  - Bảng `settings(key TEXT PK, value TEXT, is_secret INT, updated_at, updated_by)`
  - Đọc: get(key, default=env_fallback) — DB trước, env sau, default sau cùng
  - Cache in-memory với TTL 15s để giảm DB hit trong hot-path (send_telegram v.v.)
  - Secret keys mask khi trả API (chỉ hiện 4 ký tự cuối)

Keys được hỗ trợ (mỗi key có meta: label, group, is_secret, env_name):
  - telegram.bot_token        secret
  - telegram.chat_id          plain
  - telegram.admin_ids        plain   (csv)
  - smtp.host/port/user/pass/from  pass là secret
  - alert.email               plain
  - ai.backend                plain   (claude|ollama)
  - ai.enabled                plain   bool
  - ai.auto_fix               plain   bool
  - ai.anthropic_api_key      secret
  - ai.model                  plain
  - ollama.url/model/timeout  plain

Dashboard UI cho phép đổi mà không cần restart container (server-side dispatcher
tự lấy giá trị mới). Riêng sw-telegram container chỉ đọc env lúc startup —
khi đổi token cần docker restart sw-telegram.
"""

from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    is_secret   INTEGER DEFAULT 0,
    updated_at  TEXT,
    updated_by  TEXT
);
"""


# ═══════════════════════════════════════════════════════════════════════════════
# Schema của các key được hỗ trợ
# ═══════════════════════════════════════════════════════════════════════════════

# (key, group, label, is_secret, env_var, description)
# Env_var = tên ENV fallback; rỗng nếu không có ENV đồng nghĩa.
SCHEMA: list[tuple[str, str, str, bool, str, str]] = [
    # Telegram
    ("telegram.bot_token",   "Telegram", "Bot Token",      True,  "TELEGRAM_BOT_TOKEN",
      "Token từ @BotFather. Đổi xong cần restart sw-telegram container để bot polling dùng token mới."),
    ("telegram.chat_id",     "Telegram", "Chat ID",        False, "TELEGRAM_CHAT_ID",
      "Chat/group ID nhận alert (VD: -100xxxxxxxxxx)."),
    ("telegram.admin_ids",   "Telegram", "Admin IDs",      False, "TELEGRAM_ADMIN_IDS",
      "CSV user ID được phép dùng /exec và lệnh admin của bot."),

    # Email
    ("smtp.host",    "Email", "SMTP Host", False, "SMTP_HOST", "VD: smtp.gmail.com"),
    ("smtp.port",    "Email", "SMTP Port", False, "SMTP_PORT", "Mặc định 587"),
    ("smtp.user",    "Email", "SMTP User", False, "SMTP_USER", "Tài khoản gửi"),
    ("smtp.pass",    "Email", "SMTP Pass", True,  "SMTP_PASS", "App password (Gmail)"),
    ("alert.email",  "Email", "Alert Email", False, "ALERT_EMAIL", "Nhận alert critical"),

    # Monitoring rules (runtime configurable, không cần restart)
    ("monitor.expected_processes", "Monitoring", "Expected processes",
      False, "", "CSV danh sách process name phải có (vd: postgres,nginx,redis-server). Vắng → alert."),
    ("monitor.host_offline_sec",   "Monitoring", "Host offline threshold (s)",
      False, "", "Số giây không nhận push thì coi host offline. Default 180."),
]

SCHEMA_BY_KEY = {s[0]: s for s in SCHEMA}
SECRET_KEYS = {s[0] for s in SCHEMA if s[3]}


def init_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# In-memory cache với TTL 15s
# ═══════════════════════════════════════════════════════════════════════════════

_cache: dict = {}
_cache_ts: float = 0.0
_CACHE_TTL_SEC = 15


def _load_all(db_path: str) -> dict:
    global _cache, _cache_ts
    if _cache and (time.time() - _cache_ts) < _CACHE_TTL_SEC:
        return _cache
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    _cache = {k: v for k, v in rows}
    _cache_ts = time.time()
    return _cache


def invalidate_cache() -> None:
    global _cache, _cache_ts
    _cache = {}
    _cache_ts = 0.0


def get(db_path: str, key: str, default: str = "") -> str:
    """
    Đọc setting: DB trước, ENV theo schema sau, default cuối cùng.
    Luôn trả str (đổi type ở caller nếu cần int/bool).
    """
    data = _load_all(db_path)
    if key in data and data[key] != "":
        return data[key]
    meta = SCHEMA_BY_KEY.get(key)
    if meta and meta[4]:   # env_var
        env_val = os.getenv(meta[4], "")
        if env_val:
            return env_val
    return default


def get_int(db_path: str, key: str, default: int = 0) -> int:
    try:
        return int(get(db_path, key, str(default)))
    except ValueError:
        return default


def get_bool(db_path: str, key: str, default: bool = False) -> bool:
    v = get(db_path, key, "true" if default else "false").strip().lower()
    return v in ("1", "true", "yes", "on")


def set_value(db_path: str, key: str, value: str, by_user: str = "") -> None:
    """Ghi đè setting. Nếu key không trong schema → cho phép nhưng đánh dấu plain."""
    meta = SCHEMA_BY_KEY.get(key)
    is_secret = 1 if (meta and meta[3]) else 0
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO settings (key, value, is_secret, updated_at, updated_by)
           VALUES (?,?,?,?,?)
           ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                                           updated_at=excluded.updated_at,
                                           updated_by=excluded.updated_by""",
        (key, value, is_secret, now, by_user)
    )
    conn.commit()
    conn.close()
    invalidate_cache()


def delete(db_path: str, key: str) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.execute("DELETE FROM settings WHERE key=?", (key,))
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    invalidate_cache()
    return ok


# ═══════════════════════════════════════════════════════════════════════════════
# Public listing với mask
# ═══════════════════════════════════════════════════════════════════════════════

def _mask(v: str) -> str:
    if not v:
        return ""
    if len(v) <= 4:
        return "*" * len(v)
    return "***" + v[-4:]


def list_all(db_path: str) -> list[dict]:
    """
    Trả về list[{key, group, label, is_secret, source, value, env_fallback,
                 description, updated_at, updated_by}] cho dashboard.
    Value của secret được mask. source = 'db' | 'env' | 'default'.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    db_rows = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM settings").fetchall()}
    conn.close()

    out = []
    for key, group, label, is_secret, env_var, desc in SCHEMA:
        db_row = db_rows.get(key)
        env_val = os.getenv(env_var, "") if env_var else ""
        if db_row and (db_row["value"] or "") != "":
            value = db_row["value"]
            source = "db"
        elif env_val:
            value = env_val
            source = "env"
        else:
            value = ""
            source = "default"
        out.append({
            "key":           key,
            "group":         group,
            "label":         label,
            "is_secret":     bool(is_secret),
            "source":        source,
            "value":         _mask(value) if is_secret else value,
            "has_value":     bool(value),
            "env_var":       env_var,
            "env_set":       bool(env_val),
            "description":   desc,
            "updated_at":    db_row["updated_at"] if db_row else None,
            "updated_by":    db_row["updated_by"] if db_row else None,
        })
    return out
