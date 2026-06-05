"""
ServerWatch Backend API — lean rewrite.

FastAPI nhận metrics từ agent, chạy rule engine, gửi alert Telegram/Email,
lưu time-series + state vào SQLite (không cần InfluxDB).

Module phụ thuộc giữ:
  - anomaly        : Z-score + port scan
  - alert_state    : dedup + silence
  - monitors       : cert / domain / HTTP / TCP probes
  - settings       : runtime settings table
  - metrics_ts     : SQLite ring-buffer thay InfluxDB
  - backup         : SQLite + audit dir tarball backup

Đã bỏ so với phiên bản trước: ai_analyzer, slo, forecast, extras (log_fts/
events/escalation), audit (HMAC signing), telegram_bot, remote command exec,
topology, FIM endpoint.
"""

import os
import json
import time
import hmac
import asyncio
import smtplib
import hashlib
import sqlite3
import logging
import secrets
import base64
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiohttp
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse

from dotenv import load_dotenv
load_dotenv()

from anomaly import AnomalyDetector, PortScanDetector
import alert_state
import monitors as monitors_mod
import settings as settings_mod
import metrics_ts
import backup as backup_mod


# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("server")


# ─── Cấu hình ────────────────────────────────────────────────────────────────

SECRET_TOKEN     = os.getenv("SECRET_TOKEN", "changeme")
ADMIN_EMAIL      = os.getenv("ADMIN_EMAIL", "admin@serverwatch.local")
ADMIN_PASSWORD   = os.getenv("ADMIN_PASSWORD", "changeme")

# JWT_SECRET và BACKUP_HMAC_SECRET phải khác SECRET_TOKEN — nếu admin để trống,
# server tự sinh random (in-memory, mất khi restart → JWT cũ bị invalidate, an toàn).
# Trước đây cùng default = SECRET_TOKEN → 1 leak agent token = forge JWT + forge
# backup HMAC + bypass admin auth qua Bearer. Tách ra giảm blast radius.
def _resolve_secret(env_var: str, fallback: str) -> tuple[str, bool]:
    val = os.getenv(env_var, "")
    if val and val != SECRET_TOKEN:
        return val, False
    # Sinh random ephemeral nếu env không set HOẶC trùng SECRET_TOKEN
    return secrets.token_urlsafe(48), True

JWT_SECRET, _jwt_generated = _resolve_secret("JWT_SECRET", SECRET_TOKEN)
BACKUP_HMAC_SECRET, _backup_generated = _resolve_secret("BACKUP_HMAC_SECRET", SECRET_TOKEN)
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

ALERT_RENOTIFY_SEC     = int(os.getenv("ALERT_RENOTIFY_SEC", "3600"))
ALERT_AUTO_RESOLVE_SEC = int(os.getenv("ALERT_AUTO_RESOLVE_SEC", "900"))

METRICS_RETENTION_HOURS = int(os.getenv("METRICS_RETENTION_HOURS", "48"))
ALERTS_RETENTION_DAYS   = int(os.getenv("ALERTS_RETENTION_DAYS", "30"))

HEARTBEAT_SECRET = os.getenv("HEARTBEAT_SECRET", "")

BACKUP_DIR             = Path(os.getenv("BACKUP_DIR", "/app/backup"))
BACKUP_RETENTION_DAYS  = int(os.getenv("BACKUP_RETENTION_DAYS", "30"))
BACKUP_HOUR_UTC        = int(os.getenv("BACKUP_HOUR_UTC", "19"))
BACKUP_VERIFY_DAY      = int(os.getenv("BACKUP_VERIFY_DAY", "0"))

_backup_state: dict = {"running": False, "last_result": None, "last_error": None}

_data_dir = Path(__file__).parent / "data"
_data_dir.mkdir(exist_ok=True)
DB_PATH = str(_data_dir / "serverwatch.db")


# Monkey-patch sqlite3.connect để mọi connection mặc định có:
#   - timeout=10s (busy_timeout) — WAL cho phép reader/writer song song nhưng
#     2 writer cùng lúc sẽ SQLITE_BUSY; timeout=10s sẽ retry trong sqlite3 layer.
#   - isolation_level=None — autocommit, không giữ implicit BEGIN treo lock
_orig_sqlite_connect = sqlite3.connect
def _patched_connect(*args, **kwargs):
    kwargs.setdefault("timeout", 10.0)
    return _orig_sqlite_connect(*args, **kwargs)
sqlite3.connect = _patched_connect


# ─── Password hashing ────────────────────────────────────────────────────────

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return h.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return hmac.compare_digest(h.hex(), stored_hash)


# ─── JWT đơn giản ────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(payload: dict, secret: str = JWT_SECRET,
                expire_hours: int = JWT_EXPIRE_HOURS) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    # Thêm jti (JWT ID) ngẫu nhiên để hỗ trợ blacklist khi logout — cần unique
    # per-token để 1 lần logout không invalidate token khác của cùng user.
    payload = {**payload,
               "exp": int(time.time()) + expire_hours * 3600,
               "jti": secrets.token_urlsafe(16)}
    h = _b64url_encode(json.dumps(header).encode())
    p = _b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"

def verify_jwt(token: str, secret: str = JWT_SECRET) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, s = parts
        expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(s), expected):
            return None
        payload = json.loads(_b64url_decode(p))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ─── SQLite khởi tạo ─────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA wal_autocheckpoint=1000")
    conn.execute("PRAGMA mmap_size=268435456")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host        TEXT    NOT NULL,
            type        TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            detail      TEXT,
            timestamp   TEXT    NOT NULL,
            notified    INTEGER DEFAULT 0,
            resolved    INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts(timestamp);

        CREATE TABLE IF NOT EXISTS hosts (
            hostname    TEXT PRIMARY KEY,
            os          TEXT,
            last_seen   TEXT,
            status      TEXT DEFAULT 'online'
        );

        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            salt        TEXT NOT NULL,
            name        TEXT DEFAULT '',
            role        TEXT DEFAULT 'admin',
            created_at  TEXT NOT NULL,
            last_login  TEXT
        );
    """)
    conn.commit()
    conn.close()

    alert_state.init_schema(DB_PATH)
    monitors_mod.init_schema(DB_PATH)
    settings_mod.init_schema(DB_PATH)
    metrics_ts.init_schema(DB_PATH)

    # Đồng bộ tài khoản admin từ .env
    conn = sqlite3.connect(DB_PATH)
    if ADMIN_EMAIL and ADMIN_PASSWORD and ADMIN_PASSWORD != "changeme":
        pw_hash, salt = hash_password(ADMIN_PASSWORD)
        existing = conn.execute(
            "SELECT id, password, salt FROM users WHERE email=?",
            (ADMIN_EMAIL,)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (email, password, salt, name, role, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (ADMIN_EMAIL, pw_hash, salt, "Admin", "admin",
                 datetime.now(timezone.utc).isoformat())
            )
            log.info("Tài khoản admin đã tạo: %s", ADMIN_EMAIL)
        elif not verify_password(ADMIN_PASSWORD, existing[1], existing[2]):
            new_hash, new_salt = hash_password(ADMIN_PASSWORD)
            conn.execute("UPDATE users SET password=?, salt=? WHERE id=?",
                         (new_hash, new_salt, existing[0]))
            log.info("Mật khẩu admin đã cập nhật: %s", ADMIN_EMAIL)
    else:
        log.warning("ADMIN_EMAIL/ADMIN_PASSWORD chưa cấu hình trong .env")
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class RuleEngine:
    COOLDOWN_SEC = 300

    def __init__(self):
        self._last_alert: dict = defaultdict(float)

    def _should_alert(self, host: str, alert_type: str) -> bool:
        key = (host, alert_type)
        if time.time() - self._last_alert[key] > self.COOLDOWN_SEC:
            self._last_alert[key] = time.time()
            return True
        return False

    def evaluate(self, host: str, metrics: dict) -> list:
        alerts = []

        for t in metrics.get("threats", []):
            if self._should_alert(host, t["type"]):
                alerts.append(t)

        if metrics.get("cpu", {}).get("percent", 0) > 90:
            if self._should_alert(host, "cpu_high"):
                alerts.append({"type": "cpu_high", "severity": "warning",
                               "detail": f"CPU {metrics['cpu']['percent']}% — kiểm tra process"})

        if metrics.get("memory", {}).get("percent", 0) > 95:
            if self._should_alert(host, "mem_critical"):
                alerts.append({"type": "mem_critical", "severity": "critical",
                               "detail": f"RAM {metrics['memory']['percent']}% — nguy cơ OOM"})

        for disk in metrics.get("disk", []):
            if disk.get("percent", 0) > 90:
                key = f"disk_{disk.get('mountpoint')}"
                if self._should_alert(host, key):
                    alerts.append({"type": "disk_full", "severity": "warning",
                                   "detail": f"Disk {disk['mountpoint']} = {disk['percent']}%"})

        for ip, count in metrics.get("network", {}).get("top_remote_ips", []):
            if count > 50 and self._should_alert(host, f"ddos_{ip}"):
                alerts.append({"type": "ddos_suspect", "severity": "critical",
                               "detail": f"IP {ip} có {count} kết nối đồng thời"})

        # Process watchlist — alert nếu process trong settings vắng.
        # Ưu tiên `process_names` (full set tên, không top-20) nếu agent gửi;
        # fallback sang `processes` (top-20) cho agent cũ.
        expected = settings_mod.get(DB_PATH, "monitor.expected_processes", "")
        if expected:
            wanted = {p.strip().lower() for p in expected.split(",") if p.strip()}
            names_full = metrics.get("process_names")
            if names_full is not None:
                running = {str(n).lower() for n in names_full}
            else:
                running = {p.get("name", "").lower() for p in metrics.get("processes", [])}
            # Match prefix (vd "sshd" khớp với "sshd: /usr/sbin/sshd -D")
            missing = []
            for proc in sorted(wanted):
                if not any(r == proc or r.startswith(proc + ":") or r.startswith(proc + " ")
                            for r in running):
                    missing.append(proc)
            for proc in missing:
                if self._should_alert(host, f"process_missing_{proc}"):
                    alerts.append({"type": "process_missing", "severity": "critical",
                                   "detail": f"Process '{proc}' không chạy trên host"})

        # Docker rules — chỉ giữ các cảnh báo có giá trị thực
        docker = metrics.get("docker", {}) or {}
        if docker.get("available"):
            for c in docker.get("containers", []):
                cname = c.get("name", "?")
                if c.get("restart_count", 0) > 5 and self._should_alert(host, f"docker_restart_{cname}"):
                    alerts.append({"type": "docker_restart_loop", "severity": "critical",
                                   "detail": f"Container '{cname}' restart {c['restart_count']} lần"})
                if c.get("mem_percent", 0) > 95 and self._should_alert(host, f"docker_oom_{cname}"):
                    alerts.append({"type": "docker_oom_risk", "severity": "critical",
                                   "detail": f"Container '{cname}' MEM={c['mem_percent']:.1f}%"})
                if c.get("log_error_count", 0) > 10 and self._should_alert(host, f"docker_errors_{cname}"):
                    alerts.append({"type": "docker_error_spike", "severity": "warning",
                                   "detail": f"Container '{cname}' có {c['log_error_count']} lỗi trong log"})

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# ALERT DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

class AlertDispatcher:

    async def send_telegram(self, host: str, alert: dict):
        token   = settings_mod.get(DB_PATH, "telegram.bot_token", "")
        chat_id = settings_mod.get(DB_PATH, "telegram.chat_id", "")
        if not token or not chat_id:
            return
        emoji = "🔴" if alert["severity"] == "critical" else "🟡"
        # Escape Markdown special chars trong field user-controlled (host, type,
        # detail có thể đến từ agent gửi giả mạo). parse_mode=Markdown sẽ render
        # [text](url) thành clickable link → phishing/javascript: URL risk.
        # Bọc trong code-block (`…`) là cách đơn giản nhất, an toàn vì code-block
        # không parse Markdown bên trong (chỉ cần escape ` và \\).
        def _md_code(s: str) -> str:
            return str(s).replace("\\", "\\\\").replace("`", "'")
        text = (
            f"{emoji} *ServerWatch Alert*\n"
            f"*Host:* `{_md_code(host)}`\n"
            f"*Loại:* `{_md_code(alert['type'])}`\n"
            f"*Mức:* `{alert['severity'].upper()}`\n"
            f"*Chi tiết:* `{_md_code(alert['detail'])}`\n"
            f"*Thời gian:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(url, json={
                    "chat_id":    chat_id,
                    "text":       text,
                    "parse_mode": "Markdown",
                }, timeout=aiohttp.ClientTimeout(total=5))
            log.info("Telegram alert: %s/%s", host, alert["type"])
        except Exception as e:
            log.error("Lỗi Telegram: %s", e)

    def send_email(self, host: str, alert: dict):
        user      = settings_mod.get(DB_PATH, "smtp.user", "")
        pwd       = settings_mod.get(DB_PATH, "smtp.pass", "")
        smtp_host = settings_mod.get(DB_PATH, "smtp.host", "smtp.gmail.com")
        port      = settings_mod.get_int(DB_PATH, "smtp.port", 587)
        to        = settings_mod.get(DB_PATH, "alert.email", "")
        if not user or not to:
            return
        subject = f"[{alert['severity'].upper()}] {host} — {alert['type']}"
        body = (
            f"ServerWatch Cảnh Báo\n"
            f"====================\n"
            f"Host     : {host}\n"
            f"Loại     : {alert['type']}\n"
            f"Mức độ   : {alert['severity'].upper()}\n"
            f"Chi tiết : {alert['detail']}\n"
            f"Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        msg = MIMEMultipart()
        msg["From"], msg["To"], msg["Subject"] = user, to, subject
        msg.attach(MIMEText(body, "plain", "utf-8"))
        try:
            with smtplib.SMTP(smtp_host, port) as smtp:
                smtp.starttls()
                smtp.login(user, pwd)
                smtp.send_message(msg)
            log.info("Email alert: %s", subject)
        except Exception as e:
            log.error("Lỗi Email: %s", e)

    async def dispatch(self, host: str, alert: dict):
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO alerts (host, type, severity, detail, timestamp) VALUES (?,?,?,?,?)",
            (host, alert["type"], alert["severity"],
             alert.get("detail", ""), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        conn.close()

        should_notify, fingerprint = alert_state.record_and_check(
            DB_PATH, host, alert, renotify_after_sec=ALERT_RENOTIFY_SEC
        )

        silence = alert_state.is_silenced(DB_PATH, host, alert["type"])
        if silence:
            log.info("Alert %s/%s silenced bởi rule #%d", host, alert["type"], silence["id"])
            return
        if not should_notify:
            return

        alert_with_fp = {**alert, "fingerprint": fingerprint}
        await self.send_telegram(host, alert_with_fp)
        if alert["severity"] == "critical":
            # smtplib là sync; offload sang threadpool để không block event loop.
            await asyncio.to_thread(self.send_email, host, alert_with_fp)


# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.active:
                self.active.remove(ws)


# ══════════════════════════════════════════════════════════════════════════════
# Globals
# ══════════════════════════════════════════════════════════════════════════════

rule_engine      = RuleEngine()
dispatcher       = AlertDispatcher()
ws_manager       = ConnectionManager()
anomaly_detector = AnomalyDetector()
port_scan_det    = PortScanDetector()

latest_metrics: dict = {}


# ══════════════════════════════════════════════════════════════════════════════
# Background loops
# ══════════════════════════════════════════════════════════════════════════════

async def _task_auto_resolve_loop():
    """Đánh dấu resolved các alert không update trong ALERT_AUTO_RESOLVE_SEC giây."""
    while True:
        try:
            resolved = alert_state.auto_resolve_stale(DB_PATH, ALERT_AUTO_RESOLVE_SEC)
            for r in resolved:
                if alert_state.is_silenced(DB_PATH, r["host"], r["type"]):
                    continue
                await dispatcher.send_telegram(r["host"], {
                    "type": r["type"], "severity": "info",
                    "detail": f"✅ [{r['type']}] đã tự giải quyết (xảy ra {r['occurrences']} lần)",
                    "fingerprint": r["fingerprint"],
                })
        except Exception as e:
            log.error("auto_resolve loop error: %s", e)
        await asyncio.sleep(60)


async def _task_monitors_loop():
    async def _on_result(monitor: dict, result: dict):
        status = result.get("status", "ok")
        if status == "ok":
            return
        severity = "critical" if status == "critical" else "warning"
        await dispatcher.dispatch(monitor["target"], {
            "type": f"monitor_{monitor['kind']}",
            "severity": severity,
            "detail": f"[{monitor['kind']}] {monitor['target']}: {result.get('detail','')}",
        })

    await monitors_mod.scheduler_loop(DB_PATH, on_result=_on_result)


async def _task_metrics_cleanup_loop():
    """
    Xoá data cũ mỗi giờ:
      - metrics_ts/docker_ts: > METRICS_RETENTION_HOURS (default 48h)
      - alerts:              > ALERTS_RETENTION_DAYS    (default 30d)
    """
    while True:
        await asyncio.sleep(3600)
        try:
            n = metrics_ts.cleanup(DB_PATH, METRICS_RETENTION_HOURS)
            if n:
                log.info("metrics_ts cleanup: xoá %d row cũ", n)
        except Exception as e:
            log.error("metrics_ts cleanup error: %s", e)
        try:
            conn = sqlite3.connect(DB_PATH)
            cutoff = (datetime.now(timezone.utc) -
                      timedelta(days=ALERTS_RETENTION_DAYS)).isoformat()
            n = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,)).rowcount
            conn.commit()
            conn.close()
            if n:
                log.info("alerts cleanup: xoá %d row cũ (>%dd)", n, ALERTS_RETENTION_DAYS)
        except Exception as e:
            log.error("alerts cleanup error: %s", e)


async def _task_wal_truncate_loop():
    """Mỗi 24h chạy PRAGMA wal_checkpoint(TRUNCATE) để giữ file .db-wal nhỏ."""
    while True:
        await asyncio.sleep(86400)
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
            log.info("WAL checkpoint TRUNCATE done")
        except Exception as e:
            log.error("WAL truncate error: %s", e)


async def _task_host_offline_loop():
    """
    Mỗi 60s: quét bảng `hosts`, host nào last_seen quá ngưỡng (default 180s)
    thì fire alert `host_down`. Khi host push lại, alert auto-resolve qua
    auto_resolve_stale loop sẵn có.

    LƯU Ý: connection chỉ giữ mở đủ cho SELECT + UPDATE, rồi đóng TRƯỚC khi
    gọi dispatcher.dispatch (dispatcher cũng mở connection write → tránh
    deadlock với cùng DB qua connection riêng).
    """
    while True:
        await asyncio.sleep(60)
        try:
            threshold = settings_mod.get_int(DB_PATH, "monitor.host_offline_sec", 180)
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=threshold)
            cutoff_iso = cutoff.isoformat()

            conn = sqlite3.connect(DB_PATH)
            offline_rows = conn.execute(
                "SELECT hostname, last_seen FROM hosts WHERE last_seen < ? AND status='online'",
                (cutoff_iso,)
            ).fetchall()
            for hostname, _ in offline_rows:
                conn.execute("UPDATE hosts SET status='offline' WHERE hostname=?", (hostname,))
            conn.execute(
                "UPDATE hosts SET status='online' WHERE status='offline' AND last_seen >= ?",
                (cutoff_iso,)
            )
            conn.commit()
            conn.close()

            # Dispatch sau khi đã đóng conn
            for hostname, last_seen in offline_rows:
                await dispatcher.dispatch(hostname, {
                    "type": "host_down",
                    "severity": "critical",
                    "detail": f"Host '{hostname}' không gửi metrics từ {last_seen} (> {threshold}s)",
                })
        except Exception as e:
            log.error("host_offline loop error: %s", e)


async def _task_backup_loop():
    """Daily backup lúc BACKUP_HOUR_UTC. Weekly verify backup mới nhất."""
    last_backup_day: Optional[str] = None
    last_verify_week: Optional[str] = None

    while True:
        try:
            now = datetime.now(timezone.utc)
            today = now.date().isoformat()
            week = f"{now.isocalendar().year}-W{now.isocalendar().week}"

            if now.hour == BACKUP_HOUR_UTC and last_backup_day != today:
                last_backup_day = today
                log.info("Backup daily start...")
                try:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None,
                        lambda: backup_mod.run_backup(
                            DB_PATH, _data_dir, BACKUP_DIR,
                            hmac_key=BACKUP_HMAC_SECRET,
                        )
                    )
                    log.info("Backup OK: %s (%d bytes)", result["name"], result["bytes"])
                    deleted = backup_mod.cleanup_old(BACKUP_DIR, BACKUP_RETENTION_DAYS)
                    if deleted:
                        log.info("Backup cleanup: xoá %d file cũ", deleted)
                except Exception as e:
                    log.error("Backup fail: %s", e, exc_info=True)
                    await dispatcher.dispatch("backup", {
                        "type": "backup_failed", "severity": "critical",
                        "detail": f"Backup daily fail: {e}",
                    })

            if now.weekday() == BACKUP_VERIFY_DAY and last_verify_week != week:
                last_verify_week = week
                backups = backup_mod.list_backups(BACKUP_DIR)
                if backups:
                    latest = BACKUP_DIR / backups[0]["name"]
                    try:
                        loop = asyncio.get_event_loop()
                        v = await loop.run_in_executor(
                            None, lambda: backup_mod.verify_backup(latest, BACKUP_HMAC_SECRET)
                        )
                        if not v["ok"]:
                            await dispatcher.dispatch("backup", {
                                "type": "backup_verify_failed", "severity": "critical",
                                "detail": f"Verify fail: {latest.name}",
                            })
                    except Exception as e:
                        log.error("Verify fail: %s", e, exc_info=True)
        except Exception as e:
            log.error("backup loop error: %s", e)
        await asyncio.sleep(300)


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("ServerWatch Server khởi động (lean)")
    # Cảnh báo nếu admin chưa set JWT_SECRET / BACKUP_HMAC_SECRET — server sẽ
    # dùng giá trị ephemeral (mất khi restart → user phải login lại).
    if _jwt_generated:
        log.warning("JWT_SECRET chưa set (hoặc trùng SECRET_TOKEN) — dùng "
                    "random ephemeral. User sẽ phải login lại sau mỗi lần "
                    "restart. Khuyến nghị set JWT_SECRET trong .env "
                    "(openssl rand -hex 32).")
    if _backup_generated:
        log.warning("BACKUP_HMAC_SECRET chưa set — backup mới sẽ ký bằng "
                    "ephemeral key, KHÔNG verify được sau khi restart. "
                    "Khuyến nghị set BACKUP_HMAC_SECRET trong .env.")

    tasks = [
        asyncio.create_task(_task_auto_resolve_loop()),
        asyncio.create_task(_task_monitors_loop()),
        asyncio.create_task(_task_metrics_cleanup_loop()),
        asyncio.create_task(_task_host_offline_loop()),
        asyncio.create_task(_task_wal_truncate_loop()),
        asyncio.create_task(_task_backup_loop()),
    ]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        log.info("ServerWatch Server tắt")


app = FastAPI(title="ServerWatch API", version="2.0.0-lean", lifespan=lifespan)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://monitor.example.com").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
)


# Security headers thay cho nginx (đã bỏ sw-nginx container).
# External nginx (reverse proxy) lo SSL + rate-limit ở tầng ngoài.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        # Dashboard dùng React + Babel JSX in-browser nên cần 'unsafe-inline'
        # (inline <script type="text/babel">) và 'unsafe-eval' (Babel transform).
        # Trade-off: tightening CSP đòi rewrite dashboard thành bundle pre-build.
        # 'object-src none' chặn legacy plugin (Flash/PDF embed).
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' wss: ws:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self';"
    )
    response.headers.setdefault("Strict-Transport-Security",
                                 "max-age=31536000; includeSubDomains")
    return response


# Rate limit cho /api/auth/login đã có (login bruteforce). Các endpoint khác
# dùng JWT auth → không cần rate limit nội bộ; external nginx có thể thêm.


# ─── Auth helpers ────────────────────────────────────────────────────────────

_login_attempts: dict = defaultdict(list)
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC   = 300

def verify_agent_token(authorization: str) -> bool:
    if not authorization or not authorization.startswith("Bearer "):
        return False
    # constant-time compare để chặn timing attack — kể cả với HTTPS+CDN, `==`
    # vẫn là code smell vì exploit qua local network (cùng datacenter) khả thi.
    return hmac.compare_digest(authorization.split(" ", 1)[1], SECRET_TOKEN)

# In-memory JWT blacklist — JTI của token bị logout. Reset khi server restart
# (chấp nhận được vì JWT cũ cũng invalidated khi JWT_SECRET tái sinh random).
_jwt_blacklist: set[str] = set()

def verify_dashboard_token(request: Request) -> Optional[dict]:
    token = request.cookies.get("sw_token", "")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
    if not token:
        return None
    payload = verify_jwt(token)
    if payload and payload.get("jti") in _jwt_blacklist:
        return None
    return payload

def require_login(request: Request) -> dict:
    user = verify_dashboard_token(request)
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    return user

def require_admin(request: Request) -> dict:
    # KHÔNG nhận Bearer SECRET_TOKEN nữa — agent token (chia sẻ với mọi host
    # cần monitor) trước đây trùng admin token là vấn đề bảo mật lớn: 1 host
    # bị compromise → attacker có toàn quyền admin trên dashboard/backup/users.
    # Admin chỉ qua JWT (login với email/password).
    user = verify_dashboard_token(request)
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Cần quyền admin")
    return user


# ─── Auth endpoints ──────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(request: Request):
    client_ip = request.headers.get("X-Real-IP", request.client.host)
    now = time.time()
    _login_attempts[client_ip] = [t for t in _login_attempts[client_ip]
                                   if now - t < LOGIN_WINDOW_SEC]
    if len(_login_attempts[client_ip]) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429,
                            detail=f"Quá nhiều lần thử. Thử lại sau {LOGIN_WINDOW_SEC // 60} phút")

    body = await request.json()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Thiếu email hoặc mật khẩu")

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, email, password, salt, name, role FROM users WHERE email=?",
        (email,)
    ).fetchone()
    if not row:
        conn.close()
        _login_attempts[client_ip].append(now)
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

    uid, db_email, pw_hash, salt, name, role = row
    if not verify_password(password, pw_hash, salt):
        conn.close()
        _login_attempts[client_ip].append(now)
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

    conn.execute("UPDATE users SET last_login=? WHERE id=?",
                 (datetime.now(timezone.utc).isoformat(), uid))
    conn.commit()
    conn.close()

    token = create_jwt({"uid": uid, "email": db_email, "name": name, "role": role})
    response = JSONResponse(content={
        "status": "ok", "token": token,
        "user": {"id": uid, "email": db_email, "name": name, "role": role},
    })
    response.set_cookie(
        key="sw_token", value=token,
        httponly=True, secure=True, samesite="lax",
        max_age=JWT_EXPIRE_HOURS * 3600,
    )
    return response


@app.post("/api/auth/logout")
async def logout(request: Request):
    # Revoke JWT thật sự (thêm vào blacklist) — trước đây chỉ xoá cookie nên
    # nếu attacker đã capture được JWT trước đó, vẫn dùng được 24h sau logout.
    token = request.cookies.get("sw_token", "") or (
        request.headers.get("Authorization", "")[7:]
        if request.headers.get("Authorization", "").startswith("Bearer ") else "")
    if token:
        payload = verify_jwt(token)
        if payload and payload.get("jti"):
            _jwt_blacklist.add(payload["jti"])
            # Cap blacklist size để tránh memory bloat (server restart auto-clear)
            if len(_jwt_blacklist) > 10_000:
                _jwt_blacklist.clear()
    response = JSONResponse(content={"status": "ok"})
    response.delete_cookie("sw_token")
    return response


@app.get("/api/auth/me")
async def auth_me(request: Request):
    user = verify_dashboard_token(request)
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    return {"user": {
        "id": user.get("uid"), "email": user.get("email"),
        "name": user.get("name"), "role": user.get("role"),
    }}


@app.post("/api/auth/change-password")
async def change_password(request: Request):
    user = require_login(request)
    body = await request.json()
    current_pw = body.get("current_password", "")
    new_pw = body.get("new_password", "")
    if not current_pw or not new_pw:
        raise HTTPException(status_code=400, detail="Thiếu mật khẩu")
    if len(new_pw) < 6:
        raise HTTPException(status_code=400, detail="Mật khẩu mới tối thiểu 6 ký tự")

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT password, salt FROM users WHERE id=?",
                       (user["uid"],)).fetchone()
    if not row or not verify_password(current_pw, row[0], row[1]):
        conn.close()
        raise HTTPException(status_code=401, detail="Mật khẩu hiện tại không đúng")
    new_hash, new_salt = hash_password(new_pw)
    conn.execute("UPDATE users SET password=?, salt=? WHERE id=?",
                 (new_hash, new_salt, user["uid"]))
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ─── Metrics ingest ──────────────────────────────────────────────────────────

@app.post("/api/metrics")
async def receive_metrics(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not hmac.compare_digest(
            auth.split(" ", 1)[1], SECRET_TOKEN):
        raise HTTPException(status_code=403, detail="Forbidden")

    body = await request.json()
    host    = body.get("host", "unknown")
    metrics = body.get("metrics", {})

    # Validate payload structure trước khi đăng ký host.
    # Tránh "ghost host" — POST partial payload làm crash metrics_ts.write
    # nhưng vẫn để lại row trong table hosts.
    if not isinstance(host, str) or not host or host == "unknown":
        raise HTTPException(status_code=422, detail="missing or invalid 'host'")
    if not isinstance(metrics, dict) or not metrics:
        raise HTTPException(status_code=422, detail="missing or empty 'metrics'")

    payload_copy = {k: v for k, v in body.items() if k != "checksum"}
    expected_cs = hashlib.sha256(
        json.dumps(payload_copy, sort_keys=True).encode()
    ).hexdigest()
    if body.get("checksum") != expected_cs:
        log.warning("Checksum không khớp từ host %s", host)

    # Lưu time-series vào SQLite TRƯỚC khi register host. Nếu write fail
    # (payload malformed) → 422 ngay, không để lại ghost host trên dashboard.
    try:
        metrics_ts.write(DB_PATH, host, metrics)
    except Exception as e:
        log.error("metrics_ts.write error cho host %s: %s", host, e)
        raise HTTPException(status_code=422, detail=f"invalid metrics payload: {e}")

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO hosts (hostname, os, last_seen, status) VALUES (?,?,?,?)",
        (host, body.get("os", ""), body.get("timestamp", ""), "online")
    )
    conn.commit()
    conn.close()

    alerts = rule_engine.evaluate(host, metrics)
    anomalies = anomaly_detector.analyze(host, metrics)
    alerts.extend(anomalies)

    conns = metrics.get("network", {}).get("top_remote_ips", [])
    conn_list = [{"raddr": f"{ip}:0"} for ip, _ in conns]
    port_alerts = port_scan_det.check(conn_list)
    alerts.extend(port_alerts)

    if alerts:
        await asyncio.gather(
            *(dispatcher.dispatch(host, a) for a in alerts),
            return_exceptions=True,
        )

    # Sticky FIM/drift từ snapshot trước (nếu cycle này không gửi)
    prev = latest_metrics.get(host, {}).get("metrics", {})
    for sticky in ("fim", "drift"):
        if sticky not in metrics and sticky in prev:
            metrics[sticky] = prev[sticky]

    latest_metrics[host] = {
        "host": host,
        "timestamp": body.get("timestamp"),
        "metrics": metrics,
        "alerts": alerts,
    }
    await ws_manager.broadcast({"type": "metrics_update", "data": latest_metrics[host]})

    return {"status": "ok", "alerts_fired": len(alerts)}


# ─── Hosts / Alerts / Summary ────────────────────────────────────────────────

@app.get("/api/hosts")
async def get_hosts(request: Request):
    require_login(request)
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT hostname, os, last_seen, status FROM hosts ORDER BY hostname"
    ).fetchall()
    conn.close()
    return [{"hostname": r[0], "os": r[1], "last_seen": r[2], "status": r[3]}
            for r in rows]


@app.get("/api/metrics/{host}")
async def get_latest_metrics(host: str, request: Request):
    require_login(request)
    if host not in latest_metrics:
        raise HTTPException(status_code=404, detail="Host không tìm thấy")
    return latest_metrics[host]


@app.get("/api/metrics/{host}/series")
async def get_metrics_series(host: str, request: Request, hours: int = 24):
    """Trả về time-series CPU/MEM/Disk cho dashboard chart."""
    require_login(request)
    hours = max(1, min(hours, METRICS_RETENTION_HOURS))
    return {"host": host, "hours": hours,
            "series": metrics_ts.query_series(DB_PATH, host, hours)}


@app.get("/api/forecast/{host}")
async def get_forecast(host: str, request: Request, hours: int = 24):
    """
    Linear regression trên metrics_ts để dự đoán khi nào disk/memory chạm ngưỡng.
    Không tốn collector mới — chỉ tính từ data đã có sẵn.
    """
    require_login(request)
    hours = max(2, min(hours, METRICS_RETENTION_HOURS))
    series = metrics_ts.query_series(DB_PATH, host, hours)
    if len(series) < 10:
        raise HTTPException(status_code=400,
                             detail=f"Chưa đủ data (cần ≥10 mẫu, có {len(series)})")

    def _linreg(xs: list[float], ys: list[float]) -> tuple[float, float]:
        n = len(xs)
        mx = sum(xs) / n
        my = sum(ys) / n
        num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        den = sum((x - mx) ** 2 for x in xs)
        if den == 0:
            return 0.0, my
        slope = num / den
        intercept = my - slope * mx
        return slope, intercept

    def _predict(target_pct: float, current: float, slope_per_sec: float):
        """Số ngày dự kiến đến khi giá trị chạm target_pct."""
        if slope_per_sec <= 0 or current >= target_pct:
            return None
        seconds = (target_pct - current) / slope_per_sec
        return round(seconds / 86400, 1)

    ts = [float(r["ts"]) for r in series]
    disk = [float(r["disk_max"] or 0) for r in series]
    mem  = [float(r["mem"] or 0) for r in series]
    cpu  = [float(r["cpu"] or 0) for r in series]

    out = {"host": host, "samples": len(series), "hours_observed": hours,
            "disk": None, "memory": None, "cpu": None}

    for label, ys, target in (("disk", disk, 90.0),
                               ("memory", mem, 95.0),
                               ("cpu", cpu, 95.0)):
        slope, intercept = _linreg(ts, ys)
        current = ys[-1]
        slope_per_day = slope * 86400
        days = _predict(target, current, slope)
        sev = None
        if days is not None:
            if days < 2: sev = "critical"
            elif days < 7: sev = "warning"
        out[label] = {
            "current_pct": round(current, 1),
            "slope_per_day_pct": round(slope_per_day, 3),
            f"days_to_{int(target)}pct": days,
            "severity": sev,
        }
    return out


@app.get("/api/alerts")
async def get_alerts(request: Request, host: Optional[str] = None,
                     severity: Optional[str] = None, limit: int = 100):
    require_login(request)
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT id, host, type, severity, detail, timestamp FROM alerts WHERE 1=1"
    params = []
    if host:
        query += " AND host=?"; params.append(host)
    if severity:
        query += " AND severity=?"; params.append(severity)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [{"id": r[0], "host": r[1], "type": r[2], "severity": r[3],
             "detail": r[4], "timestamp": r[5]} for r in rows]


@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, request: Request):
    require_login(request)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return {"status": "resolved"}


@app.get("/api/summary")
async def get_summary(request: Request):
    require_login(request)
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    crit = conn.execute(
        "SELECT COUNT(DISTINCT host) FROM alerts WHERE severity='critical' "
        "AND timestamp > datetime('now','-1 hour') AND resolved=0"
    ).fetchone()[0]
    warn = conn.execute(
        "SELECT COUNT(DISTINCT host) FROM alerts WHERE severity='warning' "
        "AND timestamp > datetime('now','-1 hour') AND resolved=0"
    ).fetchone()[0]
    conn.close()
    return {"total_hosts": total, "online_hosts": len(latest_metrics),
            "critical_hosts": crit, "warning_hosts": warn}


@app.get("/api/baseline/{host}")
async def get_baseline(host: str, request: Request):
    require_login(request)
    report = anomaly_detector.get_baseline_report(host)
    if not report:
        raise HTTPException(status_code=404, detail="Chưa có baseline — cần ít nhất 30 mẫu")
    return report


# ─── Docker view ─────────────────────────────────────────────────────────────

@app.get("/api/docker/{host}")
async def get_docker_containers(host: str, request: Request):
    require_login(request)
    if host not in latest_metrics:
        raise HTTPException(status_code=404, detail="Host không tìm thấy")
    docker = latest_metrics[host].get("metrics", {}).get("docker", {})
    if not docker.get("available"):
        return {"available": False, "containers": [], "summary": {}}
    return docker


@app.get("/api/docker/{host}/{container_name}/logs")
async def get_container_logs(host: str, container_name: str, request: Request):
    require_login(request)
    if host not in latest_metrics:
        raise HTTPException(status_code=404, detail="Host không tìm thấy")
    docker = latest_metrics[host].get("metrics", {}).get("docker", {})
    for c in docker.get("containers", []):
        if c["name"] == container_name:
            return {
                "container": container_name,
                "recent_logs": c.get("recent_logs", []),
                "log_errors": c.get("log_errors", []),
                "error_count": c.get("log_error_count", 0),
                "dangerous": c.get("dangerous_activity", []),
            }
    raise HTTPException(status_code=404, detail=f"Container '{container_name}' không tìm thấy")


@app.get("/api/docker/summary")
async def get_docker_summary(request: Request):
    require_login(request)
    result = {}
    for host, data in latest_metrics.items():
        docker = data.get("metrics", {}).get("docker", {})
        if docker.get("available"):
            result[host] = docker.get("summary", {})
    return result


# ─── Silences / Alert states ─────────────────────────────────────────────────

@app.get("/api/silences")
async def api_list_silences(request: Request, include_expired: bool = False):
    require_admin(request)
    return {"silences": alert_state.list_silences(DB_PATH, include_expired)}


@app.post("/api/silences")
async def api_add_silence(request: Request):
    user = require_admin(request)
    body = await request.json()
    host_pattern = body.get("host_pattern", "*")
    type_pattern = body.get("type_pattern", "*")
    duration_sec = int(body.get("duration_sec", 3600))
    reason       = body.get("reason", "")
    if duration_sec <= 0 or duration_sec > 30 * 86400:
        raise HTTPException(status_code=400, detail="duration_sec phải trong (0, 30 ngày]")
    sid = alert_state.add_silence(DB_PATH, host_pattern, type_pattern,
                                   duration_sec, reason, user.get("email", ""))
    return {"id": sid, "status": "ok"}


@app.post("/api/silences/{sid}/remove")
async def api_remove_silence(sid: int, request: Request):
    require_admin(request)
    ok = alert_state.remove_silence(DB_PATH, sid)
    return {"status": "ok" if ok else "not_found"}


@app.get("/api/alert-states")
async def api_list_alert_states(request: Request, host: Optional[str] = None):
    require_admin(request)
    return {"alerts": alert_state.list_active_alerts(DB_PATH, host)}


@app.post("/api/alert-states/{fingerprint}/ack")
async def api_ack_alert(fingerprint: str, request: Request):
    user = require_admin(request)
    ok = alert_state.ack_alert(DB_PATH, fingerprint, user.get("email", ""))
    return {"status": "ok" if ok else "not_found"}


# ─── Monitors ────────────────────────────────────────────────────────────────

@app.get("/api/monitors")
async def api_list_monitors(request: Request):
    require_admin(request)
    return {"monitors": monitors_mod.list_monitors(DB_PATH)}


@app.post("/api/monitors")
async def api_add_monitor(request: Request):
    require_admin(request)
    body = await request.json()
    kind   = body.get("kind")
    target = body.get("target", "").strip()
    params = body.get("params", {})
    interval_sec = int(body.get("interval_sec", 3600))
    if not kind or not target:
        raise HTTPException(status_code=400, detail="Thiếu kind hoặc target")
    try:
        mid = monitors_mod.add_monitor(DB_PATH, kind, target, params, interval_sec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"id": mid, "status": "ok"}


@app.post("/api/monitors/{mid}/toggle")
async def api_toggle_monitor(mid: int, request: Request):
    require_admin(request)
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    ok = monitors_mod.set_enabled(DB_PATH, mid, enabled)
    return {"status": "ok" if ok else "not_found"}


@app.post("/api/monitors/{mid}/delete")
async def api_delete_monitor(mid: int, request: Request):
    require_admin(request)
    ok = monitors_mod.delete_monitor(DB_PATH, mid)
    return {"status": "ok" if ok else "not_found"}


@app.post("/api/monitors/{mid}/run")
async def api_run_monitor(mid: int, request: Request):
    require_admin(request)
    mons = [m for m in monitors_mod.list_monitors(DB_PATH) if m["id"] == mid]
    if not mons:
        raise HTTPException(status_code=404, detail="Monitor không tìm thấy")
    result = await monitors_mod.run_monitor(DB_PATH, mons[0])
    return result


@app.get("/api/monitors/{mid}/results")
async def api_monitor_results(mid: int, request: Request, limit: int = 50):
    require_admin(request)
    return {"results": monitors_mod.recent_results(DB_PATH, mid, limit)}


# ─── Settings ────────────────────────────────────────────────────────────────

@app.get("/api/settings")
async def api_list_settings(request: Request):
    require_admin(request)
    return {"settings": settings_mod.list_all(DB_PATH)}


@app.post("/api/settings")
async def api_set_settings(request: Request):
    user = require_admin(request)
    body = await request.json()
    updates = body.get("updates")
    if updates is None:
        updates = [{"key": body.get("key"), "value": body.get("value", "")}]
    count = 0
    errors = []
    for u in updates:
        key = u.get("key", "")
        val = u.get("value", "")
        if not key:
            continue
        if key not in settings_mod.SCHEMA_BY_KEY:
            errors.append(f"{key}: không trong schema")
            continue
        settings_mod.set_value(DB_PATH, key, str(val), user.get("email", ""))
        count += 1
    return {"updated": count, "errors": errors}


@app.post("/api/settings/{key}/delete")
async def api_delete_setting(key: str, request: Request):
    require_admin(request)
    if key not in settings_mod.SCHEMA_BY_KEY:
        raise HTTPException(status_code=400, detail="key không trong schema")
    ok = settings_mod.delete(DB_PATH, key)
    return {"status": "ok" if ok else "not_found"}


@app.post("/api/settings/test/telegram")
async def api_test_telegram(request: Request):
    require_admin(request)
    await dispatcher.send_telegram("test", {
        "type": "test", "severity": "info",
        "detail": "Test message từ dashboard — config Telegram hoạt động.",
    })
    token = settings_mod.get(DB_PATH, "telegram.bot_token", "")
    chat  = settings_mod.get(DB_PATH, "telegram.chat_id", "")
    return {"status": "sent" if (token and chat) else "skipped",
            "token_set": bool(token), "chat_id_set": bool(chat)}


@app.post("/api/settings/test/email")
async def api_test_email(request: Request):
    require_admin(request)
    try:
        dispatcher.send_email("test", {
            "type": "test", "severity": "critical",
            "detail": "Test email từ ServerWatch dashboard.",
        })
        return {"status": "sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email test fail: {e}")


# ─── Users ───────────────────────────────────────────────────────────────────

@app.get("/api/users")
async def api_list_users(request: Request):
    require_admin(request)
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, email, name, role, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return {"users": [
        {"id": r[0], "email": r[1], "name": r[2], "role": r[3],
         "created_at": r[4], "last_login": r[5]} for r in rows
    ]}


@app.post("/api/users")
async def api_create_user(request: Request):
    require_admin(request)
    body = await request.json()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    name = body.get("name", "")
    role = body.get("role", "viewer")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Thiếu email hoặc password")
    if role not in ("viewer", "operator", "admin"):
        raise HTTPException(status_code=400, detail="Role không hợp lệ")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password tối thiểu 6 ký tự")
    pw_hash, salt = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO users (email, password, salt, name, role, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (email, pw_hash, salt, name, role,
             datetime.now(timezone.utc).isoformat())
        )
        uid = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Email đã tồn tại")
    conn.close()
    return {"id": uid, "status": "ok"}


@app.post("/api/users/{uid}/role")
async def api_update_role(uid: int, request: Request):
    user = require_admin(request)
    body = await request.json()
    role = body.get("role", "")
    if role not in ("viewer", "operator", "admin"):
        raise HTTPException(status_code=400, detail="Role không hợp lệ")
    if uid == user.get("uid"):
        raise HTTPException(status_code=400, detail="Không thể đổi role của chính mình")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    conn.commit()
    conn.close()
    return {"status": "ok" if cur.rowcount else "not_found"}


@app.post("/api/users/{uid}/delete")
async def api_delete_user(uid: int, request: Request):
    user = require_admin(request)
    if uid == user.get("uid"):
        raise HTTPException(status_code=400, detail="Không thể xóa chính mình")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    return {"status": "ok" if cur.rowcount else "not_found"}


# ─── Backup ──────────────────────────────────────────────────────────────────

@app.get("/api/backup/list")
async def api_backup_list(request: Request):
    require_admin(request)
    return {
        "backups": backup_mod.list_backups(BACKUP_DIR),
        "retention_days": BACKUP_RETENTION_DAYS,
        "backup_dir": str(BACKUP_DIR),
        "schedule_utc": f"daily {BACKUP_HOUR_UTC:02d}:00, verify weekday={BACKUP_VERIFY_DAY}",
    }


async def _run_backup_bg(by_user: str):
    _backup_state["running"] = True
    _backup_state["last_error"] = None
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None,
            lambda: backup_mod.run_backup(
                DB_PATH, _data_dir, BACKUP_DIR, hmac_key=BACKUP_HMAC_SECRET,
            )
        )
        _backup_state["last_result"] = {
            "name": result["name"], "bytes": result["bytes"],
            "created_at": result["created_at"],
        }
        log.info("Manual backup OK: %s (%d bytes)", result["name"], result["bytes"])
    except Exception as e:
        log.error("Manual backup fail: %s", e, exc_info=True)
        _backup_state["last_error"] = str(e)
    finally:
        _backup_state["running"] = False


@app.post("/api/backup/run")
async def api_backup_run(request: Request):
    user = require_admin(request)
    if _backup_state.get("running"):
        raise HTTPException(status_code=409, detail="Đang có backup khác chạy")
    asyncio.create_task(_run_backup_bg(user.get("email", "unknown")))
    return {"status": "started"}


@app.get("/api/backup/status")
async def api_backup_status(request: Request):
    require_admin(request)
    return _backup_state


@app.post("/api/backup/{name}/verify")
async def api_backup_verify(name: str, request: Request):
    require_admin(request)
    if "/" in name or ".." in name or not name.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Name không hợp lệ")
    path = BACKUP_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup không tồn tại")
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: backup_mod.verify_backup(path, BACKUP_HMAC_SECRET)
    )


@app.post("/api/backup/{name}/delete")
async def api_backup_delete(name: str, request: Request):
    require_admin(request)
    if "/" in name or ".." in name or not name.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Name không hợp lệ")
    path = BACKUP_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup không tồn tại")
    path.unlink()
    return {"status": "ok"}


@app.get("/api/backup/{name}/download")
async def api_backup_download(name: str, request: Request):
    require_admin(request)
    if "/" in name or ".." in name or not name.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Name không hợp lệ")
    path = BACKUP_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup không tồn tại")
    return FileResponse(path, media_type="application/gzip", filename=name)


# ─── Heartbeat / Health ──────────────────────────────────────────────────────

@app.get("/api/heartbeat")
async def api_heartbeat(secret: str = ""):
    # Bắt buộc HEARTBEAT_SECRET phải được cấu hình — trước đây nếu để trống,
    # bất kỳ ai cũng query được fresh_hosts + firing_alerts (reconnaissance).
    if not HEARTBEAT_SECRET or not hmac.compare_digest(secret, HEARTBEAT_SECRET):
        raise HTTPException(status_code=403, detail="Bad secret")
    now = datetime.now(timezone.utc)
    checks = {}
    ok = True

    stale_cutoff = (now - timedelta(minutes=5)).isoformat()
    fresh_hosts = [h for h, m in latest_metrics.items()
                   if (m.get("timestamp") or "") > stale_cutoff]
    checks["fresh_hosts"] = len(fresh_hosts)
    if not fresh_hosts:
        ok = False

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("SELECT 1").fetchone()
        conn.close()
        checks["sqlite"] = "ok"
    except Exception as e:
        checks["sqlite"] = f"fail: {e}"
        ok = False

    try:
        checks["firing_alerts"] = len(alert_state.list_active_alerts(DB_PATH))
    except Exception:
        checks["firing_alerts"] = -1

    return JSONResponse(
        status_code=200 if ok else 503,
        content={"status": "ok" if ok else "degraded",
                 "timestamp": now.isoformat(), "checks": checks},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "hosts_online": len(latest_metrics)}


@app.post("/api/logs/ingest")
async def api_logs_ingest_compat():
    """Compat stub cho agent cũ còn LogShipper. Im lặng accept để hết spam 404."""
    return JSONResponse(status_code=204, content=None)


# ─── WebSocket ───────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    token = ws.query_params.get("token", "")
    user = verify_jwt(token) if token else None
    if not user:
        await ws.close(code=4001, reason="Unauthorized")
        return
    await ws_manager.connect(ws)
    await ws.send_json({"type": "snapshot", "data": latest_metrics})
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ─── Dashboard ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)
