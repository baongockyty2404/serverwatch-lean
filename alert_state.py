"""
Alert state tracking: dedup, fingerprinting, silence windows.

Ý tưởng:
  - Mỗi alert có fingerprint = sha1(host|type|key) → xác định "cùng sự cố"
  - State machine: firing → resolved. Chỉ notify khi state đổi.
  - Silence window: cho phép mute alert theo (host, type_pattern) trong khoảng thời gian.

Tables:
  - alert_states       (fingerprint PK, host, type, severity, detail, first_seen,
                        last_seen, last_notified, state, occurrences)
  - silences           (id PK, host_pattern, type_pattern, reason, created_by,
                        created_at, expires_at, active)

Quy ước pattern (host_pattern / type_pattern):
  - "*"      → match tất cả
  - "web-*"  → glob (fnmatch)
  - "web-01" → exact
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alert_states (
    fingerprint    TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    type           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    detail         TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    last_notified  TEXT,
    state          TEXT NOT NULL DEFAULT 'firing',   -- firing|resolved
    occurrences    INTEGER DEFAULT 1,
    resolved_at    TEXT,
    ack_by         TEXT,
    ack_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_states_host  ON alert_states(host);
CREATE INDEX IF NOT EXISTS idx_alert_states_state ON alert_states(state);

CREATE TABLE IF NOT EXISTS silences (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_pattern   TEXT NOT NULL DEFAULT '*',
    type_pattern   TEXT NOT NULL DEFAULT '*',
    reason         TEXT,
    created_by     TEXT,
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    active         INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_silences_active ON silences(active, expires_at);
"""


# ── Đăng ký key phụ từ alert để phân biệt alert same-type nhưng khác context ──
# Ví dụ: "disk_full" trên /var vs /home phải là 2 fingerprint khác nhau.
def _alert_context_key(alert: dict) -> str:
    t = alert.get("type", "")
    detail = alert.get("detail", "") or ""
    # Heuristic: dùng phần "định danh" cụ thể trong detail nếu có
    # - docker: "Container 'sw-server' ..." → sw-server
    # - disk:   "Disk /var = 91%"           → /var
    # - ddos:   "IP 1.2.3.4 ..."             → 1.2.3.4
    # Nếu không match, fallback "": mỗi (host, type) là 1 fingerprint
    import re
    patterns = [
        (r"Container '([^']+)'", 1),
        (r"Disk (/\S+)",          1),
        (r"\bIP ([\d.]+)",        1),
        (r"mount ([^\s,]+)",       1),
    ]
    for pat, grp in patterns:
        m = re.search(pat, detail)
        if m:
            return m.group(grp)
    return ""


def compute_fingerprint(host: str, alert: dict) -> str:
    key = f"{host}|{alert.get('type','')}|{_alert_context_key(alert)}"
    return hashlib.sha1(key.encode()).hexdigest()


def init_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Dedup / state management
# ═══════════════════════════════════════════════════════════════════════════════

def record_and_check(
    db_path: str,
    host: str,
    alert: dict,
    renotify_after_sec: int = 3600,
) -> tuple[bool, str]:
    """
    Ghi nhận alert + quyết định có notify không.

    Trả về (should_notify, fingerprint).

    Quy tắc:
      - Alert chưa có trong state_table → notify, lưu state=firing.
      - Alert đã firing, lần trước notify < renotify_after_sec → KHÔNG notify (dedup).
      - Alert đã firing nhưng > renotify_after_sec → notify lại (re-flare).
      - Alert đã resolved → notify (tái phát), đổi state về firing.
    """
    fp = compute_fingerprint(host, alert)
    now = datetime.now(timezone.utc).isoformat()
    now_ts = time.time()

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT state, last_notified, occurrences FROM alert_states WHERE fingerprint=?",
        (fp,)
    ).fetchone()

    if row is None:
        # Lần đầu thấy
        conn.execute(
            """INSERT INTO alert_states
               (fingerprint, host, type, severity, detail, first_seen, last_seen,
                last_notified, state, occurrences)
               VALUES (?,?,?,?,?,?,?,?,?,1)""",
            (fp, host, alert.get("type", ""), alert.get("severity", "info"),
             alert.get("detail", ""), now, now, now, "firing")
        )
        conn.commit()
        conn.close()
        return True, fp

    state, last_notified, occurrences = row
    should_notify = False

    if state == "resolved":
        # Tái phát — notify lại, reset state
        should_notify = True
    else:
        # firing → check thời điểm notify gần nhất
        if last_notified:
            try:
                last_ts = datetime.fromisoformat(last_notified).timestamp()
            except Exception:
                last_ts = 0
            if (now_ts - last_ts) >= renotify_after_sec:
                should_notify = True

    conn.execute(
        """UPDATE alert_states SET
             severity=?, detail=?, last_seen=?, state='firing',
             occurrences=occurrences+1,
             last_notified=CASE WHEN ?=1 THEN ? ELSE last_notified END,
             resolved_at=NULL
           WHERE fingerprint=?""",
        (alert.get("severity", "info"), alert.get("detail", ""), now,
         1 if should_notify else 0, now, fp)
    )
    conn.commit()
    conn.close()
    return should_notify, fp


def auto_resolve_stale(db_path: str, stale_after_sec: int = 900) -> list[dict]:
    """
    Đánh dấu resolved các alert "firing" mà không được update trong `stale_after_sec` giây.

    Trả về danh sách alert vừa auto-resolve để notify "đã giải quyết".
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_sec)).isoformat()
    now = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        """SELECT fingerprint, host, type, severity, detail, occurrences
           FROM alert_states
           WHERE state='firing' AND last_seen < ?""",
        (cutoff,)
    ).fetchall()

    resolved = []
    for fp, host, atype, sev, detail, occ in rows:
        conn.execute(
            "UPDATE alert_states SET state='resolved', resolved_at=? WHERE fingerprint=?",
            (now, fp)
        )
        resolved.append({
            "fingerprint": fp, "host": host, "type": atype,
            "severity": sev, "detail": detail, "occurrences": occ,
        })
    conn.commit()
    conn.close()
    return resolved


def list_active_alerts(db_path: str, host: Optional[str] = None) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if host:
        rows = conn.execute(
            """SELECT * FROM alert_states
               WHERE state='firing' AND host=?
               ORDER BY last_seen DESC""",
            (host,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alert_states WHERE state='firing' ORDER BY last_seen DESC"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def ack_alert(db_path: str, fingerprint: str, user: str) -> bool:
    """Đánh dấu alert đã được xác nhận (acknowledged). Dùng cho on-call."""
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "UPDATE alert_states SET ack_by=?, ack_at=? WHERE fingerprint=? AND state='firing'",
        (user, now, fingerprint)
    )
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    return ok


# ═══════════════════════════════════════════════════════════════════════════════
# Silence windows
# ═══════════════════════════════════════════════════════════════════════════════

def add_silence(
    db_path: str,
    host_pattern: str,
    type_pattern: str,
    duration_sec: int,
    reason: str,
    created_by: str,
) -> int:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=duration_sec)
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        """INSERT INTO silences (host_pattern, type_pattern, reason, created_by,
                                  created_at, expires_at, active)
           VALUES (?,?,?,?,?,?,1)""",
        (host_pattern or "*", type_pattern or "*", reason, created_by,
         now.isoformat(), expires.isoformat())
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return sid


def list_silences(db_path: str, include_expired: bool = False) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if include_expired:
        rows = conn.execute("SELECT * FROM silences ORDER BY created_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM silences WHERE active=1 AND expires_at > ? ORDER BY expires_at",
            (now,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def remove_silence(db_path: str, silence_id: int) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.execute("UPDATE silences SET active=0 WHERE id=?", (silence_id,))
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    return ok


def is_silenced(db_path: str, host: str, alert_type: str) -> Optional[dict]:
    """Trả về silence rule match đầu tiên, hoặc None."""
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM silences WHERE active=1 AND expires_at > ?",
        (now,)
    ).fetchall()
    conn.close()
    for r in rows:
        if fnmatch.fnmatch(host, r["host_pattern"]) and \
           fnmatch.fnmatch(alert_type, r["type_pattern"]):
            return dict(r)
    return None
