"""
Synthetic monitors: SSL certificate expiry, domain (WHOIS) expiry, HTTP/TCP probes.

Chạy background task trên server (không cần agent). Mỗi monitor:
  - kind="cert"   → parse x509 via TLS handshake → not_after
  - kind="domain" → whois TCP query → expires
  - kind="http"   → HTTP GET status + latency
  - kind="tcp"    → TCP connect test

Tables:
  - monitors          (id, kind, target, params, interval_sec, created_at, enabled)
  - monitor_results   (id, monitor_id, checked_at, status, latency_ms, detail, expires_in_days)

Alert khi:
  - cert hoặc domain còn < WARN_DAYS / CRIT_DAYS
  - http/tcp probe fail hoặc latency > ngưỡng
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import sqlite3
import ssl
import time
import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

import aiohttp


# SSRF guardrail — chặn admin tạo monitor trỏ vào internal/loopback/metadata IPs.
# Synthetic monitors chạy trong sw-server container nên có thể probe sang
# container khác cùng Docker network, host gateway, cloud metadata (169.254.169.254).
# Trước khi fix: 1 admin compromise → đầy đủ SSRF capability (DNS probe, port scan,
# limited info leak qua latency + error message). Block ở cả CRUD + probe runtime.
_BLOCKED_HOSTNAMES = {
    # Loopback aliases
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    # Cloud metadata endpoints
    "metadata.google.internal", "metadata", "metadata.azure.com",
    # Docker DNS shortcuts
    "host.docker.internal", "gateway.docker.internal",
    "docker.for.mac.localhost", "docker.for.win.localhost",
}

def _is_blocked_target(target: str) -> tuple[bool, str]:
    """
    Trả về (blocked, reason). Áp dụng cho host của cert/tcp và URL của http.
    Block private (RFC1918), loopback, link-local (incl AWS metadata 169.254.169.254),
    multicast, reserved, và list hostnames đặc biệt.
    """
    if not target:
        return True, "empty target"

    # Trích host từ URL nếu có scheme
    host = target.strip()
    if "://" in host:
        try:
            parsed = urlparse(host)
            host = (parsed.hostname or "").strip()
        except Exception:
            return True, "invalid URL"

    if not host:
        return True, "empty host"

    if host.lower() in _BLOCKED_HOSTNAMES:
        return True, f"hostname '{host}' blocked"

    # Try parse như IP literal
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:    return True, f"{ip} is loopback"
        if ip.is_private:     return True, f"{ip} is private (RFC1918)"
        if ip.is_link_local:  return True, f"{ip} is link-local (incl cloud metadata)"
        if ip.is_multicast:   return True, f"{ip} is multicast"
        if ip.is_reserved:    return True, f"{ip} is reserved"
        if ip.is_unspecified: return True, f"{ip} is unspecified (0.0.0.0)"
    except ValueError:
        # Không phải IP literal — là hostname. Kiểm tra qua DNS resolve.
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            # DNS không resolve được → cho qua (probe sẽ tự fail). Không nên
            # block ở đây vì có thể chỉ là transient DNS issue.
            return False, ""
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if ip.is_loopback or ip.is_private or ip.is_link_local \
                    or ip.is_multicast or ip.is_reserved:
                return True, f"hostname '{host}' resolves to internal IP {ip}"

    return False, ""


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS monitors (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,             -- cert|domain|http|tcp
    target         TEXT NOT NULL,             -- hostname hoặc URL
    params         TEXT DEFAULT '{}',         -- JSON: port, method, timeout, status_expect
    interval_sec   INTEGER DEFAULT 3600,
    enabled        INTEGER DEFAULT 1,
    created_at     TEXT NOT NULL,
    last_checked   TEXT,
    last_status    TEXT,                      -- ok|warning|critical|error
    last_detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_monitors_enabled ON monitors(enabled);

CREATE TABLE IF NOT EXISTS monitor_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id       INTEGER NOT NULL,
    checked_at       TEXT NOT NULL,
    status           TEXT NOT NULL,
    latency_ms       REAL,
    detail           TEXT,
    expires_in_days  INTEGER,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id)
);
CREATE INDEX IF NOT EXISTS idx_monitor_results_mid_ts ON monitor_results(monitor_id, checked_at);
"""

# Ngưỡng cảnh báo expiry (ngày)
WARN_DAYS = 30
CRIT_DAYS = 7

# Giới hạn số kết quả giữ lại mỗi monitor
RESULT_RETENTION = 200


def init_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Probes
# ═══════════════════════════════════════════════════════════════════════════════

async def check_cert(hostname: str, port: int = 443, timeout: float = 8) -> dict:
    """Kết nối TLS, lấy certificate, trả về days_remaining."""
    loop = asyncio.get_event_loop()
    start = time.time()

    def _handshake():
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()

    try:
        cert = await asyncio.wait_for(loop.run_in_executor(None, _handshake),
                                       timeout=timeout + 2)
    except Exception as e:
        return {"status": "error", "detail": f"TLS failed: {e}",
                "latency_ms": (time.time() - start) * 1000}

    not_after = cert.get("notAfter", "")
    try:
        # Format: "Sep 17 03:25:00 2026 GMT"
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return {"status": "error", "detail": f"parse cert date: {not_after}",
                "latency_ms": (time.time() - start) * 1000}

    days = (exp - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))

    if days < 0:
        status = "critical"
        detail = f"CERT ĐÃ HẾT HẠN {-days} ngày trước"
    elif days <= CRIT_DAYS:
        status = "critical"
        detail = f"Cert hết hạn sau {days} ngày"
    elif days <= WARN_DAYS:
        status = "warning"
        detail = f"Cert còn {days} ngày"
    else:
        status = "ok"
        detail = f"OK — hết hạn {exp.date().isoformat()} (còn {days} ngày)"

    return {
        "status": status,
        "detail": detail,
        "expires_in_days": days,
        "expires_at": exp.isoformat(),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "subject_cn": subject.get("commonName", ""),
        "latency_ms": (time.time() - start) * 1000,
    }


# WHOIS servers phổ biến theo TLD
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",          "io":  "whois.nic.io",
    "vn":  "whois.vnnic.vn",         "info": "whois.afilias.net",
    "co":  "whois.nic.co",           "dev": "whois.nic.google",
    "app": "whois.nic.google",       "ai":  "whois.nic.ai",
}


RDAP_HEADERS = {
    "User-Agent": "ServerWatch/1.0 (RDAP client)",
    "Accept":     "application/rdap+json, application/json",
}

# Thứ tự RDAP endpoints. IANA bootstrap chỉ có gTLD chính thức.
# rdap.org là third-party aggregator phủ rộng hơn (gồm nhiều ccTLD).
RDAP_ENDPOINTS = [
    "https://rdap.iana.org/domain/{}",
    "https://rdap.org/domain/{}",
]


async def _rdap_lookup(domain: str, timeout: float = 10) -> tuple[Optional[datetime], Optional[str]]:
    """
    Tra cứu expiry qua RDAP (Registration Data Access Protocol).
    RDAP chạy HTTPS:443 → hoạt động ngay cả khi firewall chặn port 43.

    Trả về (datetime expiration, source_url) hoặc (None, last_status_msg).
    """
    last_msg = "không endpoint nào trả expiration"
    async with aiohttp.ClientSession(headers=RDAP_HEADERS) as sess:
        for tmpl in RDAP_ENDPOINTS:
            url = tmpl.format(domain)
            try:
                async with sess.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                       allow_redirects=True) as resp:
                    if resp.status == 404:
                        last_msg = f"{url} → 404 (TLD không hỗ trợ)"
                        continue
                    if resp.status != 200:
                        last_msg = f"{url} → HTTP {resp.status}"
                        continue
                    try:
                        data = await resp.json(content_type=None)
                    except Exception:
                        last_msg = f"{url} → JSON parse fail"
                        continue
            except asyncio.TimeoutError:
                last_msg = f"{url} → timeout"
                continue
            except Exception as e:
                last_msg = f"{url} → {type(e).__name__}"
                continue

            for event in data.get("events", []):
                if event.get("eventAction") in ("expiration", "registrar expiration"):
                    raw = event.get("eventDate", "")
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
                        try:
                            dt = datetime.strptime(raw, fmt)
                            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None \
                                else dt.astimezone(timezone.utc)
                            return dt, url
                        except ValueError:
                            continue
    return None, last_msg


def _whois_tcp(domain: str, server: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{domain}\r\n".encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="ignore")


async def check_domain(domain: str, timeout: float = 10) -> dict:
    """
    Tìm expiry date của domain.
    Thứ tự thử:
      1. RDAP (HTTPS:443) — modern, hoạt động qua firewall
      2. WHOIS TCP:43 fallback (nếu port 43 outbound mở)
    """
    start = time.time()
    exp = None
    method = None
    rdap_msg = ""

    # 1. Thử RDAP trước (HTTPS:443, hoạt động sau firewall)
    exp, rdap_info = await _rdap_lookup(domain, timeout)
    if exp:
        method = "rdap"
        rdap_msg = f" via {rdap_info.split('/')[2]}" if rdap_info else ""
    else:
        rdap_msg = f" RDAP: {rdap_info}"

    # 2. Fallback WHOIS TCP nếu RDAP fail
    if not exp:
        loop = asyncio.get_event_loop()
        tld = domain.rsplit(".", 1)[-1].lower()
        whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")
        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(None, _whois_tcp, domain, whois_server, timeout),
                timeout=timeout + 2
            )
            # Follow refer
            refer = re.search(r"Registrar WHOIS Server:\s*(\S+)", response, re.IGNORECASE)
            if refer:
                try:
                    response2 = await asyncio.wait_for(
                        loop.run_in_executor(None, _whois_tcp, domain,
                                              refer.group(1).strip(), timeout),
                        timeout=timeout + 2
                    )
                    if response2 and len(response2) > len(response):
                        response = response2
                except Exception:
                    pass

            patterns = [
                r"Registry Expiry Date:\s*(\S+)",
                r"Expiration Date:\s*(\S+)",
                r"Registrar Registration Expiration Date:\s*(\S+)",
                r"expires?:\s*(\S+)",
                r"paid-till:\s*(\S+)",
                r"Expiry [Dd]ate:\s*(\S+)",
            ]
            for p in patterns:
                m = re.search(p, response, re.IGNORECASE)
                if not m:
                    continue
                raw = m.group(1).strip()
                for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                            "%d-%b-%Y", "%d.%m.%Y"):
                    try:
                        exp = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                        method = "whois"
                        break
                    except ValueError:
                        continue
                if exp:
                    break
        except Exception as e:
            return {
                "status": "error",
                "detail": f"RDAP + WHOIS đều fail.{rdap_msg}; WHOIS:{e}",
                "latency_ms": (time.time() - start) * 1000,
            }

    if not exp:
        # Một số ccTLD (như .vn) không có RDAP công khai và WHOIS server bị
        # firewall chặn từ data center → không thể tự kiểm tra. User cần config
        # API key 3rd-party (whoisxmlapi/whoisfreaks) hoặc theo dõi thủ công.
        return {
            "status": "error",
            "detail": f"Không parse được expiry.{rdap_msg}. "
                       f"TLD này (.{domain.rsplit('.',1)[-1]}) có thể không hỗ trợ RDAP "
                       f"và WHOIS server không reachable.",
            "latency_ms": (time.time() - start) * 1000,
        }

    days = (exp - datetime.now(timezone.utc)).days
    if days < 0:
        status, detail = "critical", f"DOMAIN ĐÃ HẾT HẠN {-days} ngày trước"
    elif days <= CRIT_DAYS:
        status, detail = "critical", f"Domain hết hạn sau {days} ngày"
    elif days <= WARN_DAYS:
        status, detail = "warning",  f"Domain còn {days} ngày"
    else:
        status, detail = "ok",       f"OK — hết hạn {exp.date().isoformat()} ({days}d via {method}{rdap_msg})"

    return {
        "status": status,
        "detail": detail,
        "expires_in_days": days,
        "expires_at": exp.isoformat(),
        "method": method,
        "latency_ms": (time.time() - start) * 1000,
    }


async def check_http(url: str, method: str = "GET", timeout: float = 10,
                     expect_status: int = 200) -> dict:
    start = time.time()
    try:
        async with aiohttp.ClientSession() as sess:
            async with sess.request(method, url,
                                    timeout=aiohttp.ClientTimeout(total=timeout),
                                    allow_redirects=True) as resp:
                status_code = resp.status
                latency = (time.time() - start) * 1000
                if status_code == expect_status:
                    return {"status": "ok",
                            "detail": f"HTTP {status_code} ({latency:.0f}ms)",
                            "latency_ms": latency,
                            "status_code": status_code}
                severity = "critical" if status_code >= 500 else "warning"
                return {"status": severity,
                        "detail": f"HTTP {status_code} (expected {expect_status})",
                        "latency_ms": latency,
                        "status_code": status_code}
    except asyncio.TimeoutError:
        return {"status": "critical", "detail": f"Timeout sau {timeout}s",
                "latency_ms": (time.time() - start) * 1000}
    except Exception as e:
        return {"status": "critical", "detail": f"{type(e).__name__}: {e}",
                "latency_ms": (time.time() - start) * 1000}


async def check_tcp(host: str, port: int, timeout: float = 5) -> dict:
    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        latency = (time.time() - start) * 1000
        return {"status": "ok",
                "detail": f"TCP {host}:{port} OK ({latency:.0f}ms)",
                "latency_ms": latency}
    except asyncio.TimeoutError:
        return {"status": "critical", "detail": f"TCP timeout {timeout}s",
                "latency_ms": (time.time() - start) * 1000}
    except Exception as e:
        return {"status": "critical", "detail": f"TCP lỗi: {e}",
                "latency_ms": (time.time() - start) * 1000}


# ═══════════════════════════════════════════════════════════════════════════════
# CRUD
# ═══════════════════════════════════════════════════════════════════════════════

def add_monitor(db_path: str, kind: str, target: str,
                params: Optional[dict] = None,
                interval_sec: int = 3600) -> int:
    if kind not in ("cert", "domain", "http", "tcp"):
        raise ValueError(f"kind không hợp lệ: {kind}")
    # SSRF block: cert/tcp/http probe sẽ chạy từ trong sw-server container và
    # có thể với tới internal services. domain (RDAP/WHOIS) đi qua URL cố định
    # nên không cần check target.
    if kind in ("cert", "tcp", "http"):
        blocked, reason = _is_blocked_target(target)
        if blocked:
            raise ValueError(f"target bị chặn (SSRF guard): {reason}")
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        """INSERT INTO monitors (kind, target, params, interval_sec, enabled, created_at)
           VALUES (?,?,?,?,1,?)""",
        (kind, target, json.dumps(params or {}), interval_sec,
         datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    mid = cur.lastrowid
    conn.close()
    return mid


def list_monitors(db_path: str, enabled_only: bool = False) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    q = "SELECT * FROM monitors"
    if enabled_only:
        q += " WHERE enabled=1"
    q += " ORDER BY id"
    rows = conn.execute(q).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_monitor(db_path: str, mid: int) -> bool:
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM monitor_results WHERE monitor_id=?", (mid,))
    cur = conn.execute("DELETE FROM monitors WHERE id=?", (mid,))
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    return ok


def set_enabled(db_path: str, mid: int, enabled: bool) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.execute("UPDATE monitors SET enabled=? WHERE id=?",
                       (1 if enabled else 0, mid))
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    return ok


def recent_results(db_path: str, mid: int, limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM monitor_results WHERE monitor_id=? ORDER BY id DESC LIMIT ?",
        (mid, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
# Scheduler loop
# ═══════════════════════════════════════════════════════════════════════════════

async def run_monitor(db_path: str, monitor: dict) -> dict:
    kind = monitor["kind"]
    target = monitor["target"]
    params = json.loads(monitor.get("params") or "{}")

    if kind == "cert":
        result = await check_cert(target, port=params.get("port", 443))
    elif kind == "domain":
        result = await check_domain(target)
    elif kind == "http":
        result = await check_http(target,
                                  method=params.get("method", "GET"),
                                  timeout=params.get("timeout", 10),
                                  expect_status=params.get("expect_status", 200))
    elif kind == "tcp":
        result = await check_tcp(target, port=params.get("port", 80),
                                  timeout=params.get("timeout", 5))
    else:
        result = {"status": "error", "detail": f"kind không hỗ trợ: {kind}"}

    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO monitor_results (monitor_id, checked_at, status, latency_ms, detail, expires_in_days)
           VALUES (?,?,?,?,?,?)""",
        (monitor["id"], now, result.get("status", "error"),
         result.get("latency_ms"), result.get("detail", ""),
         result.get("expires_in_days"))
    )
    conn.execute(
        """UPDATE monitors SET last_checked=?, last_status=?, last_detail=? WHERE id=?""",
        (now, result.get("status", "error"), result.get("detail", ""), monitor["id"])
    )
    # Trim kết quả cũ
    conn.execute(
        """DELETE FROM monitor_results WHERE monitor_id=? AND id NOT IN
           (SELECT id FROM monitor_results WHERE monitor_id=? ORDER BY id DESC LIMIT ?)""",
        (monitor["id"], monitor["id"], RESULT_RETENTION)
    )
    conn.commit()
    conn.close()

    result["monitor_id"] = monitor["id"]
    result["kind"] = kind
    result["target"] = target
    return result


async def scheduler_loop(db_path: str, on_result=None):
    """
    Vòng lặp chính: mỗi 60s check monitor nào đến hạn thì chạy.
    `on_result(monitor_dict, result_dict)` được gọi sau mỗi lần check (để dispatch alert).
    """
    from collections import defaultdict
    last_run: dict = defaultdict(float)

    while True:
        try:
            monitors = list_monitors(db_path, enabled_only=True)
            now_ts = time.time()
            tasks = []
            to_run = []
            for m in monitors:
                if now_ts - last_run[m["id"]] >= m.get("interval_sec", 3600):
                    last_run[m["id"]] = now_ts
                    to_run.append(m)
                    tasks.append(run_monitor(db_path, m))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for m, r in zip(to_run, results):
                    if isinstance(r, Exception):
                        continue
                    if on_result:
                        try:
                            await on_result(m, r)
                        except Exception:
                            pass
        except Exception:
            pass
        await asyncio.sleep(60)
