"""
metrics_ts — time-series metrics lưu trong SQLite, thay cho InfluxDB.

Chỉ giữ snapshot tóm gọn (cpu/mem/disk/net) trong khoảng RETENTION_HOURS.
Mỗi push từ agent ghi 1 row + 1 row per docker-container nếu có.

Không thiết kế cho khối lượng lớn (>100 host). Cho setup nhỏ thì rẻ hơn,
gọn hơn InfluxDB và không tốn 1 GB RAM cho TSDB riêng.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metrics_ts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT    NOT NULL,
    ts            INTEGER NOT NULL,
    cpu           REAL,
    mem           REAL,
    disk_max      REAL,
    net_recv_mb   REAL,
    net_sent_mb   REAL,
    connections   INTEGER,
    proc_count    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_metrics_ts_host_ts ON metrics_ts(host, ts);

CREATE TABLE IF NOT EXISTS docker_ts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT    NOT NULL,
    ts            INTEGER NOT NULL,
    container     TEXT    NOT NULL,
    cpu_percent   REAL,
    mem_percent   REAL,
    restart_count INTEGER
);
CREATE INDEX IF NOT EXISTS idx_docker_ts_host_ts ON docker_ts(host, ts);
"""


def init_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def write(db_path: str, host: str, metrics: dict) -> None:
    ts = int(time.time())
    cpu = float(metrics.get("cpu", {}).get("percent", 0) or 0)
    mem = float(metrics.get("memory", {}).get("percent", 0) or 0)
    disk_max = max(
        (float(d.get("percent", 0) or 0) for d in metrics.get("disk", [])),
        default=0.0,
    )
    net = metrics.get("network", {}) or {}
    proc_count = len(metrics.get("processes", []) or [])

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO metrics_ts "
        "(host, ts, cpu, mem, disk_max, net_recv_mb, net_sent_mb, connections, proc_count) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (host, ts, cpu, mem, disk_max,
         float(net.get("bytes_recv_mb", 0) or 0),
         float(net.get("bytes_sent_mb", 0) or 0),
         int(net.get("connections", 0) or 0),
         proc_count),
    )

    docker = metrics.get("docker", {}) or {}
    if docker.get("available"):
        rows = []
        for c in docker.get("containers", []):
            if c.get("state") != "running":
                continue
            rows.append((
                host, ts, c.get("name", "?"),
                float(c.get("cpu_percent", 0) or 0),
                float(c.get("mem_percent", 0) or 0),
                int(c.get("restart_count", 0) or 0),
            ))
        if rows:
            conn.executemany(
                "INSERT INTO docker_ts (host, ts, container, cpu_percent, mem_percent, restart_count) "
                "VALUES (?,?,?,?,?,?)", rows)

    conn.commit()
    conn.close()


def query_series(db_path: str, host: str, hours: int = 24) -> list[dict]:
    cutoff = int(time.time()) - hours * 3600
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ts, cpu, mem, disk_max, net_recv_mb, net_sent_mb, connections "
        "FROM metrics_ts WHERE host=? AND ts>=? ORDER BY ts",
        (host, cutoff),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cleanup(db_path: str, retention_hours: int = 48) -> int:
    """Xoá row cũ hơn retention. Trả về số row đã xoá."""
    cutoff = int(time.time()) - retention_hours * 3600
    conn = sqlite3.connect(db_path)
    n = conn.execute("DELETE FROM metrics_ts WHERE ts<?", (cutoff,)).rowcount
    n += conn.execute("DELETE FROM docker_ts  WHERE ts<?", (cutoff,)).rowcount
    conn.commit()
    conn.close()
    return n
