"""
Backup + restore verification.

Mỗi backup gồm 1 tarball duy nhất:
  {backup_dir}/YYYY-MM-DD_HHMMSS.tar.gz
         └── manifest.json       (metadata + SHA256 từng file + HMAC tổng)
         └── sqlite.db.gz        (online backup qua sqlite3.Connection.backup)
         └── influx.lp.gz        (line protocol của InfluxDB, 90d retention)
         └── audit/              (append-only JSONL files hiện có)

Verify = giải nén tarball, so SHA256 từng file với manifest, so HMAC manifest,
         restore SQLite vào temp path và kiểm integrity_check.
         (Restore InfluxDB test thực tế đòi hỏi bucket riêng — có thể triển
         khai sau; hiện chỉ verify file parse được.)

Retention: xoá tarball cũ hơn BACKUP_RETENTION_DAYS (mặc định 30).
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
from datetime import datetime, timezone, timedelta, date
from pathlib import Path
from typing import Optional


DEFAULT_INFLUX_LOOKBACK_DAYS = 30   # Chỉ backup 30d gần nhất (giảm memory + time)
MANIFEST_FILE = "manifest.json"
MAX_LP_ROWS = 2_000_000             # Hard cap (30d × ~60K pts/d × 1 host ≈ 1.8M)


# ═══════════════════════════════════════════════════════════════════════════════
# SQLite online backup
# ═══════════════════════════════════════════════════════════════════════════════

def _dump_sqlite(src_path: str, dst_gz: Path) -> dict:
    """Online backup SQLite + gzip. Trả về {rows_per_table, bytes}."""
    # Online backup bằng API Connection.backup → an toàn với writer đang chạy
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        tmp_db = Path(tf.name)

    try:
        src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
        dst = sqlite3.connect(str(tmp_db))
        src.backup(dst)
        dst.close()
        src.close()

        # Đọc row counts từ backup
        conn = sqlite3.connect(str(tmp_db))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%_fts_%'"
        ).fetchall()
        rows_per_table = {}
        for (name,) in tables:
            try:
                rows_per_table[name] = conn.execute(
                    f"SELECT COUNT(*) FROM \"{name}\"").fetchone()[0]
            except Exception:
                rows_per_table[name] = -1
        conn.close()

        # Gzip file ra dst
        with open(tmp_db, "rb") as fin, gzip.open(dst_gz, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout)

        return {
            "rows_per_table": rows_per_table,
            "bytes":          dst_gz.stat().st_size,
            "raw_bytes":      tmp_db.stat().st_size,
        }
    finally:
        try:
            tmp_db.unlink()
        except Exception:
            pass


def _restore_sqlite_check(gz_path: Path) -> dict:
    """
    Verify SQLite backup: giải nén vào temp, chạy PRAGMA integrity_check +
    đếm row từng bảng.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        tmp_db = Path(tf.name)
    try:
        with gzip.open(gz_path, "rb") as fin, open(tmp_db, "wb") as fout:
            shutil.copyfileobj(fin, fout)

        conn = sqlite3.connect(str(tmp_db))
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%_fts_%'"
        ).fetchall()
        rows = {}
        for (name,) in tables:
            try:
                rows[name] = conn.execute(f"SELECT COUNT(*) FROM \"{name}\"").fetchone()[0]
            except Exception:
                rows[name] = -1
        conn.close()

        return {
            "integrity_check": integrity,
            "integrity_ok":    integrity == "ok",
            "rows_per_table":  rows,
        }
    finally:
        try:
            tmp_db.unlink()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# InfluxDB backup → line protocol
# ═══════════════════════════════════════════════════════════════════════════════

def _escape_lp_tag(s: str) -> str:
    return s.replace(" ", r"\ ").replace(",", r"\,").replace("=", r"\=")


def _escape_lp_field_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _dump_influx(url: str, token: str, org: str, bucket: str,
                  dst_gz: Path, lookback_days: int = DEFAULT_INFLUX_LOOKBACK_DAYS
                  ) -> dict:
    """
    Dump InfluxDB measurements ra file line protocol gzip.
    Trả về {points, bytes, measurements}.
    """
    try:
        from influxdb_client import InfluxDBClient
    except ImportError:
        return {"points": 0, "bytes": 0, "measurements": {},
                "error": "influxdb_client không có"}

    client = InfluxDBClient(url=url, token=token, org=org, timeout=30_000)
    qapi = client.query_api()

    # Lấy danh sách measurement trước (rẻ hơn than select all từ đầu)
    flux_measurements = f'''
    import "influxdata/influxdb/schema"
    schema.measurements(bucket: "{bucket}")
    '''
    try:
        mtables = qapi.query(flux_measurements)
    except Exception as e:
        client.close()
        return {"points": 0, "bytes": 0, "measurements": {},
                "error": f"list measurements fail: {e}"}

    measurements = []
    for tbl in mtables:
        for rec in tbl.records:
            v = rec.get_value()
            if v:
                measurements.append(v)

    points = 0
    per_meas = {}

    with gzip.open(dst_gz, "wt", encoding="utf-8", compresslevel=6) as fout:
        for m in measurements:
            if points >= MAX_LP_ROWS:
                break
            # pivot để tất cả field của 1 record nằm trên cùng dòng
            flux = f'''
            from(bucket: "{bucket}")
              |> range(start: -{lookback_days}d)
              |> filter(fn: (r) => r._measurement == "{m}")
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
            '''
            try:
                stream = qapi.query_stream(flux)
            except Exception:
                continue

            cnt = 0
            for rec in stream:
                if points >= MAX_LP_ROWS:
                    break
                vals = rec.values
                tags = []
                fields = []
                for k, v in vals.items():
                    if k.startswith("_") or k in ("result", "table"):
                        continue
                    if isinstance(v, (int, float, bool)):
                        fields.append((k, v))
                    elif isinstance(v, str) and v:
                        tags.append((k, v))

                if not fields:
                    continue

                tag_part = ",".join(
                    f"{_escape_lp_tag(k)}={_escape_lp_tag(str(v))}"
                    for k, v in tags
                )
                field_parts = []
                for k, v in fields:
                    if isinstance(v, bool):
                        field_parts.append(f"{k}={'true' if v else 'false'}")
                    elif isinstance(v, int):
                        field_parts.append(f"{k}={v}i")
                    elif isinstance(v, float):
                        field_parts.append(f"{k}={v}")
                    else:
                        field_parts.append(f'{k}="{_escape_lp_field_str(str(v))}"')

                ts_ns = int(rec.get_time().timestamp() * 1e9)
                line = f"{m}"
                if tag_part:
                    line += f",{tag_part}"
                line += f" {','.join(field_parts)} {ts_ns}\n"
                fout.write(line)
                points += 1
                cnt += 1

            per_meas[m] = cnt

    client.close()

    return {
        "points":       points,
        "bytes":        dst_gz.stat().st_size,
        "measurements": per_meas,
        "lookback_days": lookback_days,
        "capped":       points >= MAX_LP_ROWS,
    }


def _verify_influx_lp(gz_path: Path) -> dict:
    """Parse nhanh line protocol để verify format."""
    lines = 0
    bad = 0
    try:
        with gzip.open(gz_path, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                lines += 1
                # Line protocol: measurement[,tags] field1=val[,...] timestamp
                parts = line.rsplit(" ", 1)
                if len(parts) != 2 or not parts[1].isdigit():
                    bad += 1
                    continue
    except Exception as e:
        return {"lines": lines, "bad": bad, "error": str(e)}
    return {"lines": lines, "bad": bad, "parse_ok": bad == 0}


# ═══════════════════════════════════════════════════════════════════════════════
# Main pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_backup(
    db_path: str,
    data_dir: Path,
    backup_dir: Path,
    influx_url: Optional[str] = None,
    influx_token: Optional[str] = None,
    influx_org: Optional[str] = None,
    influx_bucket: Optional[str] = None,
    hmac_key: Optional[str] = None,
    lookback_days: int = DEFAULT_INFLUX_LOOKBACK_DAYS,
) -> dict:
    """Chạy backup đầy đủ + tạo tarball."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc)
    stamp = ts.strftime("%Y-%m-%d_%H%M%S")

    with tempfile.TemporaryDirectory(prefix="sw_backup_") as tmp:
        tmp_path = Path(tmp)
        sqlite_gz = tmp_path / "sqlite.db.gz"
        influx_gz = tmp_path / "influx.lp.gz"

        # 1. SQLite
        sqlite_stats = _dump_sqlite(db_path, sqlite_gz)

        # 2. InfluxDB (optional, có thể fail mà không block backup)
        if influx_url and influx_token and influx_bucket:
            try:
                influx_stats = _dump_influx(influx_url, influx_token, influx_org or "",
                                             influx_bucket, influx_gz, lookback_days)
            except Exception as e:
                influx_stats = {"error": str(e), "points": 0, "bytes": 0}
        else:
            influx_stats = {"skipped": "InfluxDB params missing",
                             "points": 0, "bytes": 0}

        # 3. Audit files
        audit_src = Path(data_dir) / "audit"
        audit_dst = tmp_path / "audit"
        audit_files = 0
        if audit_src.exists():
            audit_dst.mkdir()
            for f in audit_src.iterdir():
                if f.is_file():
                    shutil.copy2(f, audit_dst / f.name)
                    audit_files += 1

        # 4. Manifest với SHA256 của từng file
        files_info = []
        for p in sorted(tmp_path.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(tmp_path).as_posix()
            files_info.append({
                "path":   rel,
                "bytes":  p.stat().st_size,
                "sha256": _sha256_file(p),
            })

        manifest = {
            "version":       "1.0",
            "created_at":    ts.isoformat(),
            "hostname":      os.uname().nodename if hasattr(os, "uname") else "",
            "sqlite_stats":  sqlite_stats,
            "influx_stats":  influx_stats,
            "audit_files":   audit_files,
            "files":         files_info,
        }
        manifest_body = json.dumps(manifest, sort_keys=True, indent=2).encode()
        if hmac_key:
            manifest["hmac_sha256"] = hmac.new(
                hmac_key.encode(), manifest_body, hashlib.sha256
            ).hexdigest()
        final_manifest = json.dumps(manifest, sort_keys=True, indent=2).encode()
        (tmp_path / MANIFEST_FILE).write_bytes(final_manifest)

        # 5. Tarball
        tar_path = backup_dir / f"{stamp}.tar.gz"
        with tarfile.open(tar_path, "w:gz", compresslevel=6) as tar:
            for p in sorted(tmp_path.rglob("*")):
                if p.is_file():
                    tar.add(p, arcname=p.relative_to(tmp_path).as_posix())

    return {
        "ok":          True,
        "path":        str(tar_path),
        "name":        tar_path.name,
        "bytes":       tar_path.stat().st_size,
        "created_at":  ts.isoformat(),
        "manifest":    manifest,
    }


def verify_backup(tar_path: Path, hmac_key: Optional[str] = None) -> dict:
    """Verify: extract, check SHA256 khớp manifest, HMAC, restore SQLite integrity."""
    if not tar_path.exists():
        return {"ok": False, "error": "file không tồn tại"}

    with tempfile.TemporaryDirectory(prefix="sw_verify_") as tmp:
        tmp_path = Path(tmp)

        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                # Python 3.12+ đã cảnh báo filter — pass "data" filter
                try:
                    tar.extractall(tmp_path, filter="data")
                except TypeError:
                    tar.extractall(tmp_path)
        except Exception as e:
            return {"ok": False, "error": f"extract fail: {e}"}

        manifest_path = tmp_path / MANIFEST_FILE
        if not manifest_path.exists():
            return {"ok": False, "error": "không có manifest.json"}

        try:
            manifest = json.loads(manifest_path.read_bytes())
        except Exception as e:
            return {"ok": False, "error": f"manifest invalid: {e}"}

        # Verify HMAC của manifest (recompute manifest_body phải khớp)
        stored_hmac = manifest.pop("hmac_sha256", None)
        if hmac_key and stored_hmac:
            body = json.dumps(manifest, sort_keys=True, indent=2).encode()
            expected = hmac.new(hmac_key.encode(), body, hashlib.sha256).hexdigest()
            hmac_ok = hmac.compare_digest(expected, stored_hmac)
        else:
            hmac_ok = None   # không có key → skip

        # Verify SHA256 của từng file
        files_ok = True
        file_errors = []
        for fi in manifest.get("files", []):
            p = tmp_path / fi["path"]
            if not p.exists():
                files_ok = False
                file_errors.append(f"{fi['path']}: missing")
                continue
            actual = _sha256_file(p)
            if actual != fi["sha256"]:
                files_ok = False
                file_errors.append(f"{fi['path']}: SHA mismatch")

        # Restore SQLite + integrity check
        sqlite_gz = tmp_path / "sqlite.db.gz"
        sqlite_check = _restore_sqlite_check(sqlite_gz) if sqlite_gz.exists() \
                       else {"integrity_ok": False, "error": "sqlite.db.gz missing"}

        # InfluxDB line protocol check
        influx_gz = tmp_path / "influx.lp.gz"
        influx_check = _verify_influx_lp(influx_gz) if influx_gz.exists() \
                       else {"parse_ok": None}

        overall = files_ok and sqlite_check.get("integrity_ok", False) \
                  and (hmac_ok is not False) \
                  and (influx_check.get("parse_ok") is not False)

        return {
            "ok":            overall,
            "files_ok":      files_ok,
            "file_errors":   file_errors,
            "hmac_ok":       hmac_ok,
            "sqlite":        sqlite_check,
            "influx":        influx_check,
            "manifest_summary": {
                "created_at":    manifest.get("created_at"),
                "sqlite_rows":   manifest.get("sqlite_stats", {}).get("rows_per_table", {}),
                "influx_points": manifest.get("influx_stats", {}).get("points", 0),
                "audit_files":   manifest.get("audit_files", 0),
            },
        }


def list_backups(backup_dir: Path) -> list[dict]:
    if not backup_dir.exists():
        return []
    out = []
    for p in sorted(backup_dir.glob("*.tar.gz"), reverse=True):
        try:
            st = p.stat()
            # Đọc manifest để lấy metadata nhanh
            summary = {}
            try:
                with tarfile.open(p, "r:gz") as tar:
                    m = tar.extractfile(MANIFEST_FILE)
                    if m:
                        manifest = json.loads(m.read())
                        summary = {
                            "sqlite_rows":   manifest.get("sqlite_stats", {}).get("rows_per_table", {}),
                            "influx_points": manifest.get("influx_stats", {}).get("points", 0),
                            "audit_files":   manifest.get("audit_files", 0),
                            "created_at":    manifest.get("created_at"),
                        }
            except Exception:
                pass
            out.append({
                "name":       p.name,
                "bytes":      st.st_size,
                "mtime":      datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                "summary":    summary,
            })
        except Exception:
            pass
    return out


def cleanup_old(backup_dir: Path, retention_days: int) -> int:
    if not backup_dir.exists():
        return 0
    cutoff = time.time() - retention_days * 86400
    deleted = 0
    for p in backup_dir.glob("*.tar.gz"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                deleted += 1
        except Exception:
            pass
    return deleted
