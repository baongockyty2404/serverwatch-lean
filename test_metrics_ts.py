"""Smoke test cho metrics_ts.py — đảm bảo init + write + query + cleanup OK."""
import tempfile, time, os
from pathlib import Path
import metrics_ts

def main():
    db = Path(tempfile.mkdtemp(prefix="sw-mts-")) / "test.db"
    db_path = str(db)

    metrics_ts.init_schema(db_path)
    sample = {
        "cpu": {"percent": 42.5},
        "memory": {"percent": 60.0},
        "disk": [{"mountpoint": "/", "percent": 30}, {"mountpoint": "/var", "percent": 80}],
        "network": {"bytes_recv_mb": 1.5, "bytes_sent_mb": 0.3, "connections": 12},
        "processes": [{"name": "x"}, {"name": "y"}],
        "docker": {
            "available": True,
            "containers": [
                {"name": "c1", "state": "running", "cpu_percent": 5.0,
                 "mem_percent": 25.0, "restart_count": 0},
                {"name": "c2", "state": "exited"},
            ],
        },
    }
    for _ in range(3):
        metrics_ts.write(db_path, "host-a", sample)
        time.sleep(0.01)
    metrics_ts.write(db_path, "host-b", sample)

    series_a = metrics_ts.query_series(db_path, "host-a", hours=1)
    assert len(series_a) == 3, f"Expected 3 rows host-a, got {len(series_a)}"
    assert series_a[0]["cpu"] == 42.5
    assert series_a[0]["disk_max"] == 80.0
    print(f"PASS: 3 rows for host-a, disk_max={series_a[0]['disk_max']}")

    series_b = metrics_ts.query_series(db_path, "host-b", hours=1)
    assert len(series_b) == 1
    print("PASS: 1 row for host-b")

    n = metrics_ts.cleanup(db_path, retention_hours=999)
    assert n == 0
    print("PASS: cleanup retention=999h: no rows removed")

    # Force cleanup by setting tiny retention (everything older than 0h → cutoff in future)
    # Sleep 1s then cleanup 0h: should delete all (retention 0 = cutoff=now)
    time.sleep(1.1)
    n = metrics_ts.cleanup(db_path, retention_hours=0)
    # Note: cutoff = now - 0 = now; rows with ts < now → most should be deleted
    assert n >= 4, f"Expected >=4 deletions, got {n}"
    print(f"PASS: cleanup retention=0h deleted {n} rows")

    print("\nALL METRICS_TS SMOKE PASSED")

if __name__ == "__main__":
    main()
