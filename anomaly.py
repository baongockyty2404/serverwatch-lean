"""
ServerWatch — Anomaly Detection Engine
Phát hiện bất thường dựa trên baseline thống kê (Z-score + sliding window).
Không cần ML library nặng — chỉ dùng toán học cơ bản.

Tích hợp vào server.py:
    from anomaly import AnomalyDetector
    detector = AnomalyDetector()
    anomalies = detector.analyze(host, metrics)
"""

import math
import time
import json
import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# SLIDING WINDOW STATISTICS
# ══════════════════════════════════════════════════════════════════════════════

class SlidingWindowStats:
    """
    Tính mean và std trên cửa sổ N điểm gần nhất.
    Không lưu toàn bộ lịch sử — chỉ cần O(N) memory.
    """

    def __init__(self, window: int = 720):   # 720 × 10s = 2 giờ
        self.window = window
        self._data: deque = deque(maxlen=window)

    def push(self, value: float):
        self._data.append(value)

    @property
    def mean(self) -> float:
        if not self._data:
            return 0.0
        return sum(self._data) / len(self._data)

    @property
    def std(self) -> float:
        if len(self._data) < 2:
            return 0.0
        m = self.mean
        variance = sum((x - m) ** 2 for x in self._data) / len(self._data)
        return math.sqrt(variance)

    @property
    def ready(self) -> bool:
        """Cần ít nhất 30 điểm để baseline có ý nghĩa."""
        return len(self._data) >= 30

    def z_score(self, value: float) -> float:
        s = self.std
        if s == 0:
            return 0.0
        return (value - self.mean) / s


# ══════════════════════════════════════════════════════════════════════════════
# BASELINE PROFILES
# ══════════════════════════════════════════════════════════════════════════════

class HostProfile:
    """
    Lưu baseline cho 1 máy chủ.
    Mỗi metric có cửa sổ riêng.
    """

    def __init__(self):
        self.cpu        = SlidingWindowStats(window=720)   # 2 giờ
        self.memory     = SlidingWindowStats(window=720)
        self.net_recv   = SlidingWindowStats(window=360)   # 1 giờ
        self.net_sent   = SlidingWindowStats(window=360)
        self.connections = SlidingWindowStats(window=180)  # 30 phút

        # Lịch sử giờ login (0-23) để phát hiện login lạ giờ
        self.login_hours: deque = deque(maxlen=500)

        # Whitelist process (tập hợp tên process đã từng thấy)
        self.known_processes: set = set()
        self.process_count: int  = 0

        # Docker container baselines
        self.docker_containers: dict = {}  # name → ContainerProfile
        self.docker_container_set: set = set()  # Tập container đã biết
        self.docker_learning_count: int = 0

    def update(self, metrics: dict):
        # .get() defensively — partial payload (kể cả agent version cũ) không
        # crash baseline update; 0.0 là giá trị an toàn cho missing metric.
        cpu  = (metrics.get("cpu")     or {}).get("percent", 0.0) or 0.0
        mem  = (metrics.get("memory")  or {}).get("percent", 0.0) or 0.0
        net  = metrics.get("network")  or {}
        self.cpu.push(cpu)
        self.memory.push(mem)
        self.net_recv.push(net.get("bytes_recv_mb", 0.0) or 0.0)
        self.net_sent.push(net.get("bytes_sent_mb", 0.0) or 0.0)
        self.connections.push(net.get("connections", 0) or 0)

        # Học whitelist process sau 100 lần thu thập đầu
        if self.process_count < 100:
            for p in metrics.get("processes", []):
                self.known_processes.add(p["name"].lower())
            self.process_count += 1

        # Cập nhật Docker container baselines
        docker = metrics.get("docker", {})
        if docker.get("available"):
            for c in docker.get("containers", []):
                name = c.get("name", "")
                if not name:
                    continue
                if name not in self.docker_containers:
                    self.docker_containers[name] = {
                        "cpu": SlidingWindowStats(window=360),
                        "mem": SlidingWindowStats(window=360),
                        "restart_history": deque(maxlen=50),
                        "error_rate": SlidingWindowStats(window=180),
                    }
                profile = self.docker_containers[name]
                if c.get("state") == "running":
                    profile["cpu"].push(c.get("cpu_percent", 0))
                    profile["mem"].push(c.get("mem_percent", 0))
                    profile["error_rate"].push(c.get("log_error_count", 0))
                profile["restart_history"].append(c.get("restart_count", 0))

            # Học danh sách container bình thường
            if self.docker_learning_count < 50:
                for c in docker.get("containers", []):
                    self.docker_container_set.add(c.get("name", ""))
                self.docker_learning_count += 1


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Phát hiện bất thường theo 4 chiến lược:
    1. Z-score: metric lệch > N sigma so với baseline
    2. Rate-of-change: tăng đột ngột trong 1 khoảng ngắn
    3. Time-based: hành động xảy ra giờ bất thường
    4. Whitelist: process/port không có trong baseline
    """

    Z_THRESHOLD = 3.0     # > 3 sigma = bất thường
    ROC_RATIO   = 5.0     # tăng > 5x so với trung bình = đột biến
    NIGHT_HOURS = set(range(1, 6))   # 01:00 - 05:59 = giờ đêm đáng ngờ

    def __init__(self):
        self._profiles: dict[str, HostProfile] = defaultdict(HostProfile)

    def _get_profile(self, host: str) -> HostProfile:
        return self._profiles[host]

    def analyze(self, host: str, metrics: dict) -> list:
        profile = self._get_profile(host)
        anomalies = []

        # Cập nhật baseline trước
        profile.update(metrics)

        # Chỉ phân tích sau khi có đủ baseline
        if not profile.cpu.ready:
            return []

        # ── 1. Z-score anomalies ────────────────────────────────

        cpu_z = profile.cpu.z_score(metrics["cpu"]["percent"])
        if cpu_z > self.Z_THRESHOLD:
            anomalies.append({
                "type":     "cpu_anomaly",
                "severity": "warning",
                "detail":   (f"CPU {metrics['cpu']['percent']:.0f}% "
                             f"({cpu_z:.1f}σ trên baseline "
                             f"{profile.cpu.mean:.0f}%)"),
                "z_score":  round(cpu_z, 2),
            })

        net_z = profile.net_recv.z_score(metrics["network"]["bytes_recv_mb"])
        if net_z > self.Z_THRESHOLD:
            anomalies.append({
                "type":     "network_anomaly",
                "severity": "warning" if net_z < 6 else "critical",
                "detail":   (f"Network IN {metrics['network']['bytes_recv_mb']:.1f} MB/s "
                             f"({net_z:.1f}σ trên baseline "
                             f"{profile.net_recv.mean:.1f} MB/s)"),
                "z_score":  round(net_z, 2),
            })

        conn_z = profile.connections.z_score(metrics["network"]["connections"])
        if conn_z > self.Z_THRESHOLD:
            anomalies.append({
                "type":     "connection_spike",
                "severity": "warning",
                "detail":   (f"{metrics['network']['connections']} kết nối "
                             f"({conn_z:.1f}σ trên baseline "
                             f"{profile.connections.mean:.0f})"),
                "z_score":  round(conn_z, 2),
            })

        # ── 2. Rate-of-change (so với mean) ─────────────────────

        if (profile.net_recv.mean > 1 and
                metrics["network"]["bytes_recv_mb"] > profile.net_recv.mean * self.ROC_RATIO):
            anomalies.append({
                "type":     "traffic_spike",
                "severity": "critical",
                "detail":   (f"Traffic IN tăng {metrics['network']['bytes_recv_mb'] / max(profile.net_recv.mean, 0.01):.0f}x "
                             f"so với bình thường"),
            })

        # ── 3. Process ngoài whitelist ──────────────────────────

        if profile.process_count >= 100:   # whitelist đã học xong
            for proc in metrics.get("processes", []):
                name = proc["name"].lower()
                if (name not in profile.known_processes and
                        proc["cpu_pct"] > 5):   # chỉ cảnh báo nếu process dùng CPU đáng kể
                    anomalies.append({
                        "type":     "unknown_process",
                        "severity": "warning",
                        "detail":   (f"Process '{proc['name']}' (PID {proc['pid']}) "
                                     f"không có trong baseline, CPU={proc['cpu_pct']}%"),
                    })

        # ── 4. Kiểm tra failed login bất thường ─────────────────

        hour = datetime.now(timezone.utc).hour
        sec  = metrics.get("security", {})
        if sec.get("recent_fails_60s", 0) > 0 and hour in self.NIGHT_HOURS:
            anomalies.append({
                "type":     "night_login_attempt",
                "severity": "warning",
                "detail":   (f"{sec['recent_fails_60s']} lần thử login lúc "
                             f"{hour:02d}:00 UTC (giờ bất thường)"),
            })

        # ── 5. Docker anomalies ─────────────────────────────────

        docker = metrics.get("docker", {})
        if docker.get("available"):
            for c in docker.get("containers", []):
                cname = c.get("name", "")
                cp = profile.docker_containers.get(cname)
                if not cp:
                    continue

                # CPU bất thường so với baseline
                if cp["cpu"].ready and c.get("state") == "running":
                    cpu_z = cp["cpu"].z_score(c.get("cpu_percent", 0))
                    if cpu_z > self.Z_THRESHOLD:
                        anomalies.append({
                            "type":     "docker_cpu_anomaly",
                            "severity": "warning",
                            "detail":   (f"Container '{cname}' CPU={c['cpu_percent']:.1f}% "
                                         f"({cpu_z:.1f}σ, baseline={cp['cpu'].mean:.1f}%)"),
                            "z_score":  round(cpu_z, 2),
                        })

                # Lỗi tăng đột biến so với baseline
                if cp["error_rate"].ready:
                    err_z = cp["error_rate"].z_score(c.get("log_error_count", 0))
                    if err_z > self.Z_THRESHOLD:
                        anomalies.append({
                            "type":     "docker_error_spike",
                            "severity": "warning",
                            "detail":   (f"Container '{cname}' có {c.get('log_error_count', 0)} lỗi "
                                         f"({err_z:.1f}σ trên baseline)"),
                        })

                # Restart count tăng nhanh
                if len(cp["restart_history"]) >= 3:
                    recent = list(cp["restart_history"])
                    if len(recent) >= 3 and recent[-1] > recent[-3] + 2:
                        anomalies.append({
                            "type":     "docker_restart_acceleration",
                            "severity": "critical",
                            "detail":   (f"Container '{cname}' restart tăng nhanh: "
                                         f"{recent[-3]} → {recent[-1]}"),
                        })

            # Container mới xuất hiện (không có trong baseline)
            if profile.docker_learning_count >= 50:
                current_names = {c.get("name", "") for c in docker.get("containers", [])}
                new_containers = current_names - profile.docker_container_set
                for nc in new_containers:
                    if nc:
                        anomalies.append({
                            "type":     "docker_unknown_container",
                            "severity": "warning",
                            "detail":   f"Container mới '{nc}' không có trong baseline",
                        })

        return anomalies

    def get_trend_data(self, host: str) -> dict:
        """Xuất dữ liệu trend cho AI analyzer sử dụng."""
        p = self._profiles.get(host)
        if not p:
            return {}
        return {
            "cpu_history": list(p.cpu._data)[-60:],
            "memory_history": list(p.memory._data)[-60:],
            "net_recv_history": list(p.net_recv._data)[-60:],
            "connections_history": list(p.connections._data)[-60:],
            "baseline_ready": p.cpu.ready,
            "known_process_count": len(p.known_processes),
            "docker_containers_known": len(p.docker_container_set),
        }

    def get_baseline_report(self, host: str) -> dict:
        """Trả về báo cáo baseline để hiển thị trên dashboard."""
        p = self._profiles.get(host)
        if not p:
            return {}
        return {
            "cpu":    {"mean": round(p.cpu.mean, 1), "std": round(p.cpu.std, 1),
                       "ready": p.cpu.ready, "samples": len(p.cpu._data)},
            "memory": {"mean": round(p.memory.mean, 1), "std": round(p.memory.std, 1),
                       "ready": p.memory.ready},
            "network_recv": {"mean": round(p.net_recv.mean, 2), "std": round(p.net_recv.std, 2)},
            "connections":  {"mean": round(p.connections.mean, 0),
                             "std":  round(p.connections.std, 1)},
            "known_processes": sorted(p.known_processes),
            "process_learning_pct": min(100, int(p.process_count)),
            "docker": {
                "known_containers": sorted(p.docker_container_set),
                "learning_pct":     min(100, int(p.docker_learning_count * 2)),
                "container_baselines": {
                    name: {
                        "cpu_mean":  round(cp["cpu"].mean, 1),
                        "cpu_std":   round(cp["cpu"].std, 1),
                        "mem_mean":  round(cp["mem"].mean, 1),
                        "error_rate_mean": round(cp["error_rate"].mean, 2),
                    }
                    for name, cp in p.docker_containers.items()
                    if cp["cpu"].ready
                },
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# PORT SCANNER DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class PortScanDetector:
    """
    Phát hiện port scan từ cùng một IP:
    1 IP kết nối đến nhiều port khác nhau trong 30 giây = port scan.
    """

    WINDOW_SEC  = 30
    PORT_THRESH = 15    # > 15 port khác nhau trong 30 giây

    def __init__(self):
        # ip → list of (timestamp, port)
        self._hits: dict = defaultdict(list)

    def check(self, connections: list) -> list:
        now = time.time()
        alerts = []

        for conn in connections:
            raddr = conn.get("raddr", "")
            if not raddr:
                continue
            ip, _, port_str = raddr.rpartition(":")
            if not port_str.isdigit():
                continue
            self._hits[ip].append((now, int(port_str)))

        # Dọn dẹp hit cũ và kiểm tra
        detected = set()
        for ip, hits in list(self._hits.items()):
            # Chỉ giữ hits trong WINDOW_SEC
            self._hits[ip] = [(t, p) for t, p in hits if now - t < self.WINDOW_SEC]
            unique_ports = {p for _, p in self._hits[ip]}
            if len(unique_ports) > self.PORT_THRESH and ip not in detected:
                detected.add(ip)
                alerts.append({
                    "type":     "port_scan",
                    "severity": "critical",
                    "detail":   (f"IP {ip} đã thử {len(unique_ports)} port "
                                 f"trong {self.WINDOW_SEC} giây "
                                 f"(port: {sorted(unique_ports)[:5]}...)"),
                })

        return alerts
