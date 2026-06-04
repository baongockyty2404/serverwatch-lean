"""
ServerWatch Agent — Cross-platform (Ubuntu / Windows)
Thu thập metrics hệ thống mỗi 10 giây và gửi về server trung tâm.

Cài đặt:
    pip install psutil requests

Chạy:
    python agent.py --server http://your-server:8000 --token YOUR_TOKEN

Chạy như service (Ubuntu):
    Xem file: serverwatch-agent.service

Chạy như service (Windows):
    python agent.py install   (dùng pywin32)
"""

import os
import sys
import stat
import time
import json
import socket
import hashlib
import logging
import platform
import argparse
import threading
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
from typing import Optional

import psutil
import requests
import subprocess
import re

# ─── Cấu hình ────────────────────────────────────────────────────────────────

DEFAULT_SERVER   = "http://localhost:8000"
DEFAULT_INTERVAL = 10          # giây
DEFAULT_BATCH    = 6           # gộp 6 bản tin = gửi 1 lần / phút
LOG_LEVEL        = logging.INFO

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("serverwatch-agent.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("agent")

# ─── Hằng số OS ──────────────────────────────────────────────────────────────

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
HOSTNAME   = socket.gethostname()
OS_NAME    = platform.system() + " " + platform.release()


# ══════════════════════════════════════════════════════════════════════════════
# THU THẬP METRICS
# ══════════════════════════════════════════════════════════════════════════════

def collect_cpu() -> dict:
    """CPU usage tổng và per-core.

    Chỉ block 1 lần / cycle: lần interval=1 đầu lấy total, lần interval=None
    sau đó lấy per-core delta tính từ thời điểm vừa rồi (instant, không block).
    """
    percent  = psutil.cpu_percent(interval=1)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    return {
        "percent":    percent,
        "per_core":   per_core,
        "count":      psutil.cpu_count(logical=True),
        "load_avg":   list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else [],
    }


def collect_memory() -> dict:
    """RAM và swap."""
    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total_gb":   round(mem.total / 1e9, 2),
        "used_gb":    round(mem.used  / 1e9, 2),
        "percent":    mem.percent,
        "swap_total": round(swap.total / 1e9, 2),
        "swap_used":  round(swap.used  / 1e9, 2),
        "swap_pct":   swap.percent,
    }


# Filesystems và mountpoints bỏ qua (luôn báo false-positive "100% full"):
#  - squashfs/overlay: snap packages, docker image layers — read-only, 100% by design
#  - tmpfs/devtmpfs/proc/sysfs: không phải disk thật
#  - /snap/*, /var/lib/docker/overlay2/*: container + snap internals
_SKIP_FSTYPES = {
    "squashfs", "overlay", "overlayfs", "tmpfs", "devtmpfs",
    "proc", "sysfs", "cgroup", "cgroup2", "fuse.gvfsd-fuse",
    "autofs", "mqueue", "nsfs", "tracefs", "debugfs", "fusectl",
    "pstore", "securityfs", "configfs", "bpf", "ramfs",
}
_SKIP_MOUNT_PREFIXES = (
    "/snap/",
    "/var/lib/docker/overlay2/",
    "/var/lib/docker/containers/",
    "/run/snapd/",
    "/run/credentials/",
    "/run/user/",
    "/sys/",
    "/proc/",
)


def collect_disk() -> list:
    """Phân vùng disk thật (bỏ qua squashfs/snap/overlay/tmpfs)."""
    partitions = []
    for part in psutil.disk_partitions(all=False):
        # Skip pseudo / readonly-by-design filesystems
        if part.fstype.lower() in _SKIP_FSTYPES:
            continue
        if any(part.mountpoint.startswith(p) for p in _SKIP_MOUNT_PREFIXES):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            io    = psutil.disk_io_counters(perdisk=True)
            dev   = part.device.split("/")[-1].split("\\")[-1]
            partitions.append({
                "device":      part.device,
                "mountpoint":  part.mountpoint,
                "fstype":      part.fstype,
                "total_gb":    round(usage.total / 1e9, 2),
                "used_gb":     round(usage.used  / 1e9, 2),
                "percent":     usage.percent,
                "read_mb":     round(io[dev].read_bytes  / 1e6, 2) if dev in io else 0,
                "write_mb":    round(io[dev].write_bytes / 1e6, 2) if dev in io else 0,
            })
        except (PermissionError, KeyError):
            continue
    return partitions


def collect_network() -> dict:
    """Băng thông mạng và danh sách kết nối."""
    net = psutil.net_io_counters()
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED":
                conns.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "pid":   c.pid,
                })
    except psutil.AccessDenied:
        pass

    # Đếm theo remote IP để phát hiện nhiều kết nối từ 1 IP
    from collections import Counter
    remote_ips = Counter(c["raddr"].split(":")[0] for c in conns if c["raddr"])

    return {
        "bytes_sent_mb":  round(net.bytes_sent / 1e6, 2),
        "bytes_recv_mb":  round(net.bytes_recv / 1e6, 2),
        "packets_sent":   net.packets_sent,
        "packets_recv":   net.packets_recv,
        "errin":          net.errin,
        "errout":         net.errout,
        "connections":    len(conns),
        "top_remote_ips": remote_ips.most_common(10),
    }


def collect_process_names() -> list:
    """Toàn bộ unique process names (chỉ tên, không stats) — dùng cho watchlist."""
    names = set()
    for p in psutil.process_iter(["name"]):
        n = p.info.get("name")
        if n:
            names.add(n)
    return sorted(names)


def collect_processes() -> list:
    """Top 20 process theo CPU, kèm thông tin bảo mật."""
    procs = []
    for p in sorted(
        psutil.process_iter(["pid", "name", "username", "cpu_percent",
                             "memory_percent", "create_time", "status",
                             "exe"]),
        key=lambda x: x.info.get("cpu_percent") or 0,
        reverse=True,
    )[:20]:
        info = p.info
        procs.append({
            "pid":        info["pid"],
            "name":       info["name"],
            "user":       info.get("username", ""),
            "cpu_pct":    round(info.get("cpu_percent") or 0, 2),
            "mem_pct":    round(info.get("memory_percent") or 0, 2),
            "status":     info.get("status", ""),
            "exe":        info.get("exe", ""),
            "started":    datetime.fromtimestamp(
                            info["create_time"], tz=timezone.utc
                          ).isoformat() if info.get("create_time") else "",
        })
    return procs


def collect_open_ports() -> list:
    """Port đang lắng nghe — quan trọng để phát hiện backdoor."""
    ports = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr:
                ports.append({
                    "port":  c.laddr.port,
                    "ip":    c.laddr.ip,
                    "pid":   c.pid,
                })
    except psutil.AccessDenied:
        pass
    return sorted(ports, key=lambda x: x["port"])


# ══════════════════════════════════════════════════════════════════════════════
# THU THẬP DOCKER METRICS
# ══════════════════════════════════════════════════════════════════════════════

class DockerCollector:
    """
    Thu thập thông tin Docker containers:
    - Danh sách container (name, status, image, uptime, health)
    - Resource usage (CPU%, MEM%, network I/O, block I/O)
    - Logs gần nhất (phát hiện lỗi, warning)
    - Restart count và exit code
    """

    # Các pattern lỗi phổ biến trong log container
    ERROR_PATTERNS = [
        re.compile(r'\b(error|err|fatal|panic|exception|traceback|critical|fail(ed|ure)?)\b', re.IGNORECASE),
        re.compile(r'\b(oom|out\s*of\s*memory|kill(ed)?|segfault|core\s*dump)\b', re.IGNORECASE),
        re.compile(r'\b(connection\s*(refused|reset|timeout)|ECONNREFUSED|ETIMEDOUT)\b', re.IGNORECASE),
        re.compile(r'\b(permission\s*denied|access\s*denied|unauthorized|forbidden)\b', re.IGNORECASE),
    ]

    # Pattern hành vi nguy hiểm trong container
    DANGEROUS_PATTERNS = [
        re.compile(r'\b(reverse\s*shell|bind\s*shell|meterpreter)\b', re.IGNORECASE),
        re.compile(r'\b(crypto\s*min(er|ing)|xmrig|monero)\b', re.IGNORECASE),
        re.compile(r'(curl|wget|fetch)\s+.*(\.sh|\.py|\.pl)\s*\|\s*(ba)?sh', re.IGNORECASE),
        re.compile(r'\b(nc|ncat|netcat)\s+-[elp]', re.IGNORECASE),
        re.compile(r'\b(chmod\s+777|chmod\s+\+s)\b', re.IGNORECASE),
    ]

    def __init__(self):
        self._docker_available = self._check_docker()

    def _check_docker(self) -> bool:
        """Kiểm tra Docker daemon có chạy không."""
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                log.info("Docker phát hiện — version %s", result.stdout.strip())
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        log.info("Docker không khả dụng — bỏ qua Docker monitoring")
        return False

    def collect(self) -> dict:
        """Thu thập toàn bộ thông tin Docker."""
        if not self._docker_available:
            return {"available": False, "containers": [], "summary": {}}

        containers = self._collect_containers()
        error_containers = [c for c in containers if c.get("log_errors")]
        danger_containers = [c for c in containers if c.get("dangerous_activity")]

        return {
            "available": True,
            "containers": containers,
            "summary": {
                "total":     len(containers),
                "running":   sum(1 for c in containers if c["state"] == "running"),
                "stopped":   sum(1 for c in containers if c["state"] in ("exited", "dead")),
                "unhealthy": sum(1 for c in containers if c.get("health") == "unhealthy"),
                "restarting": sum(1 for c in containers if c["state"] == "restarting"),
                "error_containers":  len(error_containers),
                "danger_containers": len(danger_containers),
            },
        }

    def _collect_containers(self) -> list:
        """Lấy danh sách tất cả container kèm stats."""
        try:
            # Lấy danh sách container (bao gồm cả stopped)
            result = subprocess.run(
                ["docker", "ps", "-a", "--no-trunc",
                 "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}|{{.Ports}}|{{.CreatedAt}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []

            containers = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) < 7:
                    continue

                cid, name, image, status, state, ports, created = parts[:7]

                container = {
                    "id":       cid[:12],
                    "name":     name,
                    "image":    image,
                    "status":   status,
                    "state":    state,
                    "ports":    ports,
                    "created":  created,
                }

                # Thu thập resource usage cho running containers
                if state == "running":
                    container.update(self._collect_stats(cid[:12]))
                    container["health"] = self._get_health(cid[:12])
                    container["restart_count"] = self._get_restart_count(cid[:12])

                    # Thu thập và phân tích logs
                    log_analysis = self._analyze_logs(cid[:12], name)
                    container.update(log_analysis)
                else:
                    container["exit_code"] = self._get_exit_code(cid[:12])

                containers.append(container)

            return containers

        except (subprocess.TimeoutExpired, Exception) as e:
            log.error("Lỗi thu thập Docker: %s", e)
            return []

    def _collect_stats(self, container_id: str) -> dict:
        """Lấy CPU%, MEM%, Network I/O, Block I/O của container."""
        try:
            result = subprocess.run(
                ["docker", "stats", container_id, "--no-stream",
                 "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return {}

            line = result.stdout.strip()
            if not line:
                return {}

            parts = line.split("|")
            if len(parts) < 6:
                return {}

            cpu_str, mem_usage, mem_pct, net_io, block_io, pids = parts[:6]

            return {
                "cpu_percent":  float(cpu_str.replace("%", "").strip()) if cpu_str else 0,
                "mem_usage":    mem_usage.strip(),
                "mem_percent":  float(mem_pct.replace("%", "").strip()) if mem_pct else 0,
                "net_io":       net_io.strip(),
                "block_io":     block_io.strip(),
                "pids":         int(pids.strip()) if pids.strip().isdigit() else 0,
            }
        except (subprocess.TimeoutExpired, Exception):
            return {}

    def _get_health(self, container_id: str) -> str:
        """Lấy health status của container."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container_id],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    def _get_restart_count(self, container_id: str) -> int:
        """Lấy số lần restart."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.RestartCount}}", container_id],
                capture_output=True, text=True, timeout=5
            )
            return int(result.stdout.strip()) if result.returncode == 0 else 0
        except Exception:
            return 0

    def _get_exit_code(self, container_id: str) -> int:
        """Lấy exit code của container đã dừng."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.ExitCode}}", container_id],
                capture_output=True, text=True, timeout=5
            )
            return int(result.stdout.strip()) if result.returncode == 0 else -1
        except Exception:
            return -1

    def _analyze_logs(self, container_id: str, name: str) -> dict:
        """Phân tích log container — phát hiện lỗi và hành vi nguy hiểm."""
        try:
            # Luôn lấy 100 dòng cuối, không filter --since (interval push có
            # thể >10s nên `--since 10s` sẽ bỏ sót log → recent_logs rỗng).
            # docker logs --tail là cheap: chỉ đọc cuối file json log.
            cmd = ["docker", "logs", "--tail", "100", "--timestamps", container_id]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )

            # Gộp stdout + stderr
            all_logs = (result.stdout or "") + (result.stderr or "")
            lines = all_logs.strip().split("\n")[-100:]  # Giữ 100 dòng cuối

            # Phân tích lỗi
            errors = []
            for line in lines:
                for pattern in self.ERROR_PATTERNS:
                    if pattern.search(line):
                        errors.append(line.strip()[:200])
                        break

            # Phát hiện hành vi nguy hiểm
            dangers = []
            for line in lines:
                for pattern in self.DANGEROUS_PATTERNS:
                    if pattern.search(line):
                        dangers.append({
                            "pattern": pattern.pattern[:50],
                            "line":    line.strip()[:200],
                        })
                        break

            return {
                "log_errors":          errors[-10:],    # 10 lỗi gần nhất
                "log_error_count":     len(errors),
                "dangerous_activity":  dangers[:5],     # 5 hoạt động nguy hiểm gần nhất
                "recent_logs":         lines[-5:],      # 5 dòng log gần nhất
            }

        except (subprocess.TimeoutExpired, Exception) as e:
            log.debug("Không đọc được log container %s: %s", name, e)
            return {"log_errors": [], "log_error_count": 0,
                    "dangerous_activity": [], "recent_logs": []}


# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# PHÁT HIỆN MỐI ĐE DỌA CƠ BẢN (tại agent)
# ══════════════════════════════════════════════════════════════════════════════

class LocalThreatDetector:
    """
    Phát hiện nhanh tại chỗ trước khi gửi về server.
    Kết quả được đính kèm vào payload để server xử lý tiếp.
    """

    # Danh sách port phổ biến bị dùng bởi malware / backdoor
    SUSPICIOUS_PORTS = {1337, 4444, 6666, 6667, 8888, 9999, 31337, 12345}
    # Process name không hợp lệ trên server thông thường
    SUSPICIOUS_NAMES = {"nc", "ncat", "netcat", "nmap", "masscan",
                        "msfconsole", "hydra", "john", "hashcat"}

    def analyze(self, metrics: dict) -> list:
        threats = []

        # 1. CPU spike
        if metrics["cpu"]["percent"] > 90:
            threats.append({
                "type":     "cpu_spike",
                "severity": "warning",
                "detail":   f"CPU {metrics['cpu']['percent']}%",
            })

        # 3. Port backdoor
        open_ports = {p["port"] for p in metrics["ports"]}
        bad_ports  = open_ports & self.SUSPICIOUS_PORTS
        if bad_ports:
            threats.append({
                "type":     "suspicious_port",
                "severity": "critical",
                "detail":   f"Port lạ đang mở: {sorted(bad_ports)}",
            })

        # 4. Process đáng ngờ
        for proc in metrics["processes"]:
            if proc["name"].lower() in self.SUSPICIOUS_NAMES:
                threats.append({
                    "type":     "suspicious_process",
                    "severity": "critical",
                    "detail":   f"Process: {proc['name']} PID={proc['pid']}",
                })

        # 5. RAM nguy hiểm
        if metrics["memory"]["percent"] > 95:
            threats.append({
                "type":     "memory_critical",
                "severity": "warning",
                "detail":   f"RAM {metrics['memory']['percent']}%",
            })

        # ── Docker threats ─────────────────────────────────────────
        docker = metrics.get("docker", {})
        if docker.get("available"):
            for c in docker.get("containers", []):
                # Container unhealthy
                if c.get("health") == "unhealthy":
                    threats.append({
                        "type":     "docker_unhealthy",
                        "severity": "warning",
                        "detail":   f"Container '{c['name']}' unhealthy (image: {c['image']})",
                    })

                # Container restart loop (>3 restarts)
                if c.get("restart_count", 0) > 3:
                    threats.append({
                        "type":     "docker_restart_loop",
                        "severity": "critical",
                        "detail":   f"Container '{c['name']}' đã restart {c['restart_count']} lần",
                    })

                # Container CPU > 80%
                if c.get("cpu_percent", 0) > 80:
                    threats.append({
                        "type":     "docker_cpu_high",
                        "severity": "warning",
                        "detail":   f"Container '{c['name']}' CPU={c['cpu_percent']:.1f}%",
                    })

                # Container MEM > 90%
                if c.get("mem_percent", 0) > 90:
                    threats.append({
                        "type":     "docker_mem_high",
                        "severity": "warning",
                        "detail":   f"Container '{c['name']}' MEM={c['mem_percent']:.1f}%",
                    })

                # Lỗi trong log container
                if c.get("log_error_count", 0) > 5:
                    threats.append({
                        "type":     "docker_log_errors",
                        "severity": "warning",
                        "detail":   f"Container '{c['name']}' có {c['log_error_count']} lỗi trong log gần đây",
                    })

                # Hành vi nguy hiểm trong container
                if c.get("dangerous_activity"):
                    for danger in c["dangerous_activity"]:
                        threats.append({
                            "type":     "docker_dangerous",
                            "severity": "critical",
                            "detail":   f"Container '{c['name']}' — {danger['line'][:100]}",
                        })

                # Container exit bất thường (exit code != 0)
                if c.get("state") == "exited" and c.get("exit_code", 0) != 0:
                    threats.append({
                        "type":     "docker_crash",
                        "severity": "warning",
                        "detail":   f"Container '{c['name']}' exited với code {c['exit_code']}",
                    })

            # Quá nhiều container unhealthy
            summary = docker.get("summary", {})
            if summary.get("unhealthy", 0) > 2:
                threats.append({
                    "type":     "docker_cluster_issue",
                    "severity": "critical",
                    "detail":   f"{summary['unhealthy']} containers unhealthy / {summary['total']} tổng",
                })

        return threats


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD & GỬI DỮ LIỆU
# ══════════════════════════════════════════════════════════════════════════════

def build_payload(metrics: dict) -> dict:
    """Đóng gói payload có checksum để server verify."""
    payload = {
        "host":      HOSTNAME,
        "os":        OS_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics":   metrics,
    }
    raw = json.dumps(payload, sort_keys=True)
    payload["checksum"] = hashlib.sha256(raw.encode()).hexdigest()
    return payload


class DataSender:
    """
    Gửi payload về server, có buffer local nếu mất kết nối.
    Khi kết nối lại, tự động gửi queue tồn đọng.
    """

    def __init__(self, server_url: str, token: str):
        self.url    = server_url.rstrip("/") + "/api/metrics"
        self.token  = token
        self.queue: deque = deque(maxlen=500)   # buffer tối đa 500 bản tin
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "X-Agent-Host":  HOSTNAME,
        })

    def send(self, payload: dict) -> dict | None:
        # Gửi queue tồn đọng trước
        while self.queue:
            old = self.queue[0]
            if self._post(old):
                self.queue.popleft()
            else:
                break

        return self._post(payload)

    def _post(self, payload: dict) -> dict | None:
        try:
            r = self.session.post(
                self.url,
                data=json.dumps(payload),
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            log.warning("Server trả về %d", r.status_code)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            log.warning("Mất kết nối / timeout đến server — buffer payload")
            self.queue.append(payload)
        except Exception as e:
            log.error("Lỗi gửi dữ liệu: %s", e)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# FIM — File Integrity Monitoring
# ══════════════════════════════════════════════════════════════════════════════

# HOST_ROOT cho phép chạy trong container nhưng vẫn theo dõi filesystem của host.
# Set HOST_ROOT=/host và mount /:/host:ro (hoặc các path con) trong docker-compose.
# Khi rỗng, agent đọc trực tiếp filesystem hiện tại (chạy native trên host).
HOST_ROOT = os.getenv("HOST_ROOT", "").rstrip("/")


def _hp(path: str) -> str:
    """Áp HOST_ROOT prefix nếu cần (cho việc đọc file host từ container)."""
    return f"{HOST_ROOT}{path}" if HOST_ROOT else path


def _strip_host(path: str) -> str:
    """Strip HOST_ROOT khi report, để user thấy path thật trên host."""
    if HOST_ROOT and path.startswith(HOST_ROOT):
        return path[len(HOST_ROOT):] or "/"
    return path


# Paths cần watch (tuỳ OS). File quan trọng: auth config, ssh config, cron, binaries.
FIM_PATHS_LINUX = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts", "/etc/hostname",
    "/etc/crontab",
    "/etc/pam.d/sshd",
    "/etc/nginx/nginx.conf",
    "/usr/bin/ssh", "/usr/bin/sudo", "/usr/bin/su",
    "/bin/bash", "/bin/sh",
]

FIM_DIRS_LINUX = [
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
    "/root/.ssh",
]


# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# TOPOLOGY — phát hiện dependency giữa các host/service qua outbound connections
# ══════════════════════════════════════════════════════════════════════════════

def collect_topology() -> dict:
    """
    Gom các outbound connection đang ESTABLISHED theo (dest_ip, dest_port).
    Server sẽ aggregate từ nhiều host để dựng graph.
    """
    edges: dict = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != "ESTABLISHED" or not c.raddr:
                continue
            key = f"{c.raddr.ip}:{c.raddr.port}"
            if key not in edges:
                edges[key] = {"ip": c.raddr.ip, "port": c.raddr.port, "count": 0, "pids": set()}
            edges[key]["count"] += 1
            if c.pid:
                edges[key]["pids"].add(c.pid)
    except psutil.AccessDenied:
        pass
    # Chuyển set → list để json-serializable
    return {
        "edges": [
            {**v, "pids": list(v["pids"])[:10]}
            for v in edges.values()
        ][:200],  # giới hạn 200 edges / host / snapshot
    }


# ══════════════════════════════════════════════════════════════════════════════
# VÒNG LẶP CHÍNH
# ══════════════════════════════════════════════════════════════════════════════

def run(server_url: str, token: str, interval: int):
    log.info("ServerWatch Agent khởi động — host=%s  server=%s", HOSTNAME, server_url)

    docker_collector = DockerCollector()
    threat_det       = LocalThreatDetector()
    sender           = DataSender(server_url, token)

    iter_count = 0

    # Khởi động cpu_percent (lần đầu trả 0.0)
    psutil.cpu_percent(interval=None)

    while True:
        start = time.time()
        iter_count += 1
        try:
            # Thu thập
            metrics = {
                "cpu":       collect_cpu(),
                "memory":    collect_memory(),
                "disk":      collect_disk(),
                "network":   collect_network(),
                "processes": collect_processes(),
                "process_names": collect_process_names(),
                "ports":     collect_open_ports(),
                "docker":    docker_collector.collect(),
                "topology":  collect_topology(),
            }


            # Phân tích local
            metrics["threats"] = threat_det.analyze(metrics)

            if metrics["threats"]:
                for t in metrics["threats"]:
                    log.warning("[%s] %s — %s",
                                t["severity"].upper(), t["type"], t["detail"])

            # Đóng gói và gửi
            payload = build_payload(metrics)
            response = sender.send(payload)
            log.debug("Gửi payload %s", "OK" if response else "QUEUED")

        except Exception as e:
            log.error("Lỗi thu thập: %s", e, exc_info=True)

        # Chờ đến chu kỳ tiếp theo
        elapsed = time.time() - start
        wait    = max(0, interval - elapsed)
        time.sleep(wait)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ServerWatch Agent")
    parser.add_argument("--server",   default=DEFAULT_SERVER,
                        help="URL server trung tâm")
    parser.add_argument("--token",    default="changeme",
                        help="Bearer token xác thực")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help="Chu kỳ thu thập (giây)")
    args = parser.parse_args()

    run(args.server, args.token, args.interval)


if __name__ == "__main__":
    main()
