# ServerWatch

> Hệ thống giám sát server **self-hosted** gọn nhẹ — một server + nhiều agent + dashboard realtime, cảnh báo qua Telegram/Email.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)

🇬🇧 [English version](README.md)

---

## ✨ Tính năng

### Thu thập (Agent — cross-platform Linux/Windows)
- **CPU / RAM / Disk / Network** — usage tổng + per-core, load average, IO rate
- **Process & Open ports** — top processes, port scan baseline
- **Docker containers** — status, restart count, logs, resource per container
- **Topology** — phát hiện kết nối ra ngoài (outbound IPs)
- **Batch gửi** — gộp 6 sample/phút giảm bandwidth

### Server (FastAPI + SQLite)
- **Time-series ring-buffer** trong SQLite (không cần InfluxDB)
- **JWT auth** + RBAC user/admin, đổi password, quản lý user
- **WebSocket** push metrics realtime cho dashboard
- **REST API** đầy đủ (50+ endpoints)
- **Backup** SQLite + audit dir tarball, verify, retention configurable

### Phát hiện bất thường
- **Anomaly detection** — Z-score sliding window (không cần ML library)
- **Port scan detector** — phát hiện dò port hàng loạt
- **Synthetic monitors** — SSL cert expiry, WHOIS domain expiry, HTTP/TCP probes

### Cảnh báo
- **Telegram bot** + **Email SMTP**
- **Dedup + silence + auto-resolve** — chống alert flood
- **Acknowledge** từ dashboard hoặc API

### Dashboard
- **Single-file HTML** — không cần npm build
- **Sidebar đa-host** — switch nhanh giữa các server
- **Charts realtime** qua WebSocket

---

## 🏗️ Kiến trúc

```
┌─────────────────┐         metrics POST          ┌──────────────────────┐
│  Agent (host A) │ ────────────────────────────▶ │                      │
└─────────────────┘                               │   ServerWatch API    │
┌─────────────────┐         metrics POST          │   (FastAPI)          │
│  Agent (host B) │ ────────────────────────────▶ │  ┌────────────────┐  │
└─────────────────┘                               │  │  SQLite        │  │
┌─────────────────┐         metrics POST          │  │  - metrics_ts  │  │
│  Agent (host C) │ ────────────────────────────▶ │  │  - alerts      │  │
└─────────────────┘                               │  │  - users       │  │
                                                  │  └────────────────┘  │
┌─────────────────┐  ◀──WebSocket /ws──┐          │                      │
│  Dashboard HTML │  ──REST /api/*───▶ │          │   Anomaly Engine     │
└─────────────────┘                    │          │   Alert Engine       │
                                       └─────────▶│   Synthetic Monitors │
                                                  └──────┬───────────────┘
                                                         │
                                            ┌────────────┴────────────┐
                                            ▼                         ▼
                                     ┌──────────────┐         ┌──────────────┐
                                     │ Telegram Bot │         │  Email SMTP  │
                                     └──────────────┘         └──────────────┘
```

---

## 🚀 Quick start

### Yêu cầu
- Docker + Docker Compose v2
- Ubuntu 20.04+ / Debian 11+ (server) — Windows cũng chạy được agent
- (Tuỳ chọn) Domain + SSL cert nếu muốn expose dashboard public

### 1 lệnh deploy với Docker Compose

```bash
git clone https://github.com/baongockyty2404/serverwatch-lean.git
cd serverwatch-lean

# Tạo .env từ template và điền token/password
cp .env.example .env
nano .env

# Sinh SECRET_TOKEN ngẫu nhiên 64 ký tự
openssl rand -hex 32

# Tạo network external (1 lần)
docker network create web-proxy

# Deploy
chmod +x deploy.sh
./deploy.sh --full
```

Mở `https://YOUR_DOMAIN` → login với `ADMIN_EMAIL` / `ADMIN_PASSWORD` đã đặt trong `.env`.

### Cài agent trên server khác

```bash
pip install psutil requests
python3 agent.py \
    --server https://YOUR_DOMAIN \
    --token YOUR_SECRET_TOKEN \
    --interval 10
```

Hoặc dùng systemd service mẫu: [`serverwatch-agent.service`](serverwatch-agent.service)

---

## ⚙️ Cấu hình quan trọng (`.env`)

| Biến | Mô tả |
|---|---|
| `SECRET_TOKEN` | Token agent ↔ server (64 ký tự ngẫu nhiên) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Tài khoản admin dashboard |
| `JWT_SECRET` | Secret JWT (để trống = dùng `SECRET_TOKEN`) |
| `ALLOWED_ORIGINS` | Domain được phép CORS |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Cảnh báo qua Telegram |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` | Cảnh báo qua email |
| `METRICS_RETENTION_HOURS` | Giữ metrics bao lâu (mặc định 48h) |
| `BACKUP_HOUR_UTC` | Giờ chạy backup tự động (UTC) |

Xem đầy đủ trong [`.env.example`](.env.example).

---

## 🛡️ Bảo mật

- **Đổi `SECRET_TOKEN` ngay** trước khi deploy (`openssl rand -hex 32`)
- Chỉ bind nội bộ `127.0.0.1:8800` — expose qua reverse proxy HTTPS
- Dùng `fail2ban` chặn brute force SSH
- Rotate token định kỳ 3 tháng

---

## 🛠️ Stack công nghệ

- **Backend**: Python 3.12, FastAPI, SQLite (WAL mode), aiohttp
- **Agent**: psutil, requests, threading (cross-platform)
- **Frontend**: Vanilla JS + Chart.js (CDN), không build step
- **Deploy**: Docker multi-stage, systemd, nginx reverse proxy
- **Notification**: Telegram Bot API, SMTP

---

## 🤝 Đóng góp

PR / Issue đều welcome! Một vài hướng đang cần:
- Tách `server.py` (1500 dòng) thành package `server/`
- Thêm test suite (`pytest` + smoke test endpoints)
- GitHub Actions: lint (`ruff`) + build Docker image
- README song ngữ Anh chi tiết hơn

---

## 📜 License

MIT — xem [LICENSE](LICENSE).

Copyright © 2026 [baongockyty2404](https://github.com/baongockyty2404)
