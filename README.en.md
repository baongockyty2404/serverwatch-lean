# ServerWatch

> Lightweight **self-hosted** server monitoring — one server + many agents + realtime dashboard, with Telegram/Email alerting.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)

🇻🇳 [Phiên bản tiếng Việt](README.md)

---

## ✨ Features

### Collection (Agent — cross-platform Linux/Windows)
- **CPU / RAM / Disk / Network** — total + per-core usage, load average, IO rate
- **Processes & Open ports** — top processes, port scan baseline
- **Docker containers** — status, restart count, logs, per-container resources
- **Topology** — detect outbound connections
- **Batch sending** — 6 samples/min to save bandwidth

### Server (FastAPI + SQLite)
- **Time-series ring-buffer** in SQLite (no InfluxDB required)
- **JWT auth** + RBAC user/admin, password change, user management
- **WebSocket** realtime metrics push to dashboard
- **REST API** with 50+ endpoints
- **Backup** SQLite + audit dir tarball, verify, configurable retention

### Anomaly detection
- **Z-score sliding window** — no ML library needed
- **Port scan detector**
- **Synthetic monitors** — SSL cert expiry, WHOIS domain expiry, HTTP/TCP probes

### Alerting
- **Telegram bot** + **Email SMTP**
- **Dedup + silence + auto-resolve** — anti alert-flood
- **Acknowledge** from dashboard or API

### Dashboard
- **Single-file HTML** — no npm build required
- **Multi-host sidebar** — quickly switch between servers
- **Realtime charts** via WebSocket

---

## 🏗️ Architecture

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

### Requirements
- Docker + Docker Compose v2
- Ubuntu 20.04+ / Debian 11+ (server) — Windows is fine for agent
- (Optional) Domain + SSL cert if you want to expose dashboard publicly

### One-command deploy

```bash
git clone https://github.com/baongockyty2404/serverwatch-lean.git
cd serverwatch-lean

# Create .env from template, fill in tokens/passwords
cp .env.example .env
nano .env

# Generate a random 64-char SECRET_TOKEN
openssl rand -hex 32

# Create external network (one-time)
docker network create web-proxy

# Deploy
chmod +x deploy.sh
./deploy.sh --full
```

Open `https://YOUR_DOMAIN` → log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env`.

### Install agent on another server

```bash
pip install psutil requests
python3 agent.py \
    --server https://YOUR_DOMAIN \
    --token YOUR_SECRET_TOKEN \
    --interval 10
```

Or use the systemd template: [`serverwatch-agent.service`](serverwatch-agent.service)

---

## ⚙️ Key configuration (`.env`)

| Variable | Description |
|---|---|
| `SECRET_TOKEN` | Agent ↔ server token (random 64 chars) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Dashboard admin account |
| `JWT_SECRET` | JWT secret (empty = reuse `SECRET_TOKEN`) |
| `ALLOWED_ORIGINS` | CORS allowed domains |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Telegram alerts |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` | Email alerts |
| `METRICS_RETENTION_HOURS` | Metrics retention (default 48h) |
| `BACKUP_HOUR_UTC` | Auto-backup hour (UTC) |

See full list in [`.env.example`](.env.example).

---

## 🛡️ Security

- **Rotate `SECRET_TOKEN`** before deploying (`openssl rand -hex 32`)
- Bind only to `127.0.0.1:8800` — expose through HTTPS reverse proxy
- Use `fail2ban` to block SSH brute force
- Rotate tokens every 3 months

---

## 🛠️ Tech stack

- **Backend**: Python 3.12, FastAPI, SQLite (WAL mode), aiohttp
- **Agent**: psutil, requests, threading (cross-platform)
- **Frontend**: Vanilla JS + Chart.js (CDN), no build step
- **Deploy**: Docker multi-stage, systemd, nginx reverse proxy
- **Notification**: Telegram Bot API, SMTP

---

## 🤝 Contributing

PRs and issues welcome! Areas that need help:
- Split `server.py` (1500 lines) into a `server/` package
- Add a test suite (`pytest` + endpoint smoke tests)
- GitHub Actions: lint (`ruff`) + build Docker image
- English translation of detailed docs

---

## 📜 License

MIT — see [LICENSE](LICENSE).

Copyright © 2026 [baongockyty2404](https://github.com/baongockyty2404)
