# ═══════════════════════════════════════════════════════════
# ServerWatch (lean) — Multi-stage Dockerfile
# Stage 1: base
# Stage 2: server (API + dashboard)
# Stage 3: agent (chạy trên từng host cần giám sát)
# ═══════════════════════════════════════════════════════════

# ── Base ──────────────────────────────────────────────────
FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# ── Server (API + Dashboard) ─────────────────────────────
FROM base AS server

COPY server.py anomaly.py dashboard.html \
     alert_state.py monitors.py metrics_ts.py \
     backup.py settings.py ./
COPY vendor ./vendor

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

EXPOSE 8000

# workers=1 cố ý: background tasks (cleanup, backup, monitors, auto_resolve)
# chạy trong lifespan của process server — nhiều worker sẽ duplicate chúng và
# tranh chấp ghi SQLite. Endpoint POST/GET đều async nên 1 worker async event-loop
# đủ xử lý >100 req/s cho workload monitoring (target 5-50 host).
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]


# ── Agent (deploy trên từng host cần giám sát) ──────────
FROM base AS agent

# Agent cần docker CLI để giám sát containers (qua socket mount từ host).
RUN apt-get update && \
    apt-get install -y --no-install-recommends docker-cli && \
    rm -rf /var/lib/apt/lists/*

COPY agent.py ./

CMD ["python", "agent.py"]
