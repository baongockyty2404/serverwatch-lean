#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# ServerWatch — Script triển khai (Docker Compose)
# Domain mẫu: monitor.example.com (đổi trong .env / biến DOMAIN)
#
# Sử dụng:
#   chmod +x deploy.sh
#   ./deploy.sh                # Deploy cơ bản (server + nginx)
#   ./deploy.sh --telegram     # + Telegram bot
#   ./deploy.sh --agent        # + Agent local (giám sát host này)
#   ./deploy.sh --full         # Tất cả
#   ./deploy.sh --inject-nginx # Cấu hình external-nginx proxy
#   ./deploy.sh --stop         # Dừng tất cả
#   ./deploy.sh --status       # Kiểm tra trạng thái
#   ./deploy.sh --logs         # Xem logs
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOMAIN="monitor.example.com"
MAIN_NGINX="external-nginx"

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
info() { echo -e "${CYAN}[→]${NC} $*"; }

# ── Kiểm tra prerequisites ──────────────────────────────────
check_deps() {
    command -v docker >/dev/null 2>&1 || err "Docker chưa cài. Cài tại: https://docs.docker.com/get-docker/"
    docker compose version >/dev/null 2>&1 || err "Docker Compose v2 chưa cài."
    docker info >/dev/null 2>&1 || err "Docker daemon không chạy. Chạy: sudo systemctl start docker"
    log "Docker OK ($(docker --version | cut -d' ' -f3))"
}

# ── Kiểm tra web-proxy network ──────────────────────────────
check_network() {
    if ! docker network inspect web-proxy >/dev/null 2>&1; then
        warn "Network 'web-proxy' chưa tồn tại — tạo mới"
        docker network create web-proxy
        log "Network 'web-proxy' đã tạo"
    else
        log "Network 'web-proxy' OK"
    fi
}

# ── Tạo .env nếu chưa có ────────────────────────────────────
setup_env() {
    if [ ! -f .env ]; then
        warn "Chưa có file .env — tạo từ .env.example"
        cp .env.example .env

        # Tự động sinh SECRET_TOKEN
        TOKEN=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | xxd -p | head -c 64)
        sed -i "s/CHANGE_THIS_TO_RANDOM_64_CHAR_STRING/$TOKEN/g" .env

        log "File .env đã tạo với token ngẫu nhiên"
        warn "Mở .env để cấu hình Telegram/Email nếu cần:"
        echo "    nano .env"
        echo ""
    else
        log "File .env đã tồn tại"
    fi
}

# ── Tạo thư mục cần thiết ───────────────────────────────────
setup_dirs() {
    mkdir -p data backup 2>/dev/null || true
    log "Thư mục OK"
}

# ── Inject config vào external-nginx ────────────────────────
inject_nginx() {
    info "Cấu hình ${DOMAIN} trên ${MAIN_NGINX}..."

    # Kiểm tra external-nginx đang chạy
    if ! docker ps --format '{{.Names}}' | grep -q "^${MAIN_NGINX}$"; then
        err "${MAIN_NGINX} không đang chạy. Khởi động nó trước."
    fi

    # Copy config vào container
    docker cp "${SCRIPT_DIR}/monitor.example.com.conf" \
        "${MAIN_NGINX}:/etc/nginx/conf.d/monitor.example.com.conf"

    # Test config
    if docker exec "${MAIN_NGINX}" nginx -t 2>&1; then
        # Reload nginx
        docker exec "${MAIN_NGINX}" nginx -s reload
        log "Nginx config cho ${DOMAIN} đã được cài đặt và reload"
    else
        err "Nginx config lỗi! Kiểm tra lại monitor.example.com.conf"
    fi
}

# ── Build & Deploy ───────────────────────────────────────────
deploy() {
    local profiles=()

    case "${1:-basic}" in
        --full)
            profiles=("--profile" "telegram" "--profile" "agent-local")
            info "Deploy FULL: Server + Nginx + Telegram + Agent"
            ;;
        --telegram)
            profiles=("--profile" "telegram")
            info "Deploy: Server + Nginx + Telegram"
            ;;
        --agent)
            profiles=("--profile" "agent-local")
            info "Deploy: Server + Nginx + Agent local"
            ;;
        *)
            info "Deploy CƠ BẢN: Server + Nginx"
            ;;
    esac

    echo ""
    info "Building images..."
    docker compose "${profiles[@]}" build --parallel 2>&1 | tail -5

    echo ""
    info "Starting services..."
    docker compose "${profiles[@]}" up -d

    echo ""

    # Tự động inject nginx config
    info "Chờ services khởi động..."
    sleep 5
    inject_nginx

    echo ""
    log "Deploy thành công!"
    echo ""
    show_status
    show_urls
}

# ── Trạng thái ───────────────────────────────────────────────
show_status() {
    echo -e "${CYAN}═══ Trạng thái services ═══${NC}"
    docker compose ps -a 2>/dev/null || true
    echo ""
}

show_urls() {
    echo -e "${CYAN}═══ Truy cập ═══${NC}"
    echo -e "  Dashboard:  ${GREEN}https://${DOMAIN}${NC}"
    echo -e "  API:        ${GREEN}https://${DOMAIN}/api/summary${NC}"
    echo -e "  Health:     ${GREEN}https://${DOMAIN}/health${NC}"
    echo ""
    echo -e "${CYAN}═══ Agent cho host khác ═══${NC}"

    # Đọc token từ .env
    local token
    token=$(grep '^SECRET_TOKEN=' .env 2>/dev/null | cut -d= -f2 || echo "YOUR_TOKEN")
    local server_ip
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_SERVER_IP")

    echo -e "  Cài agent trên host cần giám sát:"
    echo -e "  ${YELLOW}pip install psutil requests${NC}"
    echo -e "  ${YELLOW}python agent.py --server https://${DOMAIN} --token ${token}${NC}"
    echo ""
}

# ── Dừng ─────────────────────────────────────────────────────
stop_all() {
    info "Dừng tất cả services..."
    docker compose --profile telegram --profile agent-local down
    log "Đã dừng tất cả"
}

# ── Xem logs ─────────────────────────────────────────────────
show_logs() {
    docker compose logs -f --tail=50 "${@:2}"
}

# ── Cập nhật (rebuild + restart) ─────────────────────────────
update() {
    info "Rebuilding..."
    docker compose build --parallel
    docker compose up -d
    log "Cập nhật xong"
    show_status
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   ServerWatch — ${DOMAIN}   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

case "${1:-}" in
    --stop)
        stop_all
        ;;
    --status)
        show_status
        show_urls
        ;;
    --logs)
        show_logs "$@"
        ;;
    --update)
        check_deps
        update
        ;;
    --inject-nginx)
        inject_nginx
        ;;
    --help|-h)
        echo "Sử dụng:"
        echo "  ./deploy.sh              Deploy cơ bản (Server + Nginx)"
        echo "  ./deploy.sh --telegram   + Telegram bot"
        echo "  ./deploy.sh --agent      + Agent giám sát host này"
        echo "  ./deploy.sh --full       Tất cả services"
        echo "  ./deploy.sh --inject-nginx  Cài config vào external-nginx"
        echo "  ./deploy.sh --stop       Dừng tất cả services"
        echo "  ./deploy.sh --status     Xem trạng thái"
        echo "  ./deploy.sh --logs       Xem logs (thêm tên service để lọc)"
        echo "  ./deploy.sh --update     Rebuild và restart"
        ;;
    *)
        check_deps
        check_network
        setup_env
        setup_dirs
        deploy "${1:-basic}"
        ;;
esac
