#!/usr/bin/env bash
# ============================================================
#  deploy.sh — IBDA3202 Secure Store (Single App)
#  Ubuntu 22.04 LTS
#
#  Usage:
#    chmod +x deploy.sh
#    sudo ./deploy.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
log_section() { echo -e "\n${BLUE}${BOLD}══ $1 ══${NC}"; }

[[ $EUID -ne 0 ]] && log_error "Jalankan sebagai root: sudo ./deploy.sh"

# ── Konfigurasi ───────────────────────────────────────────────
# DEPLOY_DIR adalah folder tempat script berada (SecureApp/deployment)
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"

# APP_SRC adalah satu tingkat di atas direktori script (yaitu SecureApp/)
APP_SRC="$(dirname "$DEPLOY_DIR")" 

APP_DEST="/var/www/ibda3202-secure"
LOG_DIR="/var/log/ibda3202"
APP_USER="ibda3202"
APP_PORT="5001"
NGINX_PORT="80"

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║   IBDA3202 Secure Store — Production Deployment  ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════
log_section "1/9 Update Sistem & Install Dependensi"
# ══════════════════════════════════════════════════════════════

apt-get update -qq
apt-get install -y -q \
    python3 python3-pip python3-venv \
    nginx ufw fail2ban curl wget
log_info "Dependensi sistem OK"

# ══════════════════════════════════════════════════════════════
log_section "2/9 Setup User & Direktori"
# ══════════════════════════════════════════════════════════════

if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    log_info "User '$APP_USER' dibuat"
else
    log_warn "User '$APP_USER' sudah ada"
fi

mkdir -p "$APP_DEST/static/uploads" "$LOG_DIR"
chown -R "$APP_USER:$APP_USER" "$APP_DEST" "$LOG_DIR"
log_info "Direktori dibuat: $APP_DEST"

# ══════════════════════════════════════════════════════════════
log_section "3/9 Salin File Aplikasi"
# ══════════════════════════════════════════════════════════════

[[ ! -d "$APP_SRC" ]] && log_error "Folder aplikasi tidak ditemukan: $APP_SRC"

# Salin semua file kecuali venv dan db lama
rsync -a --exclude='venv/' --exclude='*.db' --exclude='*.log' \
    "$APP_SRC/" "$APP_DEST/"

chown -R "$APP_USER:$APP_USER" "$APP_DEST"
chmod 750 "$APP_DEST/static/uploads"
log_info "File aplikasi disalin ke $APP_DEST"

# ══════════════════════════════════════════════════════════════
log_section "4/9 Virtual Environment & Install Packages"
# ══════════════════════════════════════════════════════════════

cd "$APP_DEST"
sudo -u "$APP_USER" python3 -m venv venv
sudo -u "$APP_USER" ./venv/bin/pip install -q --upgrade pip
sudo -u "$APP_USER" ./venv/bin/pip install -q -r requirements.txt
sudo -u "$APP_USER" ./venv/bin/pip install -q gunicorn

log_info "Virtual environment & packages OK"
echo -e "  Python  : $(sudo -u $APP_USER ./venv/bin/python --version)"
echo -e "  Gunicorn: $(sudo -u $APP_USER ./venv/bin/gunicorn --version)"

# ══════════════════════════════════════════════════════════════
log_section "5/9 Generate Secret Keys & .env"
# ══════════════════════════════════════════════════════════════

ENV_FILE="$APP_DEST/.env"

if [[ -f "$ENV_FILE" ]]; then
    log_warn ".env sudah ada — dilewati. Hapus manual jika ingin generate ulang."
else
    IBDA3202_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")

    cat > "$ENV_FILE" <<EOF
# IBDA3202 Secure Store — Environment Variables
# Auto-generated: $(date '+%Y-%m-%d %H:%M:%S')
# JANGAN share atau commit file ini!

IBDA3202_SECRET=${IBDA3202_SECRET}
FLASK_SECRET=${FLASK_SECRET}
FLASK_PORT=${APP_PORT}
FLASK_DEBUG=false
EOF

    chown "$APP_USER:$APP_USER" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    log_info "Secret keys di-generate dan disimpan di .env"
fi

# ══════════════════════════════════════════════════════════════
log_section "6/9 Inisialisasi Database"
# ══════════════════════════════════════════════════════════════

cd "$APP_DEST"
sudo -u "$APP_USER" bash -c "
    source .env
    export IBDA3202_SECRET FLASK_SECRET
    ./venv/bin/python -c 'from app import app, init_db; init_db(); print(\"DB OK\")'
"
chown "$APP_USER:$APP_USER" "$APP_DEST"/*.db 2>/dev/null || true
log_info "Database diinisialisasi"

# ══════════════════════════════════════════════════════════════
log_section "7/9 Systemd Service"
# ══════════════════════════════════════════════════════════════

cp "${DEPLOY_DIR}/systemd/ibda3202.service" /etc/systemd/system/ibda3202.service

systemctl daemon-reload
systemctl enable ibda3202
systemctl restart ibda3202

sleep 3

if systemctl is-active --quiet ibda3202; then
    log_info "Gunicorn berjalan di 127.0.0.1:${APP_PORT}"
else
    log_error "Gunicorn GAGAL start! Cek: journalctl -u ibda3202 -n 50"
fi

# ══════════════════════════════════════════════════════════════
log_section "8/9 Nginx Reverse Proxy"
# ══════════════════════════════════════════════════════════════

cp "${DEPLOY_DIR}/nginx/ibda3202.conf" /etc/nginx/sites-available/ibda3202.conf

# Enable site, hapus default
ln -sf /etc/nginx/sites-available/ibda3202.conf /etc/nginx/sites-enabled/ibda3202.conf
rm -f /etc/nginx/sites-enabled/default

if nginx -t 2>/dev/null; then
    log_info "Konfigurasi Nginx valid"
    systemctl restart nginx
    systemctl enable nginx
    log_info "Nginx berjalan di port ${NGINX_PORT}"
else
    log_error "Konfigurasi Nginx error! Jalankan: sudo nginx -t"
fi

# ══════════════════════════════════════════════════════════════
log_section "9/9 Firewall & Log Rotation"
# ══════════════════════════════════════════════════════════════

# UFW
ufw --force reset > /dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "SSH"
ufw allow 80/tcp   comment "IBDA3202 Secure (HTTP)"
ufw --force enable
log_info "Firewall dikonfigurasi (port 22, 80)"

# Log rotation
cat > /etc/logrotate.d/ibda3202 <<'EOF'
/var/log/ibda3202/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 ibda3202 ibda3202
    postrotate
        systemctl kill -s HUP ibda3202 2>/dev/null || true
    endscript
}
EOF
log_info "Log rotation dikonfigurasi (30 hari)"

# ══════════════════════════════════════════════════════════════
# VERIFIKASI FINAL
# ══════════════════════════════════════════════════════════════

SERVER_IP=$(hostname -I | awk '{print $1}')
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" "http://127.0.0.1/")

echo ""
echo -e "${BOLD}Status Akhir:${NC}"
printf "  %-20s " "ibda3202 (Gunicorn):"
systemctl is-active ibda3202 && echo -e "${GREEN}running${NC}" || echo -e "${RED}FAILED${NC}"
printf "  %-20s " "nginx:"
systemctl is-active nginx    && echo -e "${GREEN}running${NC}" || echo -e "${RED}FAILED${NC}"
printf "  %-20s " "ufw:"
systemctl is-active ufw      && echo -e "${GREEN}active${NC}"  || echo -e "${YELLOW}inactive${NC}"
printf "  %-20s " "HTTP response:"
[[ "$HTTP_CODE" == "200" ]] && echo -e "${GREEN}200 OK${NC}" || echo -e "${YELLOW}${HTTP_CODE}${NC}"

echo ""

if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║       DEPLOYMENT BERHASIL! 🎉                 ║${NC}"
    echo -e "${GREEN}${BOLD}╠════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}${BOLD}║${NC}  🌐 URL : http://${SERVER_IP}/              "
    echo -e "${GREEN}${BOLD}║${NC}  👤 Admin: admin / Admin@12345              "
    echo -e "${GREEN}${BOLD}║${NC}  📋 Log : /var/log/ibda3202/app.log        "
    echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════╝${NC}"
else
    echo -e "${YELLOW}${BOLD}Deployment selesai tapi HTTP code ${HTTP_CODE}.${NC}"
    echo -e "Cek log: ${BOLD}sudo journalctl -u ibda3202 -n 30${NC}"
fi

echo ""
echo -e "${YELLOW}Langkah selanjutnya:${NC}"
echo -e "  1. Wazuh Agent: ikuti DEPLOYMENT.md Langkah 8"
echo -e "  2. Salin rules ke Wazuh Manager:"
echo -e "     ${BOLD}sudo cp wazuh/ibda3202_rules.xml /var/ossec/etc/rules/${NC}"
echo -e "  3. Monitor log real-time:"
echo -e "     ${BOLD}sudo tail -f /var/log/ibda3202/app.log${NC}"
echo ""
