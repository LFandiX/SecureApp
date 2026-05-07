#!/usr/bin/env bash
# ============================================================
#  deploy_secure.sh — IBDA3202 Store Automated Deployment (SECURE ONLY)
# ============================================================

set -euo pipefail

# ── Warna output ─────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
log_section() { echo -e "\n${BLUE}${BOLD}══ $1 ══${NC}"; }

# ── Pastikan dijalankan sebagai root ──────────────────────────
[[ $EUID -ne 0 ]] && log_error "Script ini harus dijalankan sebagai root (sudo ./deploy_secure.sh)"

# ── Konfigurasi ───────────────────────────────────────────────
# DEPLOY_DIR adalah folder tempat script ini berada (/deployment)
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"

# SECURE_SRC adalah satu tingkat di atas DEPLOY_DIR (yaitu folder IBDA3202_Secure)
SECURE_SRC="$(dirname "$DEPLOY_DIR")" 
SECURE_DEST="/var/www/ibda3202-secure"
LOG_DIR="/var/log/ibda3202"
APP_USER="ibda3202"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 1: Update Sistem & Install Dependensi"
# ══════════════════════════════════════════════════════════════
apt update -qq
apt install -y python3 python3-pip python3-venv nginx ufw curl
log_info "Dependensi sistem terinstall"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 2: Setup User & Direktori"
# ══════════════════════════════════════════════════════════════
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    log_info "User '$APP_USER' dibuat"
fi

mkdir -p "$SECURE_DEST/static/uploads"
mkdir -p "$LOG_DIR"
log_info "Direktori aplikasi dibuat"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 3: Deploy File Aplikasi"
# ══════════════════════════════════════════════════════════════
if [[ -d "$SECURE_SRC" ]]; then
    cp -r "$SECURE_SRC"/. "$SECURE_DEST/"
    log_info "App aman disalin ke $SECURE_DEST"
else
    log_error "Folder $SECURE_SRC tidak ditemukan!"
fi

chown -R "$APP_USER:$APP_USER" "$SECURE_DEST" "$LOG_DIR"
chmod 750 "$SECURE_DEST/static/uploads"
log_info "Permission diset"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 4: Virtual Environment & Packages"
# ══════════════════════════════════════════════════════════════
cd "$SECURE_DEST"
sudo -u "$APP_USER" python3 -m venv venv
sudo -u "$APP_USER" ./venv/bin/pip install -q -r requirements.txt
sudo -u "$APP_USER" ./venv/bin/pip install -q gunicorn
log_info "Virtualenv & packages OK"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 5: Generate Secret Keys (.env)"
# ══════════════════════════════════════════════════════════════
if [[ ! -f "$SECURE_DEST/.env" ]]; then
    IBDA3202_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")

    cat > "$SECURE_DEST/.env" <<EOF
IBDA3202_SECRET=${IBDA3202_SECRET}
FLASK_SECRET=${FLASK_SECRET}
FLASK_PORT=5001
FLASK_DEBUG=false
EOF
    chown "$APP_USER:$APP_USER" "$SECURE_DEST/.env"
    chmod 640 "$SECURE_DEST/.env"
    log_info ".env dibuat"
fi

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 6: Inisialisasi Database"
# ══════════════════════════════════════════════════════════════
sudo -u "$APP_USER" ./venv/bin/python -c "from app import app, init_db; init_db()"
log_info "Database diinisialisasi"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 7: Install Systemd Service"
# ══════════════════════════════════════════════════════════════
# Pastikan file service sudah ada di folder /systemd/
cp "${DEPLOY_DIR}/systemd/ibda3202-secure.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable ibda3202-secure
systemctl start  ibda3202-secure

sleep 2
systemctl is-active --quiet ibda3202-secure && log_info "Gunicorn aman aktif di port 5001"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 8: Konfigurasi Nginx"
# ══════════════════════════════════════════════════════════════
cp "${DEPLOY_DIR}/nginx/ibda3202-secure.conf" /etc/nginx/sites-available/
ln -sf /etc/nginx/sites-available/ibda3202-secure.conf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

if nginx -t 2>/dev/null; then
    systemctl reload nginx
    log_info "Nginx OK"
fi

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 9: Firewall & Log Rotate"
# ══════════════════════════════════════════════════════════════
ufw allow 22/tcp
ufw allow 80/tcp
ufw --force enable

cat > /etc/logrotate.d/ibda3202 <<'EOF'
/var/log/ibda3202/*.log {
    daily
    rotate 7
    compress
    missingok
    create 640 ibda3202 ibda3202
    postrotate
        systemctl kill -s HUP ibda3202-secure 2>/dev/null || true
    endscript
}
EOF
log_info "Firewall & Log Rotate OK"

log_section "SELESAI"
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "${GREEN}${BOLD}Aplikasi Aman: http://${SERVER_IP}/${NC}"
