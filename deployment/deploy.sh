#!/usr/bin/env bash
# ============================================================
#  deploy.sh — IBDA3202 Store Automated Deployment
#  Tested on: Ubuntu 22.04 LTS
#
#  Usage:
#    chmod +x deploy.sh
#    sudo ./deploy.sh
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
[[ $EUID -ne 0 ]] && log_error "Script ini harus dijalankan sebagai root (sudo ./deploy.sh)"

# ── Konfigurasi ───────────────────────────────────────────────
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
VULN_SRC="${DEPLOY_DIR}/../IBDA3202_Store"
SECURE_SRC="${DEPLOY_DIR}/../IBDA3202_Secure"
VULN_DEST="/var/www/ibda3202-vuln"
SECURE_DEST="/var/www/ibda3202-secure"
LOG_DIR="/var/log/ibda3202"
APP_USER="ibda3202"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 1: Update Sistem & Install Dependensi"
# ══════════════════════════════════════════════════════════════

apt update -qq
apt install -y python3 python3-pip python3-venv nginx ufw fail2ban curl wget
log_info "Dependensi sistem terinstall"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 2: Setup User & Direktori"
# ══════════════════════════════════════════════════════════════

# Buat user sistem khusus (no shell, no home)
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    log_info "User '$APP_USER' dibuat"
else
    log_warn "User '$APP_USER' sudah ada, dilewati"
fi

# Buat direktori
mkdir -p "$VULN_DEST"   "$VULN_DEST/static/uploads"
mkdir -p "$SECURE_DEST" "$SECURE_DEST/static/uploads"
mkdir -p "$LOG_DIR"
log_info "Direktori aplikasi dibuat"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 3: Deploy File Aplikasi"
# ══════════════════════════════════════════════════════════════

# Salin app rentan
if [[ -d "$VULN_SRC" ]]; then
    cp -r "$VULN_SRC"/. "$VULN_DEST/"
    log_info "App rentan disalin ke $VULN_DEST"
else
    log_error "Folder $VULN_SRC tidak ditemukan!"
fi

# Salin app aman
if [[ -d "$SECURE_SRC" ]]; then
    cp -r "$SECURE_SRC"/. "$SECURE_DEST/"
    log_info "App aman disalin ke $SECURE_DEST"
else
    log_error "Folder $SECURE_SRC tidak ditemukan!"
fi

# Set ownership
chown -R "$APP_USER:$APP_USER" "$VULN_DEST" "$SECURE_DEST" "$LOG_DIR"

# Permission ketat
chmod 750 "$VULN_DEST/static/uploads"
chmod 750 "$SECURE_DEST/static/uploads"
chmod 640 "$SECURE_DEST/.env" 2>/dev/null || true
log_info "Permission file diset"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 4: Virtual Environment & Install Packages"
# ══════════════════════════════════════════════════════════════

# App rentan
cd "$VULN_DEST"
sudo -u "$APP_USER" python3 -m venv venv
sudo -u "$APP_USER" ./venv/bin/pip install -q -r requirements.txt
sudo -u "$APP_USER" ./venv/bin/pip install -q gunicorn
log_info "App rentan: virtualenv & packages OK"

# App aman
cd "$SECURE_DEST"
sudo -u "$APP_USER" python3 -m venv venv
sudo -u "$APP_USER" ./venv/bin/pip install -q -r requirements.txt
sudo -u "$APP_USER" ./venv/bin/pip install -q gunicorn
log_info "App aman: virtualenv & packages OK"

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
    log_info ".env dibuat dengan secret keys baru"
else
    log_warn ".env sudah ada, dilewati (hapus manual jika ingin reset)"
fi

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 6: Inisialisasi Database"
# ══════════════════════════════════════════════════════════════

cd "$VULN_DEST"
sudo -u "$APP_USER" ./venv/bin/python -c "
from app import app, init_db
init_db()
" && log_info "Database app rentan diinisialisasi"

cd "$SECURE_DEST"
sudo -u "$APP_USER" ./venv/bin/python -c "
from app import app, init_db
init_db()
" && log_info "Database app aman diinisialisasi"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 7: Install Systemd Services"
# ══════════════════════════════════════════════════════════════

cp "${DEPLOY_DIR}/systemd/ibda3202-vuln.service"   /etc/systemd/system/
cp "${DEPLOY_DIR}/systemd/ibda3202-secure.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable ibda3202-vuln ibda3202-secure
systemctl start  ibda3202-vuln ibda3202-secure

sleep 2

if systemctl is-active --quiet ibda3202-vuln; then
    log_info "Gunicorn app rentan berjalan di port 5000"
else
    log_error "Gunicorn app rentan GAGAL start! Cek: journalctl -u ibda3202-vuln"
fi

if systemctl is-active --quiet ibda3202-secure; then
    log_info "Gunicorn app aman berjalan di port 5001"
else
    log_error "Gunicorn app aman GAGAL start! Cek: journalctl -u ibda3202-secure"
fi

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 8: Konfigurasi Nginx"
# ══════════════════════════════════════════════════════════════

cp "${DEPLOY_DIR}/nginx/ibda3202-vuln.conf"   /etc/nginx/sites-available/
cp "${DEPLOY_DIR}/nginx/ibda3202-secure.conf" /etc/nginx/sites-available/

# Enable sites
ln -sf /etc/nginx/sites-available/ibda3202-vuln.conf   /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/ibda3202-secure.conf /etc/nginx/sites-enabled/

# Hapus default site
rm -f /etc/nginx/sites-enabled/default

# Test konfigurasi Nginx
if nginx -t 2>/dev/null; then
    log_info "Konfigurasi Nginx valid"
    systemctl reload nginx
    log_info "Nginx di-reload"
else
    log_error "Konfigurasi Nginx error! Jalankan: nginx -t"
fi

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 9: Setup Firewall (UFW)"
# ══════════════════════════════════════════════════════════════

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow 80/tcp    comment "App Rentan (Red Team Target)"
ufw allow 8080/tcp  comment "App Aman (Monitoring)"
ufw --force enable
log_info "Firewall dikonfigurasi"

# ══════════════════════════════════════════════════════════════
log_section "LANGKAH 10: Setup Log Rotation"
# ══════════════════════════════════════════════════════════════

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
        systemctl kill -s HUP ibda3202-vuln  2>/dev/null || true
        systemctl kill -s HUP ibda3202-secure 2>/dev/null || true
    endscript
}
EOF
log_info "Log rotation dikonfigurasi"

# ══════════════════════════════════════════════════════════════
log_section "VERIFIKASI FINAL"
# ══════════════════════════════════════════════════════════════

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}Status Services:${NC}"
systemctl is-active ibda3202-vuln   && echo -e "  ${GREEN}✓${NC} ibda3202-vuln   (Gunicorn :5000)"  || echo -e "  ${RED}✗${NC} ibda3202-vuln   GAGAL"
systemctl is-active ibda3202-secure && echo -e "  ${GREEN}✓${NC} ibda3202-secure (Gunicorn :5001)"  || echo -e "  ${RED}✗${NC} ibda3202-secure GAGAL"
systemctl is-active nginx           && echo -e "  ${GREEN}✓${NC} nginx"                            || echo -e "  ${RED}✗${NC} nginx GAGAL"

echo ""
echo -e "${BOLD}HTTP Check:${NC}"
VULN_CODE=$(curl -o /dev/null -s -w "%{http_code}" http://127.0.0.1/)
SECURE_CODE=$(curl -o /dev/null -s -w "%{http_code}" http://127.0.0.1:8080/)
echo -e "  App Rentan  → HTTP ${VULN_CODE}"
echo -e "  App Aman    → HTTP ${SECURE_CODE}"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║       DEPLOYMENT BERHASIL! 🎉               ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}${BOLD}║${NC}  🔴 App Rentan  : http://${SERVER_IP}/        ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  🟢 App Aman    : http://${SERVER_IP}:8080/   ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Langkah selanjutnya:${NC}"
echo -e "  1. Install Wazuh Agent: ikuti DEPLOYMENT.md Langkah 8"
echo -e "  2. Salin rules Wazuh ke Manager: wazuh/ibda3202_rules.xml"
echo -e "  3. Monitor log: sudo tail -f /var/log/ibda3202/vuln.log"
echo ""
