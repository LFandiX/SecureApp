# 🚀 IBDA3202 Secure Store — Deployment Guide (Single App)
## Stack: Ubuntu 22.04 + Gunicorn + Nginx + Systemd + Wazuh

---

## 🏗️ Arsitektur

```
Internet
    ↓
[ Nginx :80 ]          ← Reverse proxy, blokir file sensitif
    ↓
[ Gunicorn :5001 ]     ← WSGI server (internal only, localhost)
    ↓
[ Flask App ]          ← IBDA3202 Secure Store
    ↓
[ app_secure.log ]     ← Log aktivitas
    ↓
[ Wazuh Agent ]        ← Kirim ke Wazuh Manager → Dashboard
```

---

## ⚡ Deploy Otomatis (Direkomendasikan)

```bash
# Pastikan struktur folder seperti ini:
# ├── IBDA3202_Secure/      ← folder app
# └── IBDA3202_Deploy_Secure/
#     ├── scripts/deploy.sh
#     ├── nginx/ibda3202.conf
#     ├── systemd/ibda3202.service
#     └── wazuh/

cd IBDA3202_Deploy_Secure/scripts
chmod +x deploy.sh
sudo ./deploy.sh
```

Script akan otomatis menjalankan semua langkah di bawah.

---

## 📋 Deploy Manual (Step by Step)

### 1. Install Dependensi

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    nginx ufw fail2ban
```

### 2. Buat User & Direktori

```bash
# User sistem khusus (no login, no shell)
sudo useradd --system --no-create-home --shell /bin/false ibda3202

# Direktori aplikasi dan log
sudo mkdir -p /var/www/ibda3202-secure/static/uploads
sudo mkdir -p /var/log/ibda3202
sudo chown -R ibda3202:ibda3202 /var/www/ibda3202-secure /var/log/ibda3202
```

### 3. Salin File Aplikasi

```bash
sudo rsync -a --exclude='venv/' --exclude='*.db' \
    /path/to/IBDA3202_Secure/ /var/www/ibda3202-secure/

sudo chown -R ibda3202:ibda3202 /var/www/ibda3202-secure
sudo chmod 750 /var/www/ibda3202-secure/static/uploads
```

### 4. Virtual Environment & Packages

```bash
cd /var/www/ibda3202-secure
sudo -u ibda3202 python3 -m venv venv
sudo -u ibda3202 ./venv/bin/pip install -q -r requirements.txt
sudo -u ibda3202 ./venv/bin/pip install -q gunicorn
```

### 5. Buat File .env

```bash
cd /var/www/ibda3202-secure

# Generate secret keys
IBDA3202_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")
FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")

sudo tee .env > /dev/null <<EOF
IBDA3202_SECRET=${IBDA3202_SECRET}
FLASK_SECRET=${FLASK_SECRET}
FLASK_PORT=5001
FLASK_DEBUG=false
EOF

sudo chown ibda3202:ibda3202 .env
sudo chmod 640 .env   # Hanya owner yang bisa baca
```

### 6. Inisialisasi Database

```bash
cd /var/www/ibda3202-secure
sudo -u ibda3202 bash -c "
    source .env
    ./venv/bin/python -c 'from app import app, init_db; init_db()'
"
```

### 7. Install & Jalankan Systemd Service

```bash
sudo cp /path/to/deploy/systemd/ibda3202.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ibda3202
sudo systemctl start  ibda3202

# Verifikasi
sudo systemctl status ibda3202
curl -s http://127.0.0.1:5001 | grep -o "IBDA3202"
```

### 8. Install & Reload Nginx

```bash
sudo cp /path/to/deploy/nginx/ibda3202.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/ibda3202.conf /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

sudo nginx -t        # Wajib — test config dulu
sudo systemctl restart nginx
sudo systemctl enable nginx

# Cek
curl -I http://localhost/
```

### 9. Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22    # SSH — JANGAN lupa ini!
sudo ufw allow 80    # HTTP
sudo ufw enable
sudo ufw status
```

### 10. Wazuh Agent

```bash
# Install agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --no-default-keyring \
        --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" | \
    sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update && sudo apt install wazuh-agent -y

# Arahkan ke Wazuh Manager
# Edit /var/ossec/etc/ossec.conf — ganti MANAGER_IP
sudo nano /var/ossec/etc/ossec.conf
# Cari: <address>MANAGER_IP</address>
# Ganti: <address>IP_WAZUH_MANAGER_ANDA</address>

# Tambah log monitoring
# Salin isi wazuh/ossec_localfile.xml ke ossec.conf
# (sebelum tag </ossec_config> penutup)

sudo systemctl enable wazuh-agent
sudo systemctl start  wazuh-agent
```

### 11. Install Custom Wazuh Rules (di Wazuh Manager)

```bash
# Lakukan di mesin Wazuh Manager (bukan agent)
sudo cp ibda3202_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/ibda3202_rules.xml
sudo chmod 640 /var/ossec/etc/rules/ibda3202_rules.xml
sudo systemctl restart wazuh-manager
```

---

## ✅ Verifikasi Deployment

```bash
# Semua service harus active
sudo systemctl is-active ibda3202   # Gunicorn
sudo systemctl is-active nginx      # Nginx
sudo systemctl is-active wazuh-agent

# HTTP check
curl -o /dev/null -s -w "HTTP: %{http_code}\n" http://localhost/

# Port yang listen (5001 hanya di localhost, 80 terbuka)
sudo ss -tlnp | grep -E '(80|5001)'
# Harus: 0.0.0.0:80 dan 127.0.0.1:5001

# Uji proteksi Nginx
curl -I http://localhost/app.py          # → 404 ✅
curl -I http://localhost/.env            # → 404 ✅
curl -I http://localhost/venv/           # → 404 ✅
curl -I "http://localhost/?q=../../etc" # → 400 ✅
```

---

## 🔧 Perintah Sehari-hari

```bash
# Restart aplikasi
sudo systemctl restart ibda3202

# Reload Nginx (tanpa downtime)
sudo systemctl reload nginx

# Lihat log real-time
sudo tail -f /var/log/ibda3202/app_secure.log
sudo tail -f /var/log/nginx/ibda3202-access.log

# Lihat log systemd
sudo journalctl -u ibda3202 -f

# Cek status semua sekaligus
sudo systemctl status ibda3202 nginx wazuh-agent

# Reset database (fresh start)
sudo systemctl stop ibda3202
sudo -u ibda3202 rm /var/www/ibda3202-secure/store_secure.db
sudo -u ibda3202 bash -c "
    cd /var/www/ibda3202-secure
    source .env
    ./venv/bin/python -c 'from app import app, init_db; init_db()'
"
sudo systemctl start ibda3202

# Update aplikasi (deploy ulang kode)
sudo rsync -a --exclude='venv/' --exclude='*.db' --exclude='.env' \
    /path/to/IBDA3202_Secure/ /var/www/ibda3202-secure/
sudo chown -R ibda3202:ibda3202 /var/www/ibda3202-secure
sudo systemctl restart ibda3202
```

---

## 📂 Struktur File Setelah Deploy

```
/var/www/ibda3202-secure/      ← App root
├── app.py
├── .env                       ← Secret keys (chmod 640)
├── store_secure.db            ← Database SQLite
├── venv/                      ← Virtual environment
├── static/uploads/            ← Folder upload (chmod 750)
└── templates/

/var/log/ibda3202/             ← Semua log
├── app_secure.log             ← Log aktivitas Flask
├── gunicorn-access.log        ← HTTP request ke Gunicorn
└── gunicorn-error.log         ← Error Gunicorn

/etc/systemd/system/
└── ibda3202.service           ← Service definition

/etc/nginx/sites-available/
└── ibda3202.conf              ← Nginx config
```

---

## 👤 Akun Default

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@12345` | Admin |
| `budi` | `budi123` | User |
| `siti` | `siti456` | User |

> **Ganti password admin setelah deploy pertama!**

---

## 📊 Wazuh Alert Levels

| Level | Arti | Contoh |
|-------|------|--------|
| 2–3 | Info | Login sukses, order baru |
| 5–7 | Warning | Login gagal, rate limited |
| 8–10 | High | SQLi attempt, admin denied |
| 12–15 | Critical | Web shell upload, brute-force |

---

*IBDA3202 Secure Store — Single App Deployment*
