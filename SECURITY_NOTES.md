# 🔐 IBDA3202_Store — Security Notes
## Dokumentasi Keamanan Lengkap: Versi Rentan vs Versi Aman

> Dokumen ini adalah referensi teknis untuk memahami setiap celah keamanan
> yang ada di versi rentan (`IBDA3202_Store`) dan bagaimana masing-masing
> diperbaiki di versi aman (`IBDA3202_Secure`).

---

## 📊 Tabel Perbandingan Utama

| # | Aspek | ❌ Versi Rentan | ✅ Versi Aman | OWASP |
|---|-------|-----------------|---------------|-------|
| S1  | **Cookie / Session** | Plaintext cookie `role=admin` tanpa flag | JWT dalam `HttpOnly + Secure + SameSite=Lax` | A07 |
| S2  | **Password Storage** | Disimpan plaintext di database | PBKDF2-SHA256 dengan salt unik | A02 |
| S3  | **SQL Query** | String format → SQL Injection | Parameterized query `(?, ?)` | A03 |
| S4  | **File Upload** | Tidak ada validasi sama sekali | 5 lapis validasi | A04 |
| S5  | **CSRF** | Tidak ada proteksi | CSRF token di setiap form POST | A01 |
| S6  | **Role Authorization** | Dari cookie (client-controlled) | Dari database server-side | A01 |
| S7  | **Secret Key** | Hardcoded di source code | Dari environment variable `.env` | A05 |
| S8  | **Error Disclosure** | Error DB tampil ke user | Error hanya di log | A05 |
| S9  | **Input Validation** | Tidak ada sanitasi/limit | Regex + length limit + strip | A03 |
| S10 | **Session Cart** | — | Flask signed session | A02 |
| S11 | **Open Redirect** | Parameter `next` tidak divalidasi | `urlparse()` tolak URL eksternal | A01 |
| S12 | **Rate Limiting** | Tidak ada batas percobaan | Manual rate limit per IP | A07 |
| S13 | **Config Management** | Secret hardcoded di kode | `python-dotenv` dari `.env` | A05 |
| S14 | **Admin Transactions** | Tidak ada panel transaksi | Admin lihat semua order semua user | — |
| S15 | **Product Control** | Tidak bisa disable produk | Admin tambah / aktif / nonaktif produk | — |
| S16 | **Auth State Sync** | `g.user` hanya di route protected | `before_request` set `g.user` di semua route | A07 |

---

## 📋 Detail Teknis Per Kerentanan

---

### [S1] Cookie Vulnerability → JWT HttpOnly

#### Masalah (Versi Rentan)

Setelah login, server menyimpan sesi dalam **plaintext cookie** yang bisa dibaca dan diubah bebas melalui browser DevTools.

```python
# ❌ VULN
response.set_cookie("username", username)   # Plaintext, terbaca JS
response.set_cookie("role", user["role"])   # Role ekspos ke client!
response.set_cookie("user_id", str(user["id"]))
# Tidak ada: httponly, secure, samesite
```

**Cara eksploitasi:**
1. Login sebagai `budi`
2. DevTools → Application → Cookies
3. Ubah `role` dari `user` → `admin`
4. Akses `/admin` → berhasil!

#### Solusi (Versi Aman)

```python
# ✅ SECURE — JWT ditandatangani + cookie aman
def create_jwt(user_id, username, role):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub":      str(user_id),
        "username": username,
        "role":     role,
        "iat":      now,
        "exp":      now + timedelta(hours=8),   # expire otomatis
        "jti":      secrets.token_hex(16),       # unique token ID
    }, SECRET_KEY, algorithm="HS256")

response.set_cookie(
    "auth_token", token,
    httponly=True,    # JS tidak bisa baca (cegah XSS cookie theft)
    secure=True,      # Hanya via HTTPS (production)
    samesite="Lax",   # Proteksi CSRF lintas domain
    max_age=28800     # Expire 8 jam
)
```

**Mengapa JWT lebih aman:**
- Payload ditandatangani HMAC-SHA256 — tidak bisa dimodifikasi tanpa secret key
- `jti` mencegah token reuse
- `HttpOnly` mencegah pencurian via XSS

---

### [S2] Plaintext Password → PBKDF2-SHA256

#### Masalah (Versi Rentan)

```python
# ❌ VULN — password plaintext di DB
db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
           (username, password_plaintext))
# DB: | budi | budi123 |  ← langsung terbaca jika DB bocor!
```

#### Solusi (Versi Aman)

```python
# ✅ SECURE
from werkzeug.security import generate_password_hash, check_password_hash

# Saat register
hashed = generate_password_hash(password)
# Hasil: 'pbkdf2:sha256:600000$salt$hashvalue...'

# Saat login — timing-safe comparison
if check_password_hash(stored_hash, input_password):
    # Login berhasil
```

| Fitur | Penjelasan |
|-------|------------|
| 600.000 iterasi | Memperlambat brute-force |
| Salt unik per user | Cegah rainbow table |
| Tidak reversible | Hash satu arah |
| Timing-safe | Tidak rentan timing attack |

---

### [S3] SQL Injection → Parameterized Query

#### Masalah (Versi Rentan)

```python
# ❌ VULN — string interpolation langsung
query = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
db.execute(query)
```

**Payload eksploitasi:**
```sql
-- Dump semua user + password
' UNION SELECT 1,username,password,email,role,6,7 FROM users--

-- Dump gaji karyawan
' UNION SELECT 1,name,position,salary,email,6,7 FROM employees--

-- Boolean blind
' AND 1=1--   → hasil normal
' AND 1=2--   → hasil kosong
```

#### Solusi (Versi Aman)

```python
# ✅ SECURE — nilai dipisah dari query
safe_q = f"%{query}%"
results = db.execute(
    "SELECT * FROM products WHERE (name LIKE ? OR description LIKE ?) AND is_active=1",
    (safe_q, safe_q)
)
# Driver SQLite otomatis escape semua input
```

---

### [S4] Unrestricted File Upload → 5-Layer Validation

#### Masalah (Versi Rentan)

```python
# ❌ VULN — hanya secure_filename, tanpa cek ekstensi
filename = secure_filename(file.filename)
file.save(os.path.join(UPLOAD_FOLDER, filename))
# shell.php tersimpan → /static/uploads/shell.php → RCE!
```

#### Solusi (Versi Aman) — 5 Lapis

```python
# LAPIS 1: Whitelist ekstensi
ALLOWED = {"png", "jpg", "jpeg", "gif", "webp"}
if ext not in ALLOWED: reject()

# LAPIS 2: Cegah double extension (shell.php.jpg)
if re.search(r"\.(php\d?|phtml|phar|asp|aspx|jsp|sh|py|exe)(\.|$)", filename, re.I):
    reject()

# LAPIS 3: Magic bytes — verifikasi konten nyata
header = file.read(12)
valid = (header[:4]==b"\x89PNG" or header[:3]==b"\xff\xd8\xff"
         or header[:4]==b"GIF8" or header[8:12]==b"WEBP")
if not valid: reject()

# LAPIS 4: UUID rename — nama tidak bisa ditebak
safe_name = f"{uuid.uuid4().hex}.{ext}"
# Contoh: a3f8c2d1e4b5f6a7.jpg

# LAPIS 5: Batas ukuran 2MB
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
```

---

### [S5] CSRF Protection

#### Masalah (Versi Rentan)

```html
<!-- ❌ VULN — form tanpa CSRF token -->
<!-- Penyerang bisa submit dari domain lain! -->
<form method="POST" action="http://ibda3202.com/cart/add">
  <input name="product_id" value="1" />
</form>
<script>document.querySelector('form').submit()</script>
```

#### Solusi (Versi Aman)

```python
# ✅ SECURE — generate + validate CSRF token
def generate_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def validate_csrf():
    form_token    = request.form.get("csrf_token", "")
    session_token = session.get("_csrf", "")
    # secrets.compare_digest: timing-safe, cegah timing attack
    return bool(form_token and session_token and
                secrets.compare_digest(form_token, session_token))
```

```html
<!-- ✅ Di setiap form POST -->
<form method="POST">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
</form>
```

---

### [S6] Role Authorization dari Database

#### Masalah (Versi Rentan)

```python
# ❌ VULN — role dari cookie, bisa dimanipulasi
role = request.cookies.get("role")
if role != "admin": return 403
```

#### Solusi (Versi Aman)

```python
# ✅ SECURE — verifikasi dari DB, bukan token saja
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        # Double-check role dari DB
        row = db.execute(
            "SELECT role FROM users WHERE id=? AND username=?",
            (g.user["sub"], g.user["username"])
        ).fetchone()
        if not row or row["role"] != "admin":
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return decorated
```

**Defense in depth:** Meski JWT berisi `role`, kita tetap verifikasi ke DB. Jika admin mencabut akses user — JWT lama tidak langsung invalid, tapi DB check akan menolaknya.

---

### [S7] Secret Key Management

#### Masalah (Versi Rentan)

```python
# ❌ VULN — hardcoded di source code
app.secret_key = "ibda3202_insecure_secret_do_not_use"
SECRET_KEY = "ibda3202_secret"
# Siapapun yang lihat repo bisa forge JWT token!
```

#### Solusi (Versi Aman)

**`.env`:**
```env
IBDA3202_SECRET=d4f9a2c8e1b3f7a6d2e5c9b4...  # min 64 karakter
FLASK_SECRET=e7c1a4f8b2d6e9a3c5f0b7d4...
FLASK_DEBUG=false
FLASK_PORT=5001
```

**`app.py`:**
```python
from dotenv import load_dotenv
load_dotenv()
SECRET_KEY   = os.environ.get("IBDA3202_SECRET")
FLASK_SECRET = os.environ.get("FLASK_SECRET")
```

**Generate key:**
```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

**Best practice:**
- `.env` masuk `.gitignore` — tidak pernah di-commit
- Secret berbeda tiap environment (dev/staging/prod)
- Rotate berkala

---

### [S8] Error Disclosure

#### Masalah (Versi Rentan)

```python
# ❌ VULN — error DB tampil ke user
except Exception as e:
    error = str(e)   # bocorkan: "no such table: users"

app.run(debug=True)  # traceback penuh di browser!
```

#### Solusi (Versi Aman)

```python
# ✅ SECURE — error hanya ke log
except Exception as e:
    logger.error(f"DB_ERROR | {e}")
    results = []   # kembalikan hasil kosong

app.run(debug=False)  # tidak ada traceback di browser
```

---

### [S9] Input Validation & Sanitization

```python
# ✅ Panjang dibatasi
username = request.form.get("username", "").strip()[:30]
query    = request.args.get("q", "").strip()[:100]

# ✅ Format divalidasi dengan regex
if not re.match(r"^[a-zA-Z0-9_]{3,30}$", username):
    errors.append("Username tidak valid.")

if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
    errors.append("Format email tidak valid.")

# ✅ Whitelist nilai yang diizinkan
if status not in ("pending", "completed", "cancelled"):
    return redirect(...)   # tolak nilai di luar whitelist
```

---

### [S10] Cart — Flask Signed Session

Keranjang belanja disimpan di **Flask session** yang ditandatangani dengan `FLASK_SECRET`. Pengguna tidak bisa memanipulasi isi cart dari browser.

```python
# Cart: {product_id_str: quantity}
cart = session.get("cart", {})
cart[str(product_id)] = quantity
session["cart"]  = cart
session.modified = True
# Flask auto-sign cookie → modifikasi dari browser ditolak
```

---

### [S11] Open Redirect Prevention

#### Masalah

```
http://ibda3202.com/login?next=https://evil.com
# → User login → diarahkan ke situs phishing!
```

#### Solusi

```python
from urllib.parse import urlparse

def is_safe_redirect(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    parsed = urlparse(url)
    return (
        not parsed.scheme      # tolak http://, javascript:
        and not parsed.netloc  # tolak evil.com
        and url.startswith("/")
        and not url.startswith("//")  # tolak //evil.com
    )

# Di route login:
next_url = request.args.get("next", "")
if not is_safe_redirect(next_url):
    next_url = url_for("dashboard")
```

| Input `next=` | Hasil |
|---|---|
| `/dashboard` | ✅ Diizinkan |
| `https://evil.com` | ❌ Ditolak |
| `//evil.com` | ❌ Ditolak |
| `javascript:alert()` | ❌ Ditolak |

---

### [S12] Rate Limiting — Anti Brute-Force

#### Masalah (Versi Rentan)

Tidak ada batas percobaan — Hydra / Burp Intruder bisa mencoba ribuan kombinasi password.

#### Solusi (Versi Aman) — Implementasi Manual

```python
from collections import defaultdict
import time

_rate_store: dict[str, list[float]] = defaultdict(list)

def check_rate_limit(ip: str, limit: int = 10, window: int = 60) -> bool:
    now = time.time()
    _rate_store[ip] = [ts for ts in _rate_store[ip] if now - ts < window]
    if len(_rate_store[ip]) >= limit:
        return False   # Rate limited
    _rate_store[ip].append(now)
    return True

# Penerapan:
# Login:    maks 10 percobaan per 60 detik per IP
# Register: maks 5 per 60 detik per IP
```

**Catatan:** Storage in-memory, reset saat server restart. Untuk production gunakan Redis + Flask-Limiter.

---

### [S13] Konfigurasi dari `.env`

**Struktur `.env`:**
```env
IBDA3202_SECRET=<64-char random hex>
FLASK_SECRET=<64-char random hex>
FLASK_PORT=5001
FLASK_DEBUG=false
```

**Keamanan:**
```bash
echo ".env" >> .gitignore   # jangan di-commit!
chmod 600 .env              # permission ketat di server
```

---

### [S14] Admin — Riwayat Transaksi Semua User

Panel admin kini memiliki tab **Transaksi** yang menampilkan semua order dari semua user dengan fitur:
- Filter by status (Diproses / Selesai / Dibatalkan)
- Pencarian live by username atau nama produk
- Admin bisa update status langsung dari tabel

```sql
-- Query transaksi semua user
SELECT o.id, o.total, o.status, o.created_at,
       u.username, u.email,
       GROUP_CONCAT(p.name || ' (×' || oi.quantity || ')', ', ') as items
FROM orders o
JOIN users u        ON u.id=o.user_id
JOIN order_items oi ON oi.order_id=o.id
JOIN products p     ON p.id=oi.product_id
GROUP BY o.id
ORDER BY o.created_at DESC
```

---

### [S15] Admin — Manajemen Produk

Tab **Kelola Produk** memungkinkan admin:
- Tambah produk baru (nama, deskripsi, harga, stok, kategori)
- Toggle aktif/nonaktif produk tanpa menghapus data
- Filter dan search produk

```python
# Toggle aktif/nonaktif — CSRF protected
@app.route("/admin/product/toggle/<int:product_id>", methods=["POST"])
@admin_required
def admin_product_toggle(product_id):
    if not validate_csrf(): return redirect(...)
    row = db.execute("SELECT is_active FROM products WHERE id=?", (product_id,)).fetchone()
    new_status = 0 if row["is_active"] else 1
    db.execute("UPDATE products SET is_active=? WHERE id=?", (new_status, product_id))
    db.commit()
```

Produk nonaktif tidak muncul di halaman publik (`WHERE is_active=1`).

---

### [S16] Auth State Sync — `before_request` (Bug Fix)

#### Root Cause

`g.user` hanya di-set di dalam `@login_required` dan `@admin_required`. Route publik tidak memanggil decorator itu, sehingga `g.user` selalu `None` → navbar selalu tampil "belum login" meski sudah login.

```
❌ Sebelum fix:
Request ke / → g.user tidak pernah di-set → current_user = None
→ Navbar: "Daftar / Masuk" padahal cookie valid!
```

#### Fix

```python
# ✅ Jalan sebelum SETIAP route apapun
@app.before_request
def load_logged_in_user():
    token  = request.cookies.get("auth_token")
    g.user = decode_jwt(token) if token else None

# Context processor sekarang selalu akurat
@app.context_processor
def inject_globals():
    user       = getattr(g, "user", None)   # selalu benar
    cart_count = sum(session.get("cart", {}).values())
    return {"current_user": user, ...}
```

```
✅ Setelah fix:
Request ke / → before_request → g.user = payload
→ context_processor → current_user = {username: "budi"}
→ Navbar: avatar + cart badge ✅
```

Decorator `@login_required` juga jadi lebih ringkas — tinggal cek `if not g.user` karena decode sudah dilakukan oleh `before_request`.

---

## 🛡️ OWASP Top 10 Coverage

| OWASP 2021 | Kategori | Kerentanan | Mitigasi |
|------------|----------|------------|----------|
| **A01** | Broken Access Control | Role dari cookie, CSRF, open redirect | S1, S5, S6, S11 |
| **A02** | Cryptographic Failures | Plaintext password, plaintext cookie | S1, S2, S10 |
| **A03** | Injection | SQL Injection, input tak tersanitasi | S3, S9 |
| **A04** | Insecure Design | Upload tanpa validasi | S4 |
| **A05** | Security Misconfiguration | debug=True, secret hardcoded, error disclosure | S7, S8, S13 |
| **A06** | Vulnerable Components | Versi library tidak dikunci | `requirements.txt` pin versi |
| **A07** | Auth & Session Failures | Brute-force, auth state tidak sync | S12, S16 |
| **A08** | Data Integrity Failures | Cart bisa dimanipulasi | S10 |
| **A09** | Logging & Monitoring | Tidak ada log aktivitas | `app_secure.log` |
| **A10** | SSRF | Tidak ada request ke URL eksternal | N/A |

---

## 🚀 Cara Menjalankan

### Versi Rentan (Port 5000)
```bash
cd IBDA3202_Store
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

### Versi Aman (Port 5001)
```bash
cd IBDA3202_Secure
pip install -r requirements.txt
cp .env.example .env
# Edit .env — isi IBDA3202_SECRET dan FLASK_SECRET:
python -c "import secrets; print(secrets.token_hex(64))"
python app.py
# → http://localhost:5001
```

---

## 👤 Akun Demo

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@12345` | Admin — akses panel admin |
| `budi` | `budi123` | User |
| `siti` | `siti456` | User |
| `andi` | `andi789` | User |

---

## 📁 Struktur File

```
IBDA3202_Secure/
├── app.py                 ← Flask app + semua route + security
├── requirements.txt       ← Flask, Werkzeug, PyJWT, python-dotenv
├── .env.example           ← Template env vars (salin ke .env)
├── .env                   ← Secret keys (JANGAN di-commit ke git)
├── SECURITY_NOTES.md      ← Dokumen ini
├── app_secure.log         ← Log aktivitas (auto-generated)
├── store_secure.db        ← Database SQLite (auto-generated)
├── static/uploads/        ← Folder upload (auto-generated)
└── templates/
    ├── base.html          ← Layout + navbar + CSS global
    ├── index.html         ← Beranda
    ├── products.html      ← Katalog produk
    ├── product_detail.html← Detail + form keranjang
    ├── search.html        ← Hasil pencarian (parameterized)
    ├── login.html         ← Form login + CSRF
    ├── register.html      ← Form daftar + validasi
    ├── dashboard.html     ← Dashboard user
    ├── profile.html       ← Upload foto (5-layer)
    ├── cart.html          ← Keranjang belanja
    ├── checkout.html      ← Checkout + pembayaran
    ├── order_success.html ← Konfirmasi pesanan
    ├── admin.html         ← Panel admin (3 tab)
    ├── about.html         ← Tentang kami
    ├── 403.html           ← Forbidden
    ├── 404.html           ← Not Found
    └── 429.html           ← Rate Limited
```

---

## 📝 Log Format (untuk SIEM / Wazuh)

```
TIMESTAMP | LEVEL | TYPE | IP=x.x.x.x | Username='...' | Detail
```

**Contoh:**
```log
2025-06-01 10:23:45 | INFO    | LOGIN_SUCCESS   | IP=192.168.1.5  | Username='budi'
2025-06-01 10:24:15 | WARNING | RATE_LIMITED    | IP=192.168.1.10 | Path=/login
2025-06-01 10:25:00 | WARNING | ADMIN_DENIED    | IP=192.168.1.10 | user='budi'
2025-06-01 10:26:33 | WARNING | ADMIN_ACCESS    | IP=192.168.1.1  | Username='admin'
2025-06-01 10:27:45 | WARNING | UPLOAD_REJECTED | IP=192.168.1.10 | Reason='magic bytes invalid'
2025-06-01 10:28:02 | INFO    | ORDER_CREATED   | User='budi'     | OrderId=42 | Total=1250000
```

**Wazuh rules yang bisa dibuat:**
- Alert jika `LOGIN_FAILED` > 5x dalam 1 menit dari IP yang sama → brute-force
- Alert jika `ADMIN_DENIED` atau `UPLOAD_REJECTED` terdeteksi → potential attack
- Alert jika `RATE_LIMITED` berulang kali → automated scanning

---

*IBDA3202_Store Secure Edition — Cybersecurity Lab Documentation*
