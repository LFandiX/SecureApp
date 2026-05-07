"""
============================================================
  IBDA3202_Store — SECURE VERSION (Updated)
  ✅  Best-practice security implementation
============================================================
Keamanan yang diimplementasikan:
  [S1]  JWT dalam HttpOnly + SameSite=Lax cookie
  [S2]  Password PBKDF2-SHA256
  [S3]  Parameterized SQL query
  [S4]  File upload: whitelist + magic bytes + UUID + 2MB
  [S5]  CSRF token di setiap form POST
  [S6]  Role diverifikasi dari database
  [S7]  Secret key dari .env (python-dotenv)
  [S8]  Error tidak ditampilkan ke user
  [S9]  Input validation & length limit
  [S10] Cart: Flask signed session
  [S11] Open Redirect dicegah dengan urlparse
  [S12] Rate limiting manual anti brute-force
  [S13] Konfigurasi dari .env file
  [S14] Admin: riwayat transaksi semua user
  [S15] Admin: manajemen produk (tambah/aktif/nonaktif)
============================================================
"""

import os, re, time, secrets, sqlite3, logging, uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

import jwt
from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect,
                   url_for, make_response, g, session)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ─────────────────────────────────────────────
#  [S13] Load .env
# ─────────────────────────────────────────────
load_dotenv()

SECRET_KEY   = os.environ.get("IBDA3202_SECRET")
FLASK_SECRET = os.environ.get("FLASK_SECRET")

if not SECRET_KEY or not FLASK_SECRET:
    print("\n⚠️  WARNING: Secret keys tidak ditemukan di .env!")
    print("   Jalankan: cp .env.example .env  lalu isi nilainya.\n")
    SECRET_KEY   = SECRET_KEY   or secrets.token_hex(32)
    FLASK_SECRET = FLASK_SECRET or secrets.token_hex(32)

JWT_ALGORITHM    = "HS256"
JWT_EXPIRE_HOURS = 8

# ─────────────────────────────────────────────
#  App Setup
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # 2MB

UPLOAD_FOLDER = os.path.join("static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
DATABASE = "store_secure.db"

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# ─────────────────────────────────────────────
#  [S12] Rate Limiting — tanpa library eksternal
#  Menyimpan timestamp request per IP di memori.
# ─────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)

def check_rate_limit(ip: str, limit: int = 10, window: int = 60) -> bool:
    """True = diizinkan | False = dibatasi (rate limited)"""
    now = time.time()
    _rate_store[ip] = [ts for ts in _rate_store[ip] if now - ts < window]
    if len(_rate_store[ip]) >= limit:
        return False
    _rate_store[ip].append(now)
    return True

def remaining_wait(ip: str, window: int = 60) -> int:
    """Sisa detik sebelum rate limit reset."""
    if not _rate_store.get(ip):
        return 0
    return max(0, int(window - (time.time() - min(_rate_store[ip]))))


# ─────────────────────────────────────────────
#  [S11] Open Redirect Prevention
# ─────────────────────────────────────────────
def is_safe_redirect(url: str) -> bool:
    """
    Izinkan hanya path internal (relatif), tolak URL eksternal.
    Contoh serangan: /login?next=https://evil.com → ditolak
    Contoh aman:     /login?next=/dashboard       → diizinkan
    """
    if not url or not isinstance(url, str):
        return False
    parsed = urlparse(url)
    return (
        not parsed.scheme          # tidak ada http:// atau https://
        and not parsed.netloc      # tidak ada domain.com
        and url.startswith("/")    # harus dimulai dengan /
        and not url.startswith("//")  # cegah //evil.com
    )


# ─────────────────────────────────────────────
#  Logging (untuk SIEM / Wazuh)
# ─────────────────────────────────────────────
logging.basicConfig(
    filename="app_secure.log", level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT DEFAULT 'user',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, description TEXT,
                price REAL, category TEXT,
                stock INTEGER DEFAULT 10,
                image TEXT DEFAULT 'default.png',
                is_active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER, total REAL,
                status TEXT DEFAULT 'pending', address TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER, product_id INTEGER,
                quantity INTEGER, unit_price REAL,
                FOREIGN KEY (order_id)   REFERENCES orders(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            );
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT, position TEXT, salary REAL, email TEXT, phone TEXT
            );
            CREATE TABLE IF NOT EXISTS sales_report (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                month TEXT, revenue REAL, orders_count INTEGER, top_product TEXT
            );
        """)
        # Migrasi kolom is_active
        try:
            db.execute("ALTER TABLE products ADD COLUMN is_active INTEGER DEFAULT 1")
        except Exception:
            pass

        # Seed data
        for u in [("admin","Admin@12345","admin@ibda3202.com","admin"),
                  ("budi","budi123","budi@email.com","user"),
                  ("siti","siti456","siti@email.com","user"),
                  ("andi","andi789","andi@email.com","user")]:
            try:
                db.execute("INSERT INTO users (username,password_hash,email,role) VALUES (?,?,?,?)",
                           (u[0], generate_password_hash(u[1]), u[2], u[3]))
            except sqlite3.IntegrityError:
                pass

        for p in [
            ("Adobe Photoshop 2024 License","Lisensi resmi Adobe Photoshop untuk desainer profesional.",1250000,"Software",50,1),
            ("Microsoft Office 365 (1 Year)","Paket lengkap produktivitas Microsoft untuk 1 tahun.",899000,"Software",30,1),
            ("Antivirus Pro Suite 2025","Proteksi lengkap untuk 3 perangkat selama 1 tahun.",450000,"Security",100,1),
            ("AutoCAD 2024 Student License","Lisensi AutoCAD untuk mahasiswa teknik dan arsitektur.",2100000,"Engineering",20,1),
            ("Udemy Premium Subscription","Akses tak terbatas ke seluruh kursus Udemy.",799000,"Education",200,1),
            ("Adobe Premiere Pro License","Edit video profesional dengan Adobe Premiere Pro.",1500000,"Software",40,1),
            ("Windows 11 Pro OEM","Lisensi asli Windows 11 Pro untuk satu perangkat.",1750000,"OS",25,1),
            ("Figma Professional (1 Year)","Kolaborasi desain UI/UX tanpa batas.",650000,"Design",80,1),
            ("GitHub Copilot (12 Months)","AI pair programmer resmi dari GitHub.",1100000,"Developer Tools",60,1),
            ("Notion AI Pro Annual","Workspace all-in-one dengan kecerdasan buatan.",380000,"Productivity",150,1),
            ("VPN Premium 5 Devices","Keamanan internet untuk 5 perangkat sekaligus.",275000,"Security",300,1),
            ("Grammarly Business (1 Year)","Koreksi penulisan AI untuk tim profesional.",420000,"Productivity",90,1),
        ]:
            try:
                db.execute("INSERT INTO products (name,description,price,category,stock,is_active) VALUES (?,?,?,?,?,?)", p)
            except Exception:
                pass

        for e in [
            ("Ahmad Rizki Pratama","CEO",45000000,"ahmad@ibda3202.com","0812-3456-7890"),
            ("Dewi Rahayu","CFO",38000000,"dewi@ibda3202.com","0813-4567-8901"),
            ("Fajar Nugroho","Head of Engineering",32000000,"fajar@ibda3202.com","0814-5678-9012"),
            ("Rina Kusumawati","Marketing Manager",18000000,"rina@ibda3202.com","0815-6789-0123"),
            ("Budi Santoso","Sales Executive",12000000,"budi@ibda3202.com","0816-7890-1234"),
            ("Hendra Wijaya","IT Security Analyst",22000000,"hendra@ibda3202.com","0817-8901-2345"),
        ]:
            try:
                db.execute("INSERT INTO employees (name,position,salary,email,phone) VALUES (?,?,?,?,?)", e)
            except Exception:
                pass

        for s in [
            ("Januari 2025",287500000,382,"Adobe Photoshop 2024"),
            ("Februari 2025",315200000,421,"Microsoft Office 365"),
            ("Maret 2025",298700000,395,"Adobe Photoshop 2024"),
            ("April 2025",341000000,453,"Windows 11 Pro OEM"),
            ("Mei 2025",372800000,497,"GitHub Copilot"),
            ("Juni 2025",329100000,438,"Adobe Premiere Pro"),
        ]:
            try:
                db.execute("INSERT INTO sales_report (month,revenue,orders_count,top_product) VALUES (?,?,?,?)", s)
            except Exception:
                pass

        db.commit()


# ─────────────────────────────────────────────
#  JWT Helpers
# ─────────────────────────────────────────────
def create_jwt(user_id, username, role):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": str(user_id), "username": username, "role": role,
        "iat": now, "exp": now + timedelta(hours=JWT_EXPIRE_HOURS),
        "jti": secrets.token_hex(16),
    }, SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ─────────────────────────────────────────────
#  CSRF Helpers
# ─────────────────────────────────────────────
def generate_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def validate_csrf():
    ft = request.form.get("csrf_token", "")
    st = session.get("_csrf", "")
    return bool(ft and st and secrets.compare_digest(ft, st))


# ─────────────────────────────────────────────
#  Before Request — load user untuk SEMUA route
#  Inilah root cause fix: tanpa ini, g.user hanya
#  tersedia di route yang pakai @login_required.
#  Route publik (/, /products, /about) tidak pernah
#  set g.user, sehingga navbar selalu tampil "belum
#  login" meski cookie valid.
# ─────────────────────────────────────────────
@app.before_request
def load_logged_in_user():
    token = request.cookies.get("auth_token")
    g.user = decode_jwt(token) if token else None


# ─────────────────────────────────────────────
#  Context Processor
# ─────────────────────────────────────────────
@app.context_processor
def inject_globals():
    user       = getattr(g, "user", None)
    cart       = session.get("cart", {})
    cart_count = sum(cart.values()) if cart else 0
    return {"current_user": user, "csrf_token": generate_csrf_token(), "cart_count": cart_count}


# ─────────────────────────────────────────────
#  Auth Decorators
#  Lebih ringkas karena g.user sudah di-set
#  oleh before_request di atas.
# ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            resp = make_response(redirect(url_for("login", next=request.path)))
            resp.delete_cookie("auth_token")
            return resp
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        # [S6] Double-check role dari DB — tidak hanya dari JWT
        db  = get_db()
        row = db.execute("SELECT role FROM users WHERE id=? AND username=?",
                         (g.user["sub"], g.user["username"])).fetchone()
        if not row or row["role"] != "admin":
            logger.warning(f"ADMIN_DENIED | IP={request.remote_addr} | user={g.user.get('username')}")
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
#  File Upload Validator
# ─────────────────────────────────────────────
def validate_upload(file):
    if not file or file.filename == "":
        return False, "Tidak ada file yang dipilih."
    filename = file.filename
    if "." not in filename:
        return False, "File harus memiliki ekstensi."
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Ekstensi .{ext} tidak diizinkan."
    if re.search(r"\.(php\d?|phtml|phar|asp|aspx|jsp|sh|py|exe|bat)(\.|$)", filename, re.IGNORECASE):
        return False, "Nama file mengandung ekstensi berbahaya."
    file.seek(0)
    header = file.read(12)
    file.seek(0)
    valid = (header[:4]==b"\x89PNG" or header[:3]==b"\xff\xd8\xff"
             or header[:4]==b"GIF8" or header[8:12]==b"WEBP")
    if not valid:
        return False, "Konten file bukan gambar yang valid."
    return True, None


# ══════════════════════════════════════════════
#  ROUTES — PUBLIC
# ══════════════════════════════════════════════

@app.route("/")
def index():
    logger.info(f"ACCESS | IP={request.remote_addr} | Path=/")
    db = get_db()
    products   = db.execute("SELECT * FROM products WHERE is_active=1 LIMIT 8").fetchall()
    categories = db.execute("SELECT DISTINCT category FROM products WHERE is_active=1").fetchall()
    return render_template("index.html", products=products, categories=categories)

@app.route("/products")
def products():
    db       = get_db()
    category = request.args.get("category", "")[:50]
    prods    = db.execute(
        "SELECT * FROM products WHERE category=? AND is_active=1" if category
        else "SELECT * FROM products WHERE is_active=1",
        (category,) if category else ()
    ).fetchall()
    categories = db.execute("SELECT DISTINCT category FROM products WHERE is_active=1").fetchall()
    return render_template("products.html", products=prods, categories=categories, selected=category)

@app.route("/search")
def search():
    query   = request.args.get("q", "")[:100].strip()
    db      = get_db()
    results = []
    if query:
        q = f"%{query}%"
        results = db.execute(
            "SELECT * FROM products WHERE (name LIKE ? OR description LIKE ?) AND is_active=1",
            (q, q)
        ).fetchall()
    return render_template("search.html", results=results, query=query)

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    db      = get_db()
    product = db.execute("SELECT * FROM products WHERE id=? AND is_active=1", (product_id,)).fetchone()
    if not product:
        return render_template("404.html"), 404
    return render_template("product_detail.html", product=product)

@app.route("/about")
def about():
    return render_template("about.html")


# ══════════════════════════════════════════════
#  ROUTES — AUTH
# ══════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    if request.cookies.get("auth_token") and decode_jwt(request.cookies.get("auth_token")):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # [S12] Rate limit: 10 percobaan per 60 detik
        if not check_rate_limit(ip, limit=10, window=60):
            wait = remaining_wait(ip)
            logger.warning(f"RATE_LIMITED | IP={ip} | Path=/login")
            return render_template("login.html",
                error=f"Terlalu banyak percobaan. Coba lagi dalam {wait} detik."), 429

        if not validate_csrf():
            return render_template("login.html", error="Permintaan tidak valid. Muat ulang halaman.")

        username = request.form.get("username", "").strip()[:50]
        password = request.form.get("password", "")
        logger.info(f"LOGIN_ATTEMPT | IP={ip} | Username='{username}'")

        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            logger.warning(f"LOGIN_FAILED | IP={ip} | Username='{username}'")
            return render_template("login.html", error="Username atau password tidak valid.")

        logger.info(f"LOGIN_SUCCESS | IP={ip} | Username='{username}' | Role='{user['role']}'")
        token = create_jwt(user["id"], user["username"], user["role"])

        # [S11] Validasi redirect URL — cegah open redirect
        next_url = request.args.get("next", "")
        if not is_safe_redirect(next_url):
            next_url = url_for("dashboard")

        resp = make_response(redirect(next_url))
        resp.set_cookie("auth_token", token, httponly=True, secure=False,
                        samesite="Lax", max_age=JWT_EXPIRE_HOURS * 3600)
        return resp

    return render_template("login.html", error=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    ip = request.remote_addr
    if request.method == "POST":
        # [S12] Rate limit: 5 percobaan per 60 detik
        if not check_rate_limit(ip, limit=5, window=60):
            wait = remaining_wait(ip)
            return render_template("register.html",
                errors=[f"Terlalu banyak permintaan. Coba lagi dalam {wait} detik."], form={}), 429

        if not validate_csrf():
            return render_template("register.html", errors=["Permintaan tidak valid."], form={})

        username = request.form.get("username", "").strip()[:30]
        email    = request.form.get("email", "").strip()[:100]
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        errors = []
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", username):
            errors.append("Username hanya boleh huruf, angka, underscore (3–30 karakter).")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Format email tidak valid.")
        if len(password) < 6:
            errors.append("Password minimal 6 karakter.")
        if password != confirm:
            errors.append("Konfirmasi password tidak cocok.")
        if errors:
            return render_template("register.html", errors=errors,
                                   form={"username": username, "email": email})

        db = get_db()
        if db.execute("SELECT id FROM users WHERE username=? OR email=?",
                      (username, email)).fetchone():
            return render_template("register.html",
                errors=["Username atau email sudah digunakan."],
                form={"username": username, "email": email})

        db.execute("INSERT INTO users (username,password_hash,email,role) VALUES (?,?,?,'user')",
                   (username, generate_password_hash(password), email))
        db.commit()
        logger.info(f"REGISTER_SUCCESS | IP={ip} | Username='{username}'")
        return redirect(url_for("login") + "?registered=1")

    return render_template("register.html", errors=[], form={})


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("auth_token")
    return resp


# ══════════════════════════════════════════════
#  ROUTES — USER
# ══════════════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    db     = get_db()
    orders = db.execute("""
        SELECT o.id, o.total, o.status, o.created_at,
               GROUP_CONCAT(p.name, ', ')  as product_names,
               SUM(oi.quantity)            as total_items
        FROM orders o
        JOIN order_items oi ON oi.order_id=o.id
        JOIN products p     ON p.id=oi.product_id
        WHERE o.user_id=?
        GROUP BY o.id ORDER BY o.created_at DESC
    """, (g.user["sub"],)).fetchall()
    return render_template("dashboard.html", orders=orders)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    ip, username = request.remote_addr, g.user["username"]
    upload_info, error = None, None

    if request.method == "POST":
        if not validate_csrf():
            error = "Permintaan tidak valid."
        elif "profile_pic" not in request.files:
            error = "Tidak ada file yang dipilih."
        else:
            file        = request.files["profile_pic"]
            ok, err_msg = validate_upload(file)
            if not ok:
                error = err_msg
            else:
                ext       = secure_filename(file.filename).rsplit(".", 1)[1].lower()
                safe_name = f"{uuid.uuid4().hex}.{ext}"
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], safe_name))
                upload_info = safe_name
                logger.info(f"UPLOAD_OK | IP={ip} | User='{username}' | File='{safe_name}'")

    return render_template("profile.html", username=username, upload_info=upload_info, error=error)


# ══════════════════════════════════════════════
#  ROUTES — CART & CHECKOUT
# ══════════════════════════════════════════════

@app.route("/cart")
@login_required
def cart():
    db       = get_db()
    cart_raw = session.get("cart", {})
    items, total = [], 0
    for pid, qty in cart_raw.items():
        p = db.execute("SELECT * FROM products WHERE id=? AND is_active=1", (int(pid),)).fetchone()
        if p:
            sub = p["price"] * qty; total += sub
            items.append({"product": p, "quantity": qty, "subtotal": sub})
    return render_template("cart.html", items=items, total=total)

@app.route("/cart/add", methods=["POST"])
@login_required
def cart_add():
    if not validate_csrf():
        return redirect(url_for("products"))
    try:
        pid = int(request.form.get("product_id", 0))
        qty = max(1, min(int(request.form.get("quantity", 1)), 50))
    except ValueError:
        return redirect(url_for("products"))
    db = get_db()
    p  = db.execute("SELECT id, stock FROM products WHERE id=? AND is_active=1", (pid,)).fetchone()
    if not p:
        return redirect(url_for("products"))
    cart    = session.get("cart", {})
    key     = str(pid)
    cart[key] = min(cart.get(key, 0) + qty, p["stock"])
    session["cart"] = cart; session.modified = True
    return redirect(url_for("cart"))

@app.route("/cart/remove", methods=["POST"])
@login_required
def cart_remove():
    if not validate_csrf():
        return redirect(url_for("cart"))
    cart = session.get("cart", {})
    cart.pop(str(request.form.get("product_id", "")), None)
    session["cart"] = cart; session.modified = True
    return redirect(url_for("cart"))

@app.route("/cart/update", methods=["POST"])
@login_required
def cart_update():
    if not validate_csrf():
        return redirect(url_for("cart"))
    pid = str(request.form.get("product_id", ""))
    try: qty = max(1, min(int(request.form.get("quantity", 1)), 50))
    except ValueError: qty = 1
    cart = session.get("cart", {})
    if pid in cart:
        cart[pid] = qty; session["cart"] = cart; session.modified = True
    return redirect(url_for("cart"))

@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    cart_raw = session.get("cart", {})
    if not cart_raw:
        return redirect(url_for("cart"))
    db = get_db()
    items, total = [], 0
    for pid, qty in cart_raw.items():
        p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
        if p:
            sub = p["price"] * qty; total += sub
            items.append({"product": p, "quantity": qty, "subtotal": sub})

    if request.method == "POST":
        if not validate_csrf():
            return render_template("checkout.html", items=items, total=total, error="Permintaan tidak valid.")
        address = request.form.get("address", "").strip()[:300]
        if not address:
            return render_template("checkout.html", items=items, total=total, error="Alamat wajib diisi.")
        user_id = int(g.user["sub"])
        for item in items:
            row = db.execute("SELECT stock FROM products WHERE id=?", (item["product"]["id"],)).fetchone()
            if not row or row["stock"] < item["quantity"]:
                return render_template("checkout.html", items=items, total=total,
                    error=f"Stok {item['product']['name']} tidak mencukupi.")
        cur      = db.execute("INSERT INTO orders (user_id,total,status,address) VALUES (?,?,?,?)",
                              (user_id, total, "pending", address))
        order_id = cur.lastrowid
        for item in items:
            db.execute("INSERT INTO order_items (order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)",
                       (order_id, item["product"]["id"], item["quantity"], item["product"]["price"]))
            db.execute("UPDATE products SET stock=stock-? WHERE id=?",
                       (item["quantity"], item["product"]["id"]))
        db.commit()
        session.pop("cart", None); session.modified = True
        logger.info(f"ORDER_CREATED | User='{g.user['username']}' | OrderId={order_id} | Total={total}")
        return redirect(url_for("order_success", order_id=order_id))

    return render_template("checkout.html", items=items, total=total, error=None)

@app.route("/order/success/<int:order_id>")
@login_required
def order_success(order_id):
    db    = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=? AND user_id=?",
                       (order_id, int(g.user["sub"]))).fetchone()
    if not order:
        return render_template("404.html"), 404
    items = db.execute("""SELECT oi.quantity, oi.unit_price, p.name
        FROM order_items oi JOIN products p ON p.id=oi.product_id
        WHERE oi.order_id=?""", (order_id,)).fetchall()
    return render_template("order_success.html", order=order, items=items)


# ══════════════════════════════════════════════
#  ROUTES — ADMIN
# ══════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin():
    logger.warning(f"ADMIN_ACCESS | IP={request.remote_addr} | Username='{g.user['username']}'")
    db  = get_db()
    tab = request.args.get("tab", "overview")

    # Overview data
    employees      = db.execute("SELECT * FROM employees").fetchall()
    sales          = db.execute("SELECT * FROM sales_report ORDER BY id DESC").fetchall()
    users          = db.execute("SELECT id,username,email,role,created_at FROM users").fetchall()
    total_products = db.execute("SELECT COUNT(*) as c FROM products").fetchone()["c"]
    total_orders   = db.execute("SELECT COUNT(*) as c FROM orders").fetchone()["c"]
    total_revenue  = db.execute(
        "SELECT COALESCE(SUM(total),0) as t FROM orders WHERE status='completed'"
    ).fetchone()["t"]

    # [S14] Transaksi semua user
    transactions = db.execute("""
        SELECT o.id, o.total, o.status, o.created_at, o.address,
               u.username, u.email,
               COUNT(oi.id) as item_count,
               GROUP_CONCAT(p.name || ' (×' || oi.quantity || ')', ', ') as items_summary
        FROM orders o
        JOIN users u        ON u.id=o.user_id
        JOIN order_items oi ON oi.order_id=o.id
        JOIN products p     ON p.id=oi.product_id
        GROUP BY o.id
        ORDER BY o.created_at DESC
    """).fetchall()

    # [S15] Semua produk (aktif & nonaktif)
    all_products   = db.execute("SELECT * FROM products ORDER BY is_active DESC, id").fetchall()
    categories     = db.execute("SELECT DISTINCT category FROM products WHERE is_active=1").fetchall()

    return render_template("admin.html",
        tab=tab,
        employees=employees, sales=sales, users=users,
        total_products=total_products, total_orders=total_orders, total_revenue=total_revenue,
        transactions=transactions,
        all_products=all_products, categories=categories,
    )


@app.route("/admin/order/status", methods=["POST"])
@admin_required
def admin_order_status():
    if not validate_csrf():
        return redirect(url_for("admin", tab="transactions"))
    try:
        order_id = int(request.form.get("order_id", 0))
    except ValueError:
        return redirect(url_for("admin", tab="transactions"))
    status = request.form.get("status", "pending")
    if status not in ("pending", "completed", "cancelled"):
        return redirect(url_for("admin", tab="transactions"))
    db = get_db()
    db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    db.commit()
    logger.info(f"ORDER_STATUS | Admin='{g.user['username']}' | OrderId={order_id} | Status={status}")
    return redirect(url_for("admin", tab="transactions"))


@app.route("/admin/product/add", methods=["POST"])
@admin_required
def admin_product_add():
    if not validate_csrf():
        return redirect(url_for("admin", tab="products"))
    name        = request.form.get("name", "").strip()[:200]
    description = request.form.get("description", "").strip()[:1000]
    category    = request.form.get("category_select") or request.form.get("category_new", "").strip()[:50]
    try:
        price = float(request.form.get("price", 0))
        stock = int(request.form.get("stock", 0))
    except ValueError:
        return redirect(url_for("admin", tab="products"))
    if not name or price <= 0 or stock < 0:
        return redirect(url_for("admin", tab="products"))
    db = get_db()
    db.execute("INSERT INTO products (name,description,price,category,stock,is_active) VALUES (?,?,?,?,?,1)",
               (name, description, price, category, stock))
    db.commit()
    logger.info(f"PRODUCT_ADDED | Admin='{g.user['username']}' | Name='{name}'")
    return redirect(url_for("admin", tab="products"))


@app.route("/admin/product/toggle/<int:product_id>", methods=["POST"])
@admin_required
def admin_product_toggle(product_id):
    if not validate_csrf():
        return redirect(url_for("admin", tab="products"))
    db  = get_db()
    row = db.execute("SELECT is_active FROM products WHERE id=?", (product_id,)).fetchone()
    if not row:
        return redirect(url_for("admin", tab="products"))
    new_status = 0 if row["is_active"] else 1
    db.execute("UPDATE products SET is_active=? WHERE id=?", (new_status, product_id))
    db.commit()
    logger.info(f"PRODUCT_{'ACTIVATED' if new_status else 'DEACTIVATED'} | Admin='{g.user['username']}' | id={product_id}")
    return redirect(url_for("admin", tab="products"))


# ══════════════════════════════════════════════
#  Error Handlers
# ══════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e): return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e): return render_template("403.html"), 403

@app.errorhandler(413)
def too_large(e):
    return render_template("profile.html",
        username=getattr(g, "user", {}).get("username", ""),
        upload_info=None, error="Ukuran file melebihi batas 2MB."), 413


# ══════════════════════════════════════════════
#  Entry Point
# ══════════════════════════════════════════════

if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # init_db()
    port  = int(os.environ.get("FLASK_PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="0.0.0.0", port=port)