# ⚠️ IBDA3202_Store — Secure Web App (Lab Keamanan)

> **PERINGATAN**: Aplikasi ini DIBUAT untuk keperluan edukasi dan latihan cybersecurity.  
> **JANGAN** jalankan di lingkungan produksi atau jaringan publik.

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
*Dibuat untuk keperluan edukasi cybersecurity — IBDA3202*
