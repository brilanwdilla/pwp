import os
from functools import wraps

import mysql.connector
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

load_dotenv()

# Membuat aplikasi Flask yang menangani halaman dan permintaan dari browser.
app = Flask(__name__)

# Kunci ini dipakai Flask untuk mengamankan data session di browser.
app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di file .env")


# =========================
# KONEKSI DATABASE
# =========================
def get_db_connection():
    """Membuka koneksi MySQL menggunakan pengaturan dari file .env.

    Nilai bawaan digunakan jika host, username, atau nama database tidak
    tersedia di file .env. Password tidak memiliki nilai bawaan yang aman,
    sehingga biasanya harus diatur melalui MYSQL_PASSWORD.
    """
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv(
            "MYSQL_DATABASE", "db_perpustakaan"
        )
    )


# =========================
# MEMBUAT ADMIN AWAL
# =========================
def init_admin():
    """Memastikan akun admin awal tersedia sebelum aplikasi digunakan.

    Username dan password dibaca dari file .env. Fungsi hanya menambahkan
    akun jika username tersebut belum ditemukan, sehingga pemanggilan
    berulang tidak membuat akun duplikat.
    """
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD")

    if not password:
        raise RuntimeError("ADMIN_PASSWORD belum diatur di .env")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id FROM admin WHERE username = %s",
            (username,)
        )
        existing_admin = cur.fetchone()

        if existing_admin is None:
            # Simpan password dalam bentuk hash, bukan password aslinya.
            password_hash = generate_password_hash(password)

            cur.execute(
                """
                INSERT INTO admin (username, password)
                VALUES (%s, %s)
                """,
                (username, password_hash)
            )
            # Perubahan baru dikirim dan disimpan secara permanen di database.
            conn.commit()
    finally:
        # Tutup cursor dan koneksi baik operasi berhasil maupun gagal.
        cur.close()
        conn.close()


# =========================
# PELINDUNG SESSION
# =========================
def login_required(route_function):
    """Mencegah pengguna yang belum login membuka halaman khusus admin.

    Decorator ini memeriksa apakah ID admin tersimpan di session. Jika belum,
    pengguna diarahkan ke halaman login; jika sudah, fungsi route dijalankan.
    """
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("login"))

        # Jika sesi admin tersedia, lanjutkan ke halaman yang diminta.
        return route_function(*args, **kwargs)

    return wrapper

#============================
#menampilkan halaman beranda utama
#============================
@app.route("/")
def index():
    """Halaman depan umum yang mengarahkan ke login admin atau login user."""
    return render_template("index.html")


# =========================
# LOGIN Admin
# =========================
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    """Menampilkan formulir login atau memeriksa kredensial yang dikirim.

    Jika username dan password cocok, identitas admin disimpan di session
    agar dapat digunakan untuk mengenali login pada permintaan berikutnya.
    """
    if "admin_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Ambil data dari formulir; hapus spasi pinggir pada username.
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        try:
            # Parameter %s memisahkan data pengguna dari perintah SQL.
            cur.execute(
                "SELECT id, username, password FROM admin "
                "WHERE username = %s",
                (username,)
            )
            admin = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if admin and (check_password_hash(admin["password"], password) or admin["password"] == password):
            # Bersihkan session lama sebelum menyimpan identitas admin.
            session.clear()
            session["admin_id"] = admin["id"]
            session["username"] = admin["username"]

            return redirect(url_for("dashboard"))

        # Pesan yang ditampilkan sama untuk username dan password yang salah.
        flash("Username atau password salah.", "danger")

    return render_template("login.html")


# =========================
# REGISTER ADMIN
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():
    """Menampilkan formulir pendaftaran atau menyimpan admin baru.

    Pendaftaran menerima permintaan GET untuk menampilkan formulir dan POST
    untuk memvalidasi isian lalu membuat akun di database.
    """
    if "admin_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Baca data yang dikirim formulir; username dirapikan dari spasi pinggir.
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        konfirmasi_password = request.form.get(
            "konfirmasi_password", ""
        )

        # Tolak isian wajib yang kosong sebelum mengakses database.
        if not username or not password:
            flash("Username dan password wajib diisi.", "danger")
            return render_template("register.html")

        # Aturan sederhana agar password tidak terlalu pendek.
        if len(password) < 8:
            flash("Password minimal 8 karakter.", "danger")
            return render_template("register.html")

        # Pastikan pengguna mengetik password yang sama pada kedua kolom.
        if password != konfirmasi_password:
            flash("Konfirmasi password tidak cocok.", "danger")
            return render_template("register.html")

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Username harus unik agar setiap akun dapat dibedakan.
            cur.execute(
                "SELECT id FROM admin WHERE username = %s",
                (username,)
            )
            if cur.fetchone() is not None:
                flash("Username sudah digunakan.", "danger")
                return render_template("register.html")

            # Password di-hash sebelum disimpan, sama seperti admin awal.
            password_hash = generate_password_hash(password)
            cur.execute(
                """
                INSERT INTO admin (username, password)
                VALUES (%s, %s)
                """,
                (username, password_hash)
            )
            conn.commit()
        finally:
            # Lepaskan resource database meski query mengalami masalah.
            cur.close()
            conn.close()

        flash("Akun admin berhasil dibuat. Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
@login_required
def dashboard():
    """Menghitung jumlah jenis buku dan total stok untuk dashboard.

    Cursor dictionary membuat hasil query dapat dibaca menggunakan nama kolom.
    COALESCE mengubah hasil jumlah stok yang kosong menjadi angka nol.
    """
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        # COUNT menghitung jumlah baris, yaitu jumlah jenis/judul buku.
        cur.execute("SELECT COUNT(*) AS total FROM buku")
        total_buku = cur.fetchone()["total"]

        # SUM menjumlahkan stok semua buku; hasil kosong diganti dengan nol.
        cur.execute("SELECT COALESCE(SUM(stok), 0) AS total FROM buku")
        total_stok = cur.fetchone()["total"]
    finally:
        # Setiap query sudah selesai; tutup cursor dan koneksi database.
        cur.close()
        conn.close()

    # Kirim hasil perhitungan ke template agar dapat ditampilkan.
    return render_template(
        "dashboard.html",
        total_buku=total_buku,
        total_stok=total_stok
    )


# =========================
# DAFTAR BUKU
# =========================
@app.route("/buku")
@login_required
def daftar_buku():
    """Mengambil seluruh buku, diurutkan dari ID terbaru ke yang terlama."""
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        # Ambil semua kolom buku, lalu urutkan berdasarkan ID secara menurun.
        cur.execute("SELECT * FROM buku ORDER BY id DESC")
        daftar = cur.fetchall()
    finally:
        # Ambil semua baris terlebih dahulu, kemudian lepaskan resource DB.
        cur.close()
        conn.close()

    # Template menerima daftar hasil query untuk ditampilkan sebagai tabel.
    return render_template("buku.html", daftar=daftar)


# =========================
# TAMBAH BUKU
# =========================
@app.route("/buku/tambah", methods=["GET", "POST"])
@login_required
def tambah_buku():
    """Menampilkan formulir buku baru atau menyimpan isian yang valid.

    Nilai teks dirapikan dari spasi pinggir. Tahun dan stok harus berupa
    bilangan bulat, semua kolom teks wajib diisi, dan stok tidak boleh negatif.
    """
    if request.method == "POST":
        judul = request.form.get("judul", "").strip()
        penulis = request.form.get("penulis", "").strip()
        penerbit = request.form.get("penerbit", "").strip()

        try:
            # Form mengirim teks, jadi tahun dan stok perlu diubah menjadi angka.
            tahun = int(request.form.get("tahun_terbit", ""))
            stok = int(request.form.get("stok", ""))

            if not 1901 <= tahun <= 2155 or stok < 0:
                raise ValueError

            # Judul, penulis, dan penerbit juga wajib memiliki isi.
            if not judul or not penulis or not penerbit:
                raise ValueError

        except ValueError:
            # Kembalikan formulir dengan pesan jika angka atau isian tidak valid.
            flash("Periksa kembali data buku yang dimasukkan.", "danger")
            return render_template(
                "form_buku.html",
                buku=None,
                tahun_sekarang=2026
            )

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Simpan data menggunakan parameter query, bukan menyambung teks SQL.
            cur.execute(
                """
                INSERT INTO buku
                    (judul, penulis, penerbit, tahun_terbit, stok)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (judul, penulis, penerbit, tahun, stok)
            )
            conn.commit()
        finally:
            # Tutup resource setelah operasi penyimpanan selesai.
            cur.close()
            conn.close()

        flash("Buku berhasil ditambahkan.", "success")
        return redirect(url_for("daftar_buku"))

    return render_template(
        "form_buku.html",
        buku=None,
        tahun_sekarang=2026
    )


# =========================
# EDIT BUKU
# =========================
@app.route("/buku/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_buku(id):
    """Menampilkan formulir edit atau menyimpan perubahan untuk satu buku.

    ID buku berasal dari bagian URL. Jika data tidak ditemukan, pengguna
    dikembalikan ke daftar; jika ditemukan, formulir dapat ditampilkan atau
    perubahan dari permintaan POST divalidasi dan disimpan.
    """
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        # Parameter query memastikan pencarian menggunakan ID dari URL.
        cur.execute("SELECT * FROM buku WHERE id = %s", (id,))
        buku = cur.fetchone()

        if buku is None:
            flash("Buku tidak ditemukan.", "warning")
            return redirect(url_for("daftar_buku"))

        if request.method == "POST":
            # Ambil nilai terbaru dari formulir edit.
            judul = request.form.get("judul", "").strip()
            penulis = request.form.get("penulis", "").strip()
            penerbit = request.form.get("penerbit", "").strip()

            try:
                tahun = int(request.form.get("tahun_terbit", ""))
                stok = int(request.form.get("stok", ""))

                if (
                    not judul or not penulis or not penerbit
                    or not 1901 <= tahun <= 2155
                    or stok < 0
                ):
                    raise ValueError

            except ValueError:
                # Pertahankan data lama di formulir agar pengguna dapat mencoba lagi.
                flash("Periksa kembali data buku.", "danger")
                return render_template(
                    "form_buku.html",
                    buku=buku,
                    tahun_sekarang=2026
                )

            cur.execute(
                """
                UPDATE buku
                SET judul = %s, penulis = %s, penerbit = %s,
                    tahun_terbit = %s, stok = %s
                WHERE id = %s
                """,
                (judul, penulis, penerbit, tahun, stok, id)
            )
            conn.commit()

            flash("Data buku berhasil diperbarui.", "success")
            return redirect(url_for("daftar_buku"))

        return render_template(
            "form_buku.html",
            buku=buku,
            tahun_sekarang=2026
        )
    finally:
        # Jalur keluar apa pun akan tetap menutup cursor dan koneksi.
        cur.close()
        conn.close()


# =========================
# HAPUS BUKU
# =========================
@app.route("/buku/hapus/<int:id>", methods=["POST"])
@login_required
def hapus_buku(id):
    """Menghapus satu buku berdasarkan ID dan melaporkan hasilnya.

    Penghapusan hanya menerima POST, sehingga tidak dijalankan hanya dengan
    membuka tautan GET secara tidak sengaja.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Hapus baris yang ID-nya sama dengan ID dari alamat halaman.
        cur.execute("DELETE FROM buku WHERE id = %s", (id,))
        conn.commit()

        # rowcount bernilai benar jika query menghapus baris yang ditemukan.
        if cur.rowcount:
            flash("Buku berhasil dihapus.", "success")
        else:
            flash("Buku tidak ditemukan.", "warning")
    finally:
        # Selalu tutup resource database, termasuk jika query gagal.
        cur.close()
        conn.close()

    # Setelah penghapusan, kembali ke daftar buku.
    return redirect(url_for("daftar_buku"))

# =========================
# LOGOUT UNIVERSAL (ADMIN & USER)
# =========================
@app.route("/logout", methods=["POST"])
def logout():
    """Menghapus session dan mengarahkan sesuai siapa yang sedang login."""
    # Cek apakah yang sedang login sebelumnya adalah user
    is_user = "user_id" in session
    
    # Hapus seluruh data session
    session.clear()
    flash("Kamu berhasil logout.", "success")
    
    # Jika tadi user, kembalikan ke login user. Jika admin, ke login admin.
    if is_user:
        return redirect(url_for("login_user"))
    else:
        return redirect(url_for("login"))

# =========================
# LOGIN USER (ANGGOTA)
# =========================
@app.route("/user/login", methods=["GET", "POST"])
def login_user():
    """Halaman login khusus untuk user/peminjam buku."""
    if "user_id" in session:
        return redirect(url_for("dashboard_user"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        try:
            cur.execute("SELECT id, username, password FROM user WHERE username = %s", (username,))
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if user and (check_password_hash(user["password"], password) or user["password"] == password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard_user"))

        flash("Username atau password salah.", "danger")

    return render_template("login_user.html")


# =========================
# REGISTER USER (ANGGOTA)
# =========================
@app.route("/user/register", methods=["GET", "POST"])
def register_user():
    """Pendaftaran khusus untuk akun user/peminjam."""
    if "admin_id" in session or "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        konfirmasi_password = request.form.get("konfirmasi_password", "")

        if not username or not password:
            flash("Username dan password wajib diisi.", "danger")
            return render_template("register_user.html")

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "danger")
            return render_template("register_user.html")

        if password != konfirmasi_password:
            flash("Konfirmasi password tidak cocok.", "danger")
            return render_template("register_user.html")

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute("SELECT id FROM user WHERE username = %s", (username,))
            if cur.fetchone() is not None:
                flash("Username sudah digunakan.", "danger")
                return render_template("register_user.html")

            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            cur.execute(
                "INSERT INTO user (username, password) VALUES (%s, %s)",
                (username, password_hash)
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()

        flash("Akun user berhasil dibuat. Silakan login.", "success")
        return redirect(url_for("login_user"))

    return render_template("register_user.html")

# =========================
# LUPA PASSWORD USER
# =========================
@app.route("/user/lupa-password", methods=["GET", "POST"])
def lupa_password_user():
    """Halaman untuk mereset password user jika lupa."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password_baru = request.form.get("password_baru", "")
        konfirmasi_password = request.form.get("konfirmasi_password", "")

        if not username or not password_baru:
            flash("Username dan password baru wajib diisi.", "danger")
            return render_template("lupa_password.html")

        if len(password_baru) < 4:
            flash("Password baru minimal 4 karakter.", "danger")
            return render_template("lupa_password.html")

        if password_baru != konfirmasi_password:
            flash("Konfirmasi password tidak cocok.", "danger")
            return render_template("lupa_password.html")

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        try:
            # Cek apakah username terdaftar di database
            cur.execute("SELECT id FROM user WHERE username = %s", (username,))
            user = cur.fetchone()

            if user is None:
                flash("Username tidak ditemukan di database.", "danger")
                return render_template("lupa_password.html")

            # Update password baru (bisa di-hash atau plain text sesuai gaya database Anda)
            # Contoh jika menggunakan enkripsi hash standar:
            password_hash = generate_password_hash(password_baru, method='pbkdf2:sha256')
            
            cur.execute(
                "UPDATE user SET password = %s WHERE username = %s",
                (password_hash, username)
            )
            conn.commit()

            flash("Password berhasil direset! Silakan login dengan password baru Anda.", "success")
            return redirect(url_for("login_user"))
        finally:
            cur.close()
            conn.close()

    return render_template("lupa_password.html")

# =========================
# DASHBOARD USER (DENGAN RIWAYAT PEMINJAMAN)
# =========================
@app.route("/user/dashboard")
def dashboard_user():
    """Menampilkan katalog buku dan riwayat peminjaman buku oleh user."""
    if "user_id" not in session:
        flash("Silakan login terlebih dahulu sebagai user.", "warning")
        return redirect(url_for("login_user"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        # Ambil daftar seluruh buku
        cur.execute("SELECT id, judul, penulis, penerbit, tahun_terbit, stok FROM buku")
        daftar_buku = cur.fetchall()

        # Ambil riwayat buku yang sedang dipinjam oleh user ini
        cur.execute(
            """
            SELECT peminjaman.id AS peminjaman_id, buku.judul, peminjaman.tanggal_pinjam, peminjaman.status
            FROM peminjaman
            JOIN buku ON peminjaman.buku_id = buku.id
            WHERE peminjaman.user_id = %s AND peminjaman.status = 'dipinjam'
            """,
            (user_id,)
        )
        buku_dipinjam = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template(
        "dashboard_user.html", 
        daftar_buku=daftar_buku, 
        buku_dipinjam=buku_dipinjam
    )


# =========================
# MENU PINJAM BUKU
# =========================
@app.route("/user/pinjam/<int:id>", methods=["POST"])
def pinjam_buku(id):
    """Logika saat user meminjam buku, mencatat tanggal, dan mengurangi stok."""
    if "user_id" not in session:
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("login_user"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("SELECT judul, stok FROM buku WHERE id = %s", (id,))
        buku = cur.fetchone()

        if buku and buku["stok"] > 0:
            cur.execute("UPDATE buku SET stok = stok - 1 WHERE id = %s", (id,))
            
            # Catat transaksi peminjaman beserta tanggal hari ini secara otomatis
            cur.execute(
                """
                INSERT INTO peminjaman (user_id, buku_id, tanggal_pinjam, status)
                VALUES (%s, %s, CURDATE(), 'dipinjam')
                """,
                (user_id, id)
            )
            conn.commit()
            flash(f"Berhasil meminjam buku '{buku['judul']}'!", "success")
        else:
            flash("Maaf, stok buku ini sedang kosong.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("dashboard_user"))


# =========================
# MENU KEMBALIKAN BUKU
# =========================
@app.route("/user/kembali/<int:id>", methods=["POST"])
def kembalikan_buku(id):
    """Logika saat user mengembalikan buku, menambah stok, dan mengubah status."""
    if "user_id" not in session:
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("login_user"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute(
            """
            SELECT id, buku_id FROM peminjaman 
            WHERE id = %s AND user_id = %s AND status = 'dipinjam'
            """,
            (id, user_id)
        )
        peminjaman = cur.fetchone()

        if peminjaman:
            buku_id = peminjaman["buku_id"]

            # Ubah status menjadi 'dikembalikan'
            cur.execute(
                "UPDATE peminjaman SET status = 'dikembalikan' WHERE id = %s",
                (id,)
            )

            # Tambahkan kembali stok buku sebanyak 1
            cur.execute(
                "UPDATE buku SET stok = stok + 1 WHERE id = %s",
                (buku_id,)
            )
            conn.commit()
            flash("Buku berhasil dikembalikan. Terima kasih!", "success")
        else:
            flash("Data peminjaman tidak ditemukan.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("dashboard_user"))
# =========================
# JALANKAN APLIKASI
# =========================
if __name__ == "__main__":
    # Bagian ini hanya berjalan jika app.py dijalankan langsung.
    # Pastikan akun admin awal tersedia sebelum server menerima permintaan.
    init_admin()
    # Jalankan server Flask untuk pengembangan lokal.
    app.run(debug=True)