from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from db import db, cursor
from flask_socketio import SocketIO
from api import api, bcrypt 
import os
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
import secrets
from dotenv import load_dotenv

app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'kunci-rahasia-teman-tukang-yang-kuat'
app.config['JWT_SECRET_KEY'] = 'jwt-rahasia-teman-tukang'

load_dotenv()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

google = oauth.create_client('google')

socketio = SocketIO(app, cors_allowed_origins="*")
import socket_chat

CORS(app)
JWTManager(app)
app.register_blueprint(api)
bcrypt.init_app(app)

class Admin:
    def __init__(self, db_cursor):
        self.cursor = db_cursor

    def login(self, email, password):
        self.cursor.execute(
            "SELECT * FROM users WHERE email=%s AND role='admin'", (email,)
        )
        admin = self.cursor.fetchone()

        if not admin:
            return False, "Admin tidak ditemukan!"

        if not bcrypt.check_password_hash(admin['password'], password):
            return False, "Password salah!"

        return True, admin
    
    def register(self, nama, email, password):
        # cek email
        self.cursor.execute(
            "SELECT * FROM users WHERE email=%s", (email,)
        )
        if self.cursor.fetchone():
            return False, "Email sudah terdaftar!"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        self.cursor.execute(
            """
            INSERT INTO users (username, email, password, role)
            VALUES (%s, %s, %s, 'admin')
            """,
            (nama, email, hashed_password)
        )
        db.commit()

        return True, "Admin berhasil didaftarkan"

    def dashboard_data(self):
        self.cursor.execute("SELECT COUNT(*) total FROM users WHERE role='tukang'")
        total_akun_tukang = self.cursor.fetchone()['total']

        self.cursor.execute("SELECT COUNT(*) total FROM users WHERE role='customer'")
        total_customer = self.cursor.fetchone()['total']

        self.cursor.execute("SELECT IFNULL(ROUND(AVG(rating),1),0) avg_rating FROM review")
        avg_rating = self.cursor.fetchone()['avg_rating']

        rating_counts = {}
        for i in range(1, 6):
            self.cursor.execute("SELECT COUNT(*) total FROM review WHERE rating=%s", (i,))
            rating_counts[i] = self.cursor.fetchone()['total']

        return {
            "total_akun_tukang": total_akun_tukang,
            "total_customer": total_customer,
            "avg_rating": avg_rating,
            "rating_counts": rating_counts
        }
    def pesanan_dashboard(self):
        self.cursor.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(status='menunggu_konfirmasi') AS menunggu,
            SUM(status='diterima') AS diterima,
            SUM(status='selesai') AS selesai,
            SUM(status='ditolak') AS ditolak
        FROM pesanan
        """)
        return self.cursor.fetchone()

class KelolaTukang:
    def __init__(self, db_cursor):
        self.cursor = db_cursor

    def list_akun(self, keyword=None):
        if keyword:
            self.cursor.execute("""
                SELECT * FROM users 
                WHERE role='tukang'
                AND (username LIKE %s OR email LIKE %s)
            """, (f"%{keyword}%", f"%{keyword}%"))
        else:
            self.cursor.execute(
                "SELECT * FROM users WHERE role='tukang'"
            )
        return self.cursor.fetchall()


    def add_akun(self, username, email, password):
        self.cursor.execute(
            "INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,'tukang')",
            (username, email, password)
        )
        db.commit()

    def edit_akun(self, id_users, username, email, password):
        self.cursor.execute(
            "UPDATE users SET username=%s,email=%s,password=%s WHERE id_users=%s",
            (username, email, password, id_users)
        )
        db.commit()

    def delete_akun(self, id_users):
        self.cursor.execute("DELETE FROM users WHERE id_users=%s", (id_users,))
        db.commit()

class Customer:
    def __init__(self, db_cursor):
        self.cursor = db_cursor

    def list_customers(self, keyword=None):
        if keyword:
            self.cursor.execute("""
            SELECT * FROM users
            WHERE role='customer'
            AND (username LIKE %s OR email LIKE %s)
        """, (f"%{keyword}%", f"%{keyword}%"))
        else:
            self.cursor.execute("SELECT * FROM users WHERE role='customer'")
        return self.cursor.fetchall()

    def add_customer(self, username, email, password):
        self.cursor.execute(
            "INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,'customer')",
            (username, email, password)
        )
        db.commit()

    def edit_customer(self, id_users, username, email, password):
        self.cursor.execute(
            "UPDATE users SET username=%s,email=%s,password=%s WHERE id_users=%s",
            (username, email, password, id_users)
        )
        db.commit()

    def delete_customer(self, id_users):
        self.cursor.execute("DELETE FROM users WHERE id_users=%s", (id_users,))
        db.commit()

class DetailTukang:
    def __init__(self, db_cursor):
        self.cursor = db_cursor

    def list_tukang(self, keyword=None):
        if keyword:
            self.cursor.execute("""
            SELECT * FROM tukang
            WHERE nama LIKE %s OR keahlian LIKE %s
        """, (f"%{keyword}%", f"%{keyword}%"))
        else:
            self.cursor.execute("SELECT * FROM tukang")
        return self.cursor.fetchall()


    def add_tukang(self, id_users, nama, keahlian, pengalaman, foto):
        self.cursor.execute(
            """
            INSERT INTO tukang 
            (id_users, nama, keahlian, pengalaman, foto)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (id_users, nama, keahlian, pengalaman, foto)
    )
        db.commit()


    def edit_tukang(self, id, nama, keahlian, pengalaman, foto):
        self.cursor.execute("""
        UPDATE tukang SET
        nama=%s,
        keahlian=%s,
        pengalaman=%s,
        foto=%s
        WHERE id_tukang=%s
    """, (nama, keahlian, pengalaman, foto, id))
        db.commit()

    def delete_tukang(self, id_tukang):
        self.cursor.execute("DELETE FROM tukang WHERE id_tukang=%s", (id_tukang,))
        db.commit()

class Review:
    def __init__(self, db_cursor):
        self.cursor = db_cursor

    def list_review(self):
        self.cursor.execute("""
            SELECT r.review_text,r.rating,r.sentiment,r.tanggal,
                   u.username AS customer,t.nama AS tukang
            FROM review r
            JOIN users u ON r.user_id=u.id_users
            JOIN tukang t ON r.tukang_id=t.id_tukang
            ORDER BY r.tanggal DESC
        """)
        return self.cursor.fetchall()
    
class KelolaPesanan:
    def __init__(self, db_cursor):
        self.cursor = db_cursor

    def list_pesanan(self, keyword=None):
        if keyword:
            self.cursor.execute("""
                SELECT
                    p.id_pesanan,
                    u.username AS customer,
                    t.nama AS tukang,
                    p.tanggal_pengerjaan,
                    p.harga_per_hari,
                    p.status,
                    p.metode_pembayaran,
                    p.status_pembayaran,
                    p.created_at
                FROM pesanan p
                JOIN users u ON p.user_id = u.id_users
                JOIN tukang t ON p.tukang_id = t.id_tukang
                WHERE
                    u.username LIKE %s OR
                    t.nama LIKE %s OR
                    p.status LIKE %s
                ORDER BY p.created_at DESC
            """, (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"))
        else:
            self.cursor.execute("""
                SELECT
                    p.id_pesanan,
                    u.username AS customer,
                    t.nama AS tukang,
                    p.tanggal_pengerjaan,
                    p.harga_per_hari,
                    p.status,
                    p.metode_pembayaran,
                    p.status_pembayaran,
                    p.created_at
                FROM pesanan p
                JOIN users u ON p.user_id = u.id_users
                JOIN tukang t ON p.tukang_id = t.id_tukang
                ORDER BY p.created_at DESC
            """)
        return self.cursor.fetchall()

    def detail_pesanan(self, id_pesanan):
        self.cursor.execute("""
            SELECT
                p.id_pesanan,
                p.alamat,
                p.tanggal_pengerjaan,
                p.harga_per_hari,
                p.status,
                p.metode_pembayaran,
                p.status_pembayaran,
                p.bukti_pembayaran,
                u.username AS customer,
                t.nama AS tukang
            FROM pesanan p
            JOIN users u ON p.user_id = u.id_users
            JOIN tukang t ON p.tukang_id = t.id_tukang
            WHERE p.id_pesanan=%s
        """, (id_pesanan,))
        return self.cursor.fetchone()

    def verifikasi_pembayaran(self, id_pesanan, status):
        self.cursor.execute("""
            UPDATE pesanan
            SET status_pembayaran=%s
            WHERE id_pesanan=%s
        """, (status, id_pesanan))
        db.commit()

class WebPromosi:
    def index(self):
        return render_template('index.html')
    
admin_obj = Admin(cursor)
tukang_obj = KelolaTukang(cursor)
customer_obj = Customer(cursor)
detail_tukang_obj = DetailTukang(cursor)
review_obj = Review(cursor)
pesanan_obj = KelolaPesanan(cursor)
web_promosi = WebPromosi()

# ROUTES
# Admin
@app.route('/login/google')
def login_google():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce 

    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(
        redirect_uri,
        nonce=nonce,
        prompt="select_account"
    )

@app.route('/login/google/callback')
def google_callback():
    token = google.authorize_access_token()

    nonce = session.pop('nonce', None)
    user = google.parse_id_token(token, nonce=nonce)  

    google_id = user['sub']
    email = user['email']
    nama = user.get('name')

    cursor.execute(
        "SELECT * FROM users WHERE google_id=%s AND auth_provider='google'",
        (google_id,)
    )
    admin = cursor.fetchone()

    if not admin:
        cursor.execute("""
            INSERT INTO users
            (username, email, google_id, auth_provider, role)
            VALUES (%s,%s,%s,'google','admin')
        """, (nama, email, google_id))
        db.commit()

        cursor.execute(
            "SELECT * FROM users WHERE google_id=%s",
            (google_id,)
        )
        admin = cursor.fetchone()

    session['user_id'] = admin['id_users']
    session['username'] = admin['username']
    session['user_role'] = admin['role']
    session['auth_provider'] = 'google'

    flash("Login Google berhasil", "success")
    return redirect(url_for('admin_dashboard_route'))

@app.route('/login/admin', methods=['GET','POST'])
def login_admin_route():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        success, result = admin_obj.login(email, password)
        if not success:
            flash(result, "danger")
            return redirect(url_for('login_admin_route'))
        session['user_id'] = result['id_users']
        session['user_role'] = result['role']
        session['user_email'] = result['email']  
        session['username'] = result['username'] 
        return redirect(url_for('admin_dashboard_route'))
    return render_template('admin/login_admin.html')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin_route():
    if request.method == 'POST':
        nama = request.form['nama']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Password tidak sama!", "danger")
            return redirect(url_for('register_admin_route'))

        success, message = admin_obj.register(nama, email, password)
        if not success:
            flash(message, "danger")
            return redirect(url_for('register_admin_route'))

        flash("Admin berhasil didaftarkan", "success")
        return redirect(url_for('login_admin_route'))

    return render_template('admin/register_admin.html')

@app.route('/logout')
def logout_admin_route():
    session.clear()
    flash("Admin telah logout.", "success")
    return redirect(url_for('login_admin_route'))

@app.route('/admin')
def admin_dashboard_route():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Akses ditolak!", "danger")
        return redirect(url_for('login_admin_route'))

    data = admin_obj.dashboard_data()
    pesanan = admin_obj.pesanan_dashboard() 

    return render_template(
        'admin/admin_dashboard.html',
        total_akun_tukang=data['total_akun_tukang'],
        total_customer=data['total_customer'],
        avg_rating=data['avg_rating'],
        rating_1=data['rating_counts'][1],
        rating_2=data['rating_counts'][2],
        rating_3=data['rating_counts'][3],
        rating_4=data['rating_counts'][4],
        rating_5=data['rating_counts'][5],

        total_pesanan=pesanan['total'],
        pesanan_menunggu=pesanan['menunggu'],
        pesanan_diterima=pesanan['diterima'],
        pesanan_selesai=pesanan['selesai'],
        pesanan_ditolak=pesanan['ditolak']
    )

# Kelola Tukang
@app.route('/admin/akun_tukang')
def list_akun_tukang_route():
    keyword = request.args.get('q')
    akun_tukang = tukang_obj.list_akun(keyword)
    return render_template('admin/akun_tukang.html', akun_tukang=akun_tukang)

@app.route('/admin/akun_tukang/add', methods=['GET','POST'])
def add_akun_tukang_route():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        tukang_obj.add_akun(username, email, password)
        flash("Akun tukang berhasil ditambahkan!", "success")
        return redirect(url_for('list_akun_tukang_route'))
    return render_template('admin/add_akun_tukang.html')

@app.route('/admin/akun_tukang/edit/<int:id>', methods=['GET','POST'])
def edit_akun_tukang_route(id):
    cursor.execute("SELECT * FROM users WHERE id_users=%s", (id,))
    tukang = cursor.fetchone()
    if request.method == 'POST':
        tukang_obj.edit_akun(id, request.form['username'], request.form['email'], request.form['password'])
        flash("Akun tukang berhasil diupdate", "success")
        return redirect(url_for('list_akun_tukang_route'))
    return render_template('admin/edit_akun_tukang.html', tukang=tukang)

@app.route('/admin/akun_tukang/delete/<int:id>')
def delete_akun_tukang_route(id):
    tukang_obj.delete_akun(id)
    flash("Akun tukang berhasil dihapus", "success")
    return redirect(url_for('list_akun_tukang_route'))

# Customer
@app.route('/admin/customers')
def list_customers_route():
    keyword = request.args.get('q')
    customers = customer_obj.list_customers(keyword)
    return render_template('admin/customers.html', customers=customers)


@app.route('/admin/customers/add', methods=['GET','POST'])
def add_customer_route():
    if request.method == 'POST':
        customer_obj.add_customer(request.form['username'], request.form['email'], request.form['password'])
        flash("Customer berhasil ditambahkan!", "success")
        return redirect(url_for('list_customers_route'))
    return render_template('admin/add_customer.html')

@app.route('/admin/customers/edit/<int:id>', methods=['GET','POST'])
def edit_customer_route(id):
    cursor.execute("SELECT * FROM users WHERE id_users=%s", (id,))
    customer = cursor.fetchone()
    if request.method == 'POST':
        customer_obj.edit_customer(id, request.form['username'], request.form['email'], request.form['password'])
        flash("Customer berhasil diupdate", "success")
        return redirect(url_for('list_customers_route'))
    return render_template('admin/edit_customer.html', customer=customer)

@app.route('/admin/customers/delete/<int:id>', methods=['GET','DELETE'])
def delete_customer_route(id):
    customer_obj.delete_customer(id)
    if request.method == 'DELETE':
        return jsonify({"message": "Customer berhasil dihapus!"})
    flash("Customer berhasil dihapus!", "success")
    return redirect(url_for('list_customers_route'))

# Detail Tukang
@app.route('/admin/tukang')
def list_detail_tukang_route():
    keyword = request.args.get('keyword')  
    tukang = detail_tukang_obj.list_tukang(keyword)
    return render_template('admin/tukang.html', tukang=tukang)

@app.route('/admin/tukang/add', methods=['GET', 'POST'])
def tambah_tukang():
    if request.method == 'POST':

        foto = request.files.get('foto')
        if not foto or foto.filename == '':
            flash("Foto wajib diupload", "danger")
            return redirect(request.url)

        id_users = request.form['id_users']
        nama = request.form['nama']
        keahlian = request.form['keahlian']
        pengalaman = request.form['pengalaman']

        filename = secure_filename(foto.filename)
        foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        detail_tukang_obj.add_tukang(
        id_users, nama, keahlian, pengalaman, filename
    )

        flash("Tukang berhasil ditambahkan", "success")
        return redirect('/admin/tukang')

    # GET
    cursor.execute("SELECT id_users, username FROM users WHERE role='tukang'")
    akun_tukang = cursor.fetchall()
    return render_template('admin/add_tukang.html', akun_tukang=akun_tukang)

@app.route("/admin/tukang/edit/<int:id>", methods=["GET", "POST"])
def edit_tukang(id):
    cursor.execute("SELECT * FROM tukang WHERE id_tukang=%s", (id,))
    t = cursor.fetchone()

    if not t:
        flash("Data tukang tidak ditemukan", "danger")
        return redirect("/admin/tukang")

    if request.method == "POST":
        nama = request.form['nama']
        keahlian = request.form['keahlian']
        pengalaman = request.form['pengalaman']

        foto = request.files.get('foto')

        if foto and foto.filename != '':
            filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = t['foto']

        detail_tukang_obj.edit_tukang(
            id, nama, keahlian, pengalaman, filename
        )

        flash("Data tukang berhasil diperbarui", "success")
        return redirect("/admin/tukang")

    return render_template("admin/edit_tukang.html", t=t)

@app.route('/admin/tukang/delete/<int:id>')
def delete_detail_tukang_route(id):
    detail_tukang_obj.delete_tukang(id)
    flash("Tukang berhasil dihapus", "success")
    return redirect(url_for('list_detail_tukang_route'))

# Review
@app.route('/admin/review')
def list_review_route():
    keyword = request.args.get('q', '').strip()  
    if keyword:
        cursor.execute("""
            SELECT r.review_text, r.rating, r.sentiment, r.tanggal,
                   u.username AS customer, t.nama AS tukang
            FROM review r
            JOIN users u ON r.user_id = u.id_users
            JOIN tukang t ON r.tukang_id = t.id_tukang
            WHERE r.review_text LIKE %s
               OR u.username LIKE %s
               OR t.nama LIKE %s
            ORDER BY r.tanggal DESC
        """, (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"))
    else:
        cursor.execute("""
            SELECT r.review_text, r.rating, r.sentiment, r.tanggal,
                   u.username AS customer, t.nama AS tukang
            FROM review r
            JOIN users u ON r.user_id = u.id_users
            JOIN tukang t ON r.tukang_id = t.id_tukang
            ORDER BY r.tanggal DESC
        """)
    reviews = cursor.fetchall()
    return render_template('admin/review.html', reviews=reviews, keyword=keyword)

# KelolaPesanan
@app.route('/admin/pesanan')
def admin_pesanan_route():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Akses ditolak!", "danger")
        return redirect(url_for('login_admin_route'))

    keyword = request.args.get('q')
    pesanan = pesanan_obj.list_pesanan(keyword)

    return render_template(
        'admin/kelola_pesanan.html',
        pesanan=pesanan
    )

@app.route('/admin/pesanan/<int:id>')
def admin_detail_pesanan_route(id):
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Akses ditolak!", "danger")
        return redirect(url_for('login_admin_route'))

    data = pesanan_obj.detail_pesanan(id)
    if not data:
        flash("Pesanan tidak ditemukan", "danger")
        return redirect(url_for('admin_pesanan_route'))

    return render_template(
        'admin/detail_pesanan.html',
        pesanan=data
    )
@app.route('/admin/pesanan/verifikasi/<int:id>', methods=['POST'])
def verifikasi_pembayaran_route(id):
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Akses ditolak!", "danger")
        return redirect(url_for('login_admin_route'))

    status = request.form['status_pembayaran']

    pesanan_obj.verifikasi_pembayaran(id, status)

    flash("Status pembayaran diperbarui", "success")
    return redirect(url_for('admin_detail_pesanan_route', id=id))

# WebPromosi
@app.route('/')
def index_route():
    return web_promosi.index()

@app.before_request
def log_request():
    if request.path.startswith("/api"):
        print("API HIT:", request.path)
        print("HEADERS:", request.headers)
        print("BODY:", request.get_data())

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

