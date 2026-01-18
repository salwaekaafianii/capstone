import joblib
import numpy as np
import tensorflow as tf
from datetime import datetime
from PIL import Image
import os
from werkzeug.utils import secure_filename

from flask import Blueprint, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required
)

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from db import db, cursor
from socket_chat import emit_notifikasi 

# =========================
# INITIAL SETUP
# =========================
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
api = Blueprint("api", __name__)
bcrypt = Bcrypt()

GOOGLE_CLIENT_ID = "152566724840-itl7926ncrk5pi4lhqtmqtpoaioe5cgr.apps.googleusercontent.com"

# for keras image preprocessing
load_model = tf.keras.models.load_model
img_to_array = tf.keras.preprocessing.image.img_to_array

# =========================
# CONSTANTS
# =========================

PESANAN_MENUNGGU = "menunggu_konfirmasi"
PESANAN_DITERIMA = "diterima"
PESANAN_DITOLAK = "ditolak"
PESANAN_MENUJU = "menuju_lokasi"
PESANAN_PROSES = "dalam_pengerjaan"
PESANAN_SELESAI = "selesai"

VALID_STATUS_TUKANG = [
    PESANAN_MENUJU,
    PESANAN_PROSES,
    PESANAN_SELESAI
]

# =========================
# LOAD ML MODELS & DATA
# =========================

model = load_model("model/model_temantukang.keras")

labels = [
    "Retak Dinding",
    "Plafon Rusak",
    "Keramik Rusak",
    "Cat Mengelupas",
    "Kayu Kusen Lapuk",
    "Dinding Berjamur"
]

analisis_faktor = {
    "Retak Dinding": "Kerusakan terjadi karena fondasi mengalami penurunan tidak merata.",
    "Plafon Rusak": "Biasanya disebabkan kebocoran atau material rapuh.",
    "Keramik Rusak": "Terjadi akibat permukaan lantai tidak rata.",
    "Cat Mengelupas": "Dipicu kelembaban tinggi atau rembesan air.",
    "Kayu Kusen Lapuk": "Disebabkan paparan air dan jamur.",
    "Dinding Berjamur": "Akibat ventilasi buruk dan kelembaban tinggi."
}

svm_model = joblib.load("model/svm_model.pkl")
tfidf_vectorizer = joblib.load("model/tfidf_vectorizer.pkl")

def predict_sentiment(text):
    if not text:
        return "netral"
    vec = tfidf_vectorizer.transform([text])
    result = svm_model.predict(vec)[0]
    return "positif" if result == 1 else "negatif"

# =========================
# RECOMMENDATION SETUP
# =========================

cursor.execute("SELECT * FROM tukang")
TUKANG_DATA = cursor.fetchall()

dokumen_tukang = [
    f"{t['keahlian']} {t['pengalaman']}" for t in TUKANG_DATA
]

vectorizer = TfidfVectorizer()
TFIDF_MATRIX = vectorizer.fit_transform(dokumen_tukang) if dokumen_tukang else None

# =========================
# HELPERS
# =========================

def success(data=None, message=None, code=200):
    res = {"status": "success"}
    if message:
        res["message"] = message
    if data is not None:
        res["data"] = data
    return jsonify(res), code

def error(message, code=400):
    return jsonify({"status": "error", "message": message}), code

def success_response(data=None, message=None, code=200):
    # Alias for uniform API, same as success (optional)
    return success(data=data, message=message, code=code)

def error_response(message, code=400):
    return error(message, code=code)

def get_user_id():
    return int(get_jwt_identity())

def get_tukang_id():
    user_id = get_user_id()
    cursor.execute(
        "SELECT id_tukang FROM tukang WHERE id_users=%s", (user_id,)
    )
    row = cursor.fetchone()
    return row["id_tukang"] if row else None

def get_tukang_id_from_jwt():
    # Ensures get_tukang_id exists for correct tukang API
    return get_tukang_id()

def buat_notifikasi(user_id, judul, isi):
    cursor.execute(
        """
        INSERT INTO notifikasi (user_id, judul, isi, created_at)
        VALUES (%s, %s, %s, %s)
        """,
        (user_id, judul, isi, datetime.utcnow())
    )
    db.commit()
    emit_notifikasi(user_id, {"judul": judul, "isi": isi})

# =========================
# AUTHENTICATION
# =========================

@api.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    if not data:
        return error_response("Request tidak valid")
    nama = data.get("nama")
    email = data.get("email")
    password = data.get("password")
    if not nama or not email or not password:
        return error_response("Data tidak lengkap")
    cursor.execute("SELECT id_users FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        return error_response("Email sudah terdaftar")
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    cursor.execute(
        """
        INSERT INTO users (username, email, password, role, auth_provider)
        VALUES (%s, %s, %s, 'customer', 'local')
        """,
        (nama, email, hashed)
    )
    db.commit()
    return success_response(message="Registrasi berhasil", code=201)

@api.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return error("Email atau password salah", 401)
    token = create_access_token(identity=str(user["id_users"]))
    return success({
        "access_token": token,
        "user": {
            "id_users": user["id_users"],
            "username": user["username"],
            "role": user["role"]
        }
    })

# =========================
# GOOGLE LOGIN
# =========================

@api.route("/api/auth/google", methods=["POST"])
def api_login_google():
    token = request.json.get("id_token")
    if not token:
        return error_response("id_token wajib")
    try:
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError:
        return error_response("Token Google tidak valid", 401)
    google_id = idinfo["sub"]
    email = idinfo["email"]
    username = idinfo.get("name", email.split("@")[0])
    cursor.execute("SELECT * FROM users WHERE google_id=%s", (google_id,))
    user = cursor.fetchone()
    if not user:
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return error_response("Email sudah terdaftar dengan metode lain", 409)
        cursor.execute(
            """
            INSERT INTO users (username, email, role, auth_provider, google_id)
            VALUES (%s, %s, 'customer', 'google', %s)
            """,
            (username, email, google_id)
        )
        db.commit()
        cursor.execute("SELECT * FROM users WHERE google_id=%s", (google_id,))
        user = cursor.fetchone()
    token = create_access_token(identity=str(user["id_users"]))
    return success_response({
        "access_token": token,
        "user": {
            "id_users": user["id_users"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "auth_provider": user["auth_provider"]
        }
    })

# =========================
# ML IMAGE DETECTION
# =========================

@api.route("/api/deteksi", methods=["POST"])
def api_deteksi():
    if "file" not in request.files:
        return error_response("File gambar tidak ditemukan")
    file = request.files["file"]
    if file.filename == "":
        return error_response("File tidak valid")
    try:
        img = Image.open(file).convert("RGB")
        img = img.resize((128, 128))
        img = img_to_array(img) / 255.0
        img = np.expand_dims(img, axis=0)
        pred = model.predict(img)
        idx = int(np.argmax(pred))
        confidence = float(np.max(pred) * 100)
        hasil = labels[idx]
        return success_response({
            "hasil": hasil,
            "confidence": round(confidence, 2),
            "analisis": analisis_faktor.get(hasil, "")
        })
    except Exception:
        return error_response("Gagal memproses gambar", 500)

@api.route("/api/rekomendasi", methods=["POST"])
@jwt_required()
def api_rekomendasi():
    user_id = int(get_jwt_identity())  

    data = request.get_json()
    jenis_kerusakan = data.get("jenis_kerusakan")

    if not jenis_kerusakan:
        return jsonify({"error": "jenis_kerusakan required"}), 422

    query_vec = vectorizer.transform([jenis_kerusakan])
    sim_scores = cosine_similarity(query_vec, TFIDF_MATRIX).flatten()
    max_rating = max([t.get("rating", 0) for t in TUKANG_DATA] or [1])

    rekomendasi = []
    for i, t in enumerate(TUKANG_DATA):
        if sim_scores[i] >= 0.1:
            rating_norm = (t.get("rating", 0) / max_rating) if max_rating else 0
            score = 0.7 * sim_scores[i] + 0.3 * rating_norm

            rekomendasi.append({
                "id_tukang": t["id_tukang"],
                "nama": t["nama"],
                "keahlian": t["keahlian"],
                "pengalaman": t["pengalaman"],
                "rating": t.get("rating", 0),
                "foto": t.get("foto", ""),
                "score": round(score, 4)
            })
    
    rekomendasi = sorted(rekomendasi, key=lambda x: x["score"], reverse=True)

    return jsonify({
        "status": "success",
        "data": rekomendasi
    }), 200

# =========================
# PESANAN CUSTOMER
# =========================

@api.route("/api/pesanan", methods=["POST"])
@jwt_required()
def buat_pesanan():
    user_id = get_user_id()
    data = request.get_json()
    cursor.execute(
    """
    INSERT INTO pesanan
    (
        user_id, tukang_id, nama_customer, alamat,
        tanggal_pengerjaan, harga_per_hari,
        metode_pembayaran, status_pembayaran, status
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """,
    (
        user_id,
        data["tukang_id"],
        data["nama_customer"],
        data["alamat"],
        data["tanggal_pengerjaan"],
        data["harga_per_hari"],
        data.get("metode_pembayaran"),   
        "belum_bayar",
        PESANAN_MENUNGGU
    )
)
    db.commit()
    cursor.execute(
        "SELECT id_users FROM tukang WHERE id_tukang=%s",
        (data["tukang_id"],)
    )
    tukang = cursor.fetchone()
    if tukang:
        buat_notifikasi(
            tukang["id_users"],
            "Pesanan Baru",
            "Ada pesanan baru dari customer"
        )
    return success(message="Pesanan berhasil dibuat", code=201)

@api.route("/api/pesanan/upload-bukti/<int:id_pesanan>", methods=["POST"])
@jwt_required()
def upload_bukti_pembayaran(id_pesanan):
    if 'bukti_pembayaran' not in request.files:
        return error_response("File tidak ditemukan")

    file = request.files['bukti_pembayaran']
    ext = os.path.splitext(file.filename)[1]
    filename = secure_filename(f"{id_pesanan}_{int(datetime.now().timestamp())}{ext}")

    file.save(os.path.join(UPLOAD_FOLDER, filename))

    cursor.execute("""
        UPDATE pesanan
        SET
            bukti_pembayaran=%s,
            status_pembayaran='dibayar'
        WHERE id_pesanan=%s
    """, (filename, id_pesanan))

    db.commit()

    return success_response(message="Bukti pembayaran berhasil diupload")
@api.route("/api/pesanan/pembayaran/<int:id>", methods=["GET"])
@jwt_required()
def cek_pembayaran(id):
    cursor.execute("""
        SELECT metode_pembayaran, status_pembayaran, bukti_pembayaran
        FROM pesanan
        WHERE id_pesanan=%s
    """, (id,))
    data = cursor.fetchone()
    if not data:
        return error_response("Pesanan tidak ditemukan", 404)

    return success_response(data)

@api.route("/api/customer/home", methods=["GET"])
@jwt_required()
def home_customer():
    user_id = get_user_id()
    cursor.execute(
        """
        SELECT
            p.id_pesanan,
            t.nama AS nama_tukang,
            p.tanggal_pengerjaan,
            p.status,
            p.harga_per_hari
        FROM pesanan p
        JOIN tukang t ON p.tukang_id = t.id_tukang
        WHERE p.user_id=%s
          AND p.status != %s
        ORDER BY p.created_at DESC
        """, (user_id, PESANAN_SELESAI)
    )
    return success_response(cursor.fetchall())

@api.route("/api/customer/pesanan", methods=["GET"])
@jwt_required()
def riwayat_customer():
    user_id = get_user_id()
    cursor.execute(
        """
        SELECT
            p.id_pesanan,
            t.id_tukang AS tukang_id,
            t.nama AS nama_tukang,
            p.tanggal_pengerjaan,
            p.status,
            p.harga_per_hari,
            p.created_at
        FROM pesanan p
        JOIN tukang t ON p.tukang_id = t.id_tukang
        WHERE p.user_id=%s
        ORDER BY p.created_at DESC
        """, (user_id,)
    )
    return success_response(cursor.fetchall())

@api.route("/api/pesanan/<int:id_pesanan>", methods=["GET"])
@jwt_required()
def detail_pesanan(id_pesanan):
    user_id = get_user_id()
    cursor.execute(
        """
        SELECT
            p.*,
            t.nama AS nama_tukang
        FROM pesanan p
        JOIN tukang t ON p.tukang_id = t.id_tukang
        WHERE p.id_pesanan=%s
          AND p.user_id=%s
        """, (id_pesanan, user_id)
    )
    data = cursor.fetchone()
    if not data:
        return error_response("Pesanan tidak ditemukan", 404)
    return success_response(data)

# =========================
# PESANAN - TUKANG
# =========================

@api.route("/api/tukang/pesanan-masuk", methods=["GET"])
@jwt_required()
def pesanan_masuk_tukang():
    tukang_id = get_tukang_id()
    if not tukang_id:
        return error_response("Akun bukan tukang", 403)

    cursor.execute("""
        SELECT
            p.id_pesanan,
            u.username AS nama_customer,
            p.alamat,
            p.tanggal_pengerjaan,
            p.harga_per_hari,
            p.status
        FROM pesanan p
        JOIN users u ON p.user_id = u.id_users
        WHERE p.tukang_id = %s
          AND p.status = %s
        ORDER BY p.created_at DESC
    """, (tukang_id, PESANAN_MENUNGGU))

    return success_response(cursor.fetchall())

@api.route("/api/auth/check", methods=["GET"])
@jwt_required()
def check_token():
    return success_response({"valid": True})



# =========================
# TUKANG KONFIRMASI
# =========================

@api.route("/api/tukang/pesanan/konfirmasi", methods=["PUT"])
@jwt_required()
def konfirmasi_pesanan():
    tukang_id = get_tukang_id()
    data = request.get_json()
    cursor.execute(
        """
        UPDATE pesanan
        SET status=%s
        WHERE id_pesanan=%s AND tukang_id=%s
        """, (data["status"], data["id_pesanan"], tukang_id)
    )
    db.commit()
    cursor.execute(
        "SELECT user_id FROM pesanan WHERE id_pesanan=%s",
        (data["id_pesanan"],)
    )
    cust = cursor.fetchone()
    if cust:
        judul = "Pesanan Diterima" if data["status"] == PESANAN_DITERIMA else "Pesanan Ditolak"
        buat_notifikasi(cust["user_id"], judul, judul)
    return success(message="Pesanan diperbarui")

# =========================
# UPDATE STATUS PESANAN
# =========================

@api.route("/api/tukang/pesanan/status", methods=["PUT"])
@jwt_required()
def update_status():
    tukang_id = get_tukang_id()
    data = request.get_json()
    cursor.execute(
        """
        UPDATE pesanan
        SET status=%s
        WHERE id_pesanan=%s AND tukang_id=%s
        """, (data["status"], data["id_pesanan"], tukang_id)
    )
    db.commit()
    cursor.execute(
        "SELECT user_id FROM pesanan WHERE id_pesanan=%s",
        (data["id_pesanan"],)
    )
    cust = cursor.fetchone()
    if cust:
        buat_notifikasi(
            cust["user_id"],
            "Update Pesanan",
            f"Status pesanan sekarang: {data['status']}"
        )
    return success(message="Status diperbarui")

@api.route("/api/tukang/riwayat", methods=["GET"])
@jwt_required()
def riwayat_tukang():
    tukang_id = get_tukang_id()
    if not tukang_id:
        return error_response("Akun bukan tukang", 403)

    cursor.execute("""
        SELECT
            p.id_pesanan,
            u.username AS nama_customer,
            p.alamat,
            p.tanggal_pengerjaan,
            p.harga_per_hari,
            p.status,
            p.created_at
        FROM pesanan p
        JOIN users u ON p.user_id = u.id_users
        WHERE p.tukang_id = %s
        ORDER BY p.created_at DESC
    """, (tukang_id,))

    return success_response(cursor.fetchall())



# =========================
# REVIEW & SENTIMENT
# =========================

@api.route("/api/review", methods=["POST"])
@jwt_required()
def add_review():
    user_id = get_user_id()
    data = request.get_json()
    if not data:
        return error_response("Request tidak valid")
    tukang_id = data.get("tukang_id")
    review_text = data.get("review_text")
    rating = data.get("rating")
    if not tukang_id or not review_text or rating is None:
        return error_response("Data tidak lengkap")
    try:
        rating = int(rating)
    except ValueError:
        return error_response("Rating harus berupa angka")
    if rating < 1 or rating > 5:
        return error_response("Rating harus antara 1 sampai 5")
    sentiment = predict_sentiment(review_text)
    try:
        cursor.execute(
            """
            INSERT INTO review
            (user_id, tukang_id, review_text, sentiment, rating)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user_id,
                tukang_id,
                review_text,
                sentiment,
                rating
            )
        )
        cursor.execute(
            """
            UPDATE tukang
               SET
                rating = (
                    SELECT IFNULL(AVG(rating),0)
                    FROM review
                    WHERE tukang_id=%s
                ),
                jumlah_ulasan = (
                    SELECT COUNT(*)
                    FROM review
                    WHERE tukang_id=%s
                )
            WHERE id_tukang=%s
            """, (tukang_id, tukang_id, tukang_id)
        )
        db.commit()
        return success_response({
            "sentiment": sentiment
        }, message="Review berhasil ditambahkan", code=201)
    except Exception:
        db.rollback()
        return error_response("Gagal menyimpan review", 500)

# =========================
# PROFIL TUKANG (PRIBADI)
# =========================

@api.route("/api/tukang/profile", methods=["GET"])
@jwt_required()
def get_tukang_profile():
    user_id = get_user_id()
    cursor.execute(
        """
        SELECT
            id_tukang,
            nama,
            keahlian,
            pengalaman,
            foto,
            rating,
            jumlah_ulasan
        FROM tukang
        WHERE id_users=%s
        """, (user_id,)
    )
    tukang = cursor.fetchone()
    if not tukang:
        return jsonify({
            "status": "error",
            "message": "Profil tukang tidak ditemukan"
        }), 404
    return jsonify({
        "status": "success",
        "data": tukang
    }), 200

@api.route("/api/tukang/profile", methods=["PUT"])
@jwt_required()
def update_tukang_profile():
    user_id = get_user_id()
    data = request.get_json()
    if not data:
        return jsonify({
            "status": "error",
            "message": "Request tidak valid"
        }), 400
    cursor.execute("SELECT id_tukang FROM tukang WHERE id_users=%s", (user_id,))
    tukang = cursor.fetchone()
    if not tukang:
        return jsonify({
            "status": "error",
            "message": "Profil tukang tidak ditemukan"
        }), 404
    cursor.execute(
        """
        UPDATE tukang
        SET
            nama=%s,
            keahlian=%s,
            pengalaman=%s,
            foto=%s
        WHERE id_users=%s
        """, (
            data.get("nama"),
            data.get("keahlian"),
            data.get("pengalaman"),
            data.get("foto"),
            user_id
        )
    )
    db.commit()
    return jsonify({
        "status": "success",
        "message": "Profil berhasil diperbarui"
    }), 200

# =========================
# PROFIL TUKANG (PUBLIC)
# =========================

@api.route("/api/tukang/<int:id_tukang>", methods=["GET"])
@jwt_required()
def get_tukang_public(id_tukang):
    cursor.execute(
        """
        SELECT
            id_tukang,
            nama,
            keahlian,
            pengalaman,
            foto,
            rating,
            jumlah_ulasan
        FROM tukang
        WHERE id_tukang=%s
        """, (id_tukang,)
    )
    tukang = cursor.fetchone()
    if not tukang:
        return error_response("Tukang tidak ditemukan", 404)
    cursor.execute(
        """
        SELECT
            review_text,
            rating,
            sentiment,
            tanggal
        FROM review
        WHERE tukang_id=%s
        ORDER BY tanggal DESC
        """, (id_tukang,)
    )
    ulasan = cursor.fetchall()
    return success_response({
        "tukang": tukang,
        "ulasan": ulasan
    })

# =========================
# CHAT PESANAN
# =========================

@api.route("/api/chat/<int:pesanan_id>", methods=["GET"])
@jwt_required()
def get_chat(pesanan_id):
    user_id = get_user_id()
    cursor.execute(
        """
        SELECT id_pesanan
        FROM pesanan
        WHERE id_pesanan=%s
          AND (user_id=%s
               OR tukang_id IN (
                   SELECT id_tukang FROM tukang WHERE id_users=%s
               ))
        """, (pesanan_id, user_id, user_id)
    )
    if not cursor.fetchone():
        return jsonify({
            "status": "error",
            "message": "Akses ditolak"
        }), 403
    cursor.execute(
        """
        SELECT sender, message, created_at
        FROM chat
        WHERE pesanan_id=%s
        ORDER BY created_at ASC
        """, (pesanan_id,)
    )
    return jsonify({
        "status": "success",
        "data": cursor.fetchall()
    }), 200

@api.route("/api/chat", methods=["POST"])
@jwt_required()
def send_chat():
    user_id = get_user_id()
    data = request.get_json()
    if not data:
        return jsonify({
            "status": "error",
            "message": "Request tidak valid"
        }), 400
    pesanan_id = data.get("pesanan_id")
    message = data.get("message")
    if not pesanan_id or not message:
        return jsonify({
            "status": "error",
            "message": "Data tidak lengkap"
        }), 400
    cursor.execute("SELECT role FROM users WHERE id_users=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({
            "status": "error",
            "message": "User tidak valid"
        }), 401
    cursor.execute(
        """
        SELECT status
        FROM pesanan
        WHERE id_pesanan=%s
          AND (user_id=%s
               OR tukang_id IN (
                   SELECT id_tukang FROM tukang WHERE id_users=%s
               ))
        """, (pesanan_id, user_id, user_id)
    )
    pesanan = cursor.fetchone()
    if not pesanan or pesanan.get("status") == "selesai":
        return jsonify({
            "status": "error",
            "message": "Chat ditutup"
        }), 403
    cursor.execute(
        """
        INSERT INTO chat (pesanan_id, sender, message)
        VALUES (%s, %s, %s)
        """, (pesanan_id, user["role"], message)
    )
    db.commit()
    return jsonify({
        "status": "success",
        "message": "Pesan terkirim"
    }), 201

# =================================================
# NOTIFIKASI
# =================================================
@api.route("/api/notifikasi", methods=["GET"])
@jwt_required()
def get_notifikasi():
    user_id = get_user_id()
    cursor.execute("""
        SELECT id, judul, isi, is_read, created_at
        FROM notifikasi
        WHERE user_id=%s
        ORDER BY created_at DESC
    """, (user_id,))
    return success(cursor.fetchall())

@api.route("/api/tukang/rekap", methods=["GET"])
@jwt_required()
def rekap_tukang():
    tukang_id = get_tukang_id()
    if not tukang_id:
        return error_response("Akun bukan tukang", 403)

    cursor.execute("""
        SELECT
            SUM(CASE WHEN status = 'menunggu_konfirmasi' THEN 1 ELSE 0 END) AS masuk,
            SUM(CASE WHEN status = 'selesai' THEN 1 ELSE 0 END) AS selesai
        FROM pesanan
        WHERE tukang_id = %s
    """, (tukang_id,))

    data = cursor.fetchone()

    return success_response({
        "proyek_masuk": int(data["masuk"] or 0),
        "proyek_selesai": int(data["selesai"] or 0),
    })