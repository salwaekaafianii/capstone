from flask_bcrypt import Bcrypt
import mysql.connector

# =========================
# KONFIGURASI DATABASE
# =========================
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",        # sesuaikan
    database="capstone_web"
)

cursor = db.cursor(dictionary=True)
bcrypt = Bcrypt()

# =========================
# AMBIL SEMUA TUKANG
# =========================
cursor.execute("""
    SELECT id_users, password
    FROM users
    WHERE role = 'tukang'
""")

tukang_list = cursor.fetchall()

print(f"Total tukang ditemukan: {len(tukang_list)}")

# =========================
# HASH PASSWORD
# =========================
updated = 0

for tukang in tukang_list:
    user_id = tukang["id_users"]
    password = tukang["password"]

    # Lewati jika sudah hash bcrypt
    if password and password.startswith("$2"):
        continue

    if not password:
        print(f"User ID {user_id} password kosong, dilewati")
        continue

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

    cursor.execute("""
        UPDATE users
        SET password = %s
        WHERE id_users = %s
    """, (hashed, user_id))

    updated += 1
    print(f"✔ Password di-hash untuk user_id {user_id}")

db.commit()

print("=================================")
print(f"Selesai. Total password di-hash: {updated}")
print("=================================")

cursor.close()
db.close()
