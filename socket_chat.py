from flask import request
from flask_socketio import emit, join_room
from flask_jwt_extended import decode_token
from extensions import socketio
from db import db, cursor
from datetime import datetime

# Menyimpan koneksi pengguna socket berdasarkan SID
connected_users = {}

def get_user_id_from_token(token: str):
    """
    Mendapatkan user_id dari JWT token.
    """
    try:
        if token and token.startswith("Bearer "):
            token = token.replace("Bearer ", "", 1)
        decoded = decode_token(token)
        return int(decoded["sub"])
    except Exception as e:
        print("JWT DECODE ERROR:", e)
        return None

@socketio.on("connect")
def handle_connect(auth):
    """
    Menangani event koneksi socket baru.
    """
    token = auth.get("token") if auth else None
    user_id = get_user_id_from_token(token)
    if not user_id:
        print("SOCKET REJECTED: User token invalid")
        return False
    connected_users[request.sid] = user_id
    print(f"SOCKET CONNECTED USER: {user_id}")

@socketio.on("disconnect")
def handle_disconnect():
    """
    Menangani event disconnect socket.
    """
    user_id = connected_users.pop(request.sid, None)
    print(f"SOCKET DISCONNECTED USER: {user_id}")

@socketio.on("join_chat")
def handle_join_chat(data):
    """
    Bergabung dalam percakapan chat berdasarkan pesanan.
    """
    user_id = connected_users.get(request.sid)
    if not user_id:
        emit("error", {"message": "Unauthorized"})
        return

    pesanan_id = data.get("pesanan_id")
    if not pesanan_id:
        emit("error", {"message": "Pesanan tidak valid"})
        return

    # Verifikasi bahwa user adalah bagian dari pesanan ini
    cursor.execute("""
        SELECT p.id_pesanan
        FROM pesanan p
        LEFT JOIN tukang t ON p.tukang_id = t.id_tukang
        WHERE p.id_pesanan = %s
          AND (p.user_id = %s OR t.id_users = %s)
    """, (pesanan_id, user_id, user_id))

    if not cursor.fetchone():
        emit("error", {"message": "Akses ditolak"})
        return

    room = f"pesanan_{pesanan_id}"
    join_room(room)
    print(f"USER {user_id} JOIN ROOM {room}")

    emit("joined_chat", {
        "pesanan_id": pesanan_id,
        "room": room
    })

@socketio.on("send_message")
def handle_send_message(data):
    """
    Mengirim pesan ke chat pesanan.
    """
    print("\n=== SEND_MESSAGE EVENT MASUK ===")
    print("RAW DATA:", data)

    user_id = connected_users.get(request.sid)
    if not user_id:
        emit("error", {"message": "Unauthorized"})
        return

    pesanan_id = data.get("pesanan_id")
    message = data.get("message")
    if not pesanan_id or not message:
        emit("error", {"message": "Data tidak lengkap"})
        return

    # Pastikan user ditemukan
    cursor.execute("SELECT role FROM users WHERE id_users=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        emit("error", {"message": "User tidak ditemukan"})
        return
    sender = user["role"]

    # Pastikan akses ke pesanan
    cursor.execute("""
        SELECT p.status
        FROM pesanan p
        LEFT JOIN tukang t ON p.tukang_id = t.id_tukang
        WHERE p.id_pesanan = %s
          AND (p.user_id = %s OR t.id_users = %s)
    """, (pesanan_id, user_id, user_id))
    pesanan = cursor.fetchone()
    if not pesanan:
        emit("error", {"message": "Pesanan tidak ditemukan"})
        return

    if pesanan.get("status") == "selesai":
        emit("chat_closed", {"message": "Chat sudah ditutup"})
        return

    now_utc = datetime.utcnow()
    cursor.execute("""
        INSERT INTO chat (pesanan_id, sender, message, created_at)
        VALUES (%s, %s, %s, %s)
    """, (pesanan_id, sender, message, now_utc))
    db.commit()

    room = f"pesanan_{pesanan_id}"
    emit("receive_message", {
        "pesanan_id": pesanan_id,
        "sender": sender,
        "message": message,
        "created_at": now_utc.isoformat()
    }, room=room)

    print(f"EMIT RECEIVE_MESSAGE KE ROOM {room}")

def emit_notifikasi(user_id, data):
    """
    Mengirim notifikasi ke user tertentu lewat channel socket.
    """
    for sid, uid in connected_users.items():
        if uid == user_id:
            socketio.emit("notifikasi", data, room=sid)