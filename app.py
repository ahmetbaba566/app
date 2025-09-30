from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import datetime
import os

app = Flask(__name__)
CORS(app)

DATABASE = "database.db"

# ----------------- DB Başlangıç -----------------
def init_db():
    if not os.path.isfile(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                hwid TEXT,
                expires_at TEXT,
                is_admin INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
        print("Veritabanı oluşturuldu.")

# ----------------- Yardımcı -----------------
def get_key_data(key):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT license_key, hwid, expires_at, is_admin FROM keys WHERE license_key = ?", (key,))
    result = cursor.fetchone()
    conn.close()
    return result

# ----------------- API -----------------
@app.route("/api/validate_key", methods=["POST"])
def validate_key():
    data = request.get_json()
    key = data.get("key")
    hwid = data.get("hwid")

    if not key or not hwid:
        return jsonify({"success": False, "message": "Eksik parametre"}), 400

    row = get_key_data(key)
    if not row:
        return jsonify({"success": False, "message": "Key bulunamadı"}), 404

    _, db_hwid, expires_at, is_admin = row

    # İlk girişte HWID yoksa kaydet
    if not db_hwid:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("UPDATE keys SET hwid = ? WHERE license_key = ?", (hwid, key))
        conn.commit()
        conn.close()
        db_hwid = hwid

    if db_hwid != hwid:
        return jsonify({"success": False, "message": "Farklı cihaz (HWID uyuşmuyor)"}), 403

    if not is_admin:
        if expires_at:
            exp_date = datetime.datetime.strptime(expires_at, "%Y-%m-%d")
            if datetime.datetime.now() > exp_date:
                return jsonify({"success": False, "message": "Key süresi dolmuş"}), 403

    return jsonify({"success": True, "message": "Key geçerli", "is_admin": bool(is_admin)})

# ----------------- Giriş -----------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
