from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import jwt
import time
import os
import psycopg
import json

# --- Environment Setup ---
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@rava.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "1234")
SECRET_KEY = os.getenv("SECRET_KEY", "rava_super_secret_key")
DATABASE_URL = os.getenv("DATABASE_URL")

# --- Flask setup ---
app = Flask(__name__)
CORS(app)

# --- Database helper ---
def get_db():
    if not DATABASE_URL:
        raise Exception("❌ DATABASE_URL is not set in environment variables.")
    return psycopg.connect(DATABASE_URL, autocommit=True)

def init_db():
    """Create the licenses table if it doesn't exist."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    license_key TEXT NOT NULL,
                    expiry_timestamp BIGINT NOT NULL,
                    days_remaining INT NOT NULL
                );
            """)

# --- Admin authentication ---
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        token = jwt.encode(
            {"admin": True, "exp": time.time() + 86400},  # 1 day
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"status": "success", "token": token})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

def require_admin(request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("admin"):
            return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    return None

# --- Admin verify ---
@app.route("/api/admin/verify")
def admin_verify():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 401
    return jsonify({"status": "success"})

# --- User list ---
@app.route("/api/all_users")
def all_users():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT email, license_key, expiry_timestamp, days_remaining FROM licenses;")
            rows = cur.fetchall()
            users = [
                {
                    "email": r[0],
                    "license_key": r[1],
                    "expiry_timestamp": r[2],
                    "days_remaining": r[3]
                } for r in rows
            ]
    return jsonify({"status": "success", "users": users})

# --- Pending payments (demo data) ---
@app.route("/api/pending_payments")
def pending_payments():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    pending = [
        {"id": 1, "email": "user1@example.com", "plan": "Pro", "created_at": int(time.time()) - 3600, "txid": "ABC123"},
        {"id": 2, "email": "user2@example.com", "plan": "Standard", "created_at": int(time.time()) - 7200, "txid": "XYZ789"},
    ]
    return jsonify({"status": "success", "payments": pending})

# --- Approve payment ---
@app.route("/api/approve_payment", methods=["POST"])
def approve_payment():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json or {}
    email = data.get("email")
    plan = data.get("plan")
    days = int(data.get("days", 30))

    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400

    expiry_timestamp = int(time.time()) + days * 86400
    license_key = f"LIC-{int(time.time())}-{email[:3].upper()}"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO licenses (email, license_key, expiry_timestamp, days_remaining) VALUES (%s, %s, %s, %s)",
                (email, license_key, expiry_timestamp, days)
            )

    return jsonify({"status": "approved", "message": f"License approved for {days} days"})

# --- Reject payment ---
@app.route("/api/reject_payment", methods=["POST"])
def reject_payment():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.json or {}
    pid = data.get("id")
    print(f"Rejected payment ID {pid}")
    return jsonify({"status": "success", "message": f"Payment {pid} rejected"})

# --- Check license ---
@app.route("/api/check_license")
def check_license():
    email = request.args.get("email")
    key = request.args.get("key")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT expiry_timestamp FROM licenses WHERE email = %s AND license_key = %s;",
                (email, key)
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"status": "invalid"})
            expiry = row[0]
            if time.time() > expiry:
                return jsonify({"status": "expired"})
            return jsonify({
                "status": "valid",
                "expires_on": time.strftime("%Y-%m-%d", time.localtime(expiry))
            })

# --- Serve Admin Dashboard ---
@app.route("/admin")
def serve_admin():
    return send_from_directory("static", "admin.html")

# --- Home Route ---
@app.route("/")
def home():
    return jsonify({
        "status": "ok",
        "message": "✅ RAVA License API with PostgreSQL is running",
        "endpoints": [
            "/api/admin/login",
            "/api/all_users",
            "/api/pending_payments",
            "/api/check_license"
        ]
    })

# --- Start app ---
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
