# file: app.py
import base64
import hashlib
import hmac
import os
import time
import psycopg
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- CONFIG ---
SECRET_KEY = b"JXGjfZvXXyt74SuTlBRodp_j-JmfrOd-wZjudTxmGOI"
ADMIN_TOKEN = "supersecrettoken123"  # CHANGE before deploying!
DATABASE_URL = os.getenv("DATABASE_URL")


# --- DB CONNECTION ---
def get_db():
    return psycopg.connect(DATABASE_URL, sslmode="require")


# --- LICENSE KEY GENERATOR ---
def generate_license(username: str) -> str:
    """Generate license key from username/email"""
    username_bytes = username.strip().lower().encode()
    signature = hmac.new(SECRET_KEY, username_bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


# --- DB INIT ---
def init_db():
    """Create tables if they don’t exist"""
    with get_db() as conn:
        with conn.cursor() as cur:
            # licenses table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    email TEXT PRIMARY KEY,
                    license_key TEXT NOT NULL,
                    expiry BIGINT NOT NULL
                );
            """)
            # payments table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS payments (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    plan TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at BIGINT NOT NULL
                );
            """)
        conn.commit()


with app.app_context():
    init_db()


# --- LICENSE CHECK ---
@app.route("/api/check_license", methods=["GET"])
def check_license():
    email = request.args.get("email", "").strip().lower()
    license_key = request.args.get("key", "").strip()

    if not email or not license_key:
        return jsonify({"status": "error", "message": "Missing email or key"}), 400

    expected_key = generate_license(email)
    if not hmac.compare_digest(expected_key, license_key):
        return jsonify({"status": "invalid", "message": "Invalid license key"}), 403

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT expiry FROM licenses WHERE email = %s", (email,))
            row = cur.fetchone()

    if not row:
        return jsonify({"status": "inactive", "message": "No active license"}), 404

    expiry = row[0]
    now = int(time.time())

    if now > expiry:
        return jsonify({"status": "expired", "expires_on": time.ctime(expiry)}), 403

    remaining_days = int((expiry - now) / 86400)
    return jsonify({
        "status": "valid",
        "expires_on": time.ctime(expiry),
        "days_remaining": remaining_days
    })


# --- MARK PAYMENT PENDING (User clicks “I have paid”) ---
@app.route("/api/mark_payment_pending", methods=["POST"])
def mark_payment_pending():
    """Record a pending payment attempt"""
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    plan = data.get("plan", "").strip().lower()

    if not email or not plan:
        return jsonify({"status": "error", "message": "Missing email or plan"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO payments (email, plan, status, created_at)
                VALUES (%s, %s, 'pending', %s)
            """, (email, plan, int(time.time())))
        conn.commit()

    return jsonify({"status": "pending", "email": email, "plan": plan})


# --- ADMIN APPROVES PAYMENT & ISSUES LICENSE ---
@app.route("/api/approve_payment", methods=["POST"])
def approve_payment():
    """Admin approves a payment and issues a license"""
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    plan = data.get("plan", "").strip().lower()
    days = int(data.get("days", 30))
    token = data.get("token", "")

    if token != ADMIN_TOKEN:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    if not email or not plan:
        return jsonify({"status": "error", "message": "Missing email or plan"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            # update payment
            cur.execute("""
                UPDATE payments
                SET status='approved'
                WHERE email=%s AND plan=%s AND status='pending'
                RETURNING id
            """, (email, plan))
            payment_row = cur.fetchone()

            if not payment_row:
                return jsonify({"status": "error", "message": "No pending payment found"}), 404

            # issue license
            expiry = int(time.time()) + days * 86400
            license_key = generate_license(email)

            cur.execute("""
                INSERT INTO licenses (email, license_key, expiry)
                VALUES (%s, %s, %s)
                ON CONFLICT (email) DO UPDATE
                SET license_key = EXCLUDED.license_key,
                    expiry = EXCLUDED.expiry
            """, (email, license_key, expiry))

        conn.commit()

    return jsonify({
        "status": "approved",
        "email": email,
        "plan": plan,
        "license_key": license_key,
        "expires_on": time.ctime(expiry)
    })


# --- MANUAL ADMIN RENEW (still useful for extensions) ---
@app.route("/api/renew_license", methods=["POST"])
def renew_license():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    days = int(data.get("days", 30))
    token = data.get("token", "")

    if token != ADMIN_TOKEN:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400

    expiry = int(time.time()) + days * 86400
    license_key = generate_license(email)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (email, license_key, expiry)
                VALUES (%s, %s, %s)
                ON CONFLICT (email) DO UPDATE
                SET license_key = EXCLUDED.license_key,
                    expiry = EXCLUDED.expiry
            """, (email, license_key, expiry))
        conn.commit()

    return jsonify({
        "status": "success",
        "email": email,
        "license_key": license_key,
        "expires_on": time.ctime(expiry)
    })


# --- MAIN ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
