# file: app.py
import base64
import hashlib
import hmac
import os
import time
import psycopg
import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# Allow CORS from your Netlify frontend
CORS(app, resources={r"/api/*": {"origins": "https://rava-ai-trader.netlify.app"}})

# --- CONFIG ---
SECRET_KEY = b"JXGjfZvXXyt74SuTlBRodp_j-JmfrOd-wZjudTxmGOI"   # for license key gen
DATABASE_URL = os.getenv("DATABASE_URL")

# JWT config
JWT_SECRET = os.getenv("JWT_SECRET", "WoGlKaNaAnJm06")   # CHANGE before production
JWT_EXPIRY = 86400  # 1 day

# Bootstrap token used *only* for initial admin registration
ADMIN_TOKEN = os.getenv("ADMIN_BOOTSTRAP_TOKEN", "supersecrettoken123")

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
            # admin_users table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at BIGINT NOT NULL
                );
            """)
        conn.commit()


# --- TEMPORARY ADMIN REGISTRATION ---
# @app.route("/api/admin/register", methods=["POST"])
# def admin_register():
  #  """One-time: Create a new admin user. DELETE after use!"""
   # data = request.get_json(force=True)
  #  email = data.get("email", "").strip().lower()
 #   password = data.get("password", "")
 #   token = data.get("token", "")

#    if token != ADMIN_TOKEN:
 #       return jsonify({"status": "error", "message": "Unauthorized"}), 401

#    if not email or not password:
 #       return jsonify({"status": "error", "message": "Missing email or password"}), 400

#    password_hash = generate_password_hash(password)

 #   try:
 #       with get_db() as conn:
 #           with conn.cursor() as cur:
 #               cur.execute("""
 #                   INSERT INTO admin_users (email, password_hash, created_at)
#                    VALUES (%s, %s, %s)
 #               """, (email, password_hash, int(time.time())))
  #          conn.commit()
 #   except Exception as e:
 #       return jsonify({"status": "error", "message": str(e)}), 400

  #  return jsonify({"status": "success", "email": email})


with app.app_context():
    init_db()


# --- ADMIN AUTH HELPERS ---
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Missing or invalid token"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            if payload.get("role") != "admin":
                raise jwt.InvalidTokenError
        except jwt.ExpiredSignatureError:
            return jsonify({"status": "error", "message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": "error", "message": "Invalid token"}), 401

        return f(*args, **kwargs)
    return wrapper


# --- ADMIN: LOGIN ---
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"status": "error", "message": "Missing email or password"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM admin_users WHERE email=%s", (email,))
            row = cur.fetchone()

    if not row or not check_password_hash(row[0], password):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # generate JWT
    payload = {
        "email": email,
        "role": "admin",
        "exp": int(time.time()) + JWT_EXPIRY
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify({"status": "success", "token": token})


# --- LICENSE CHECK (user side) ---
@app.route("/api/check_license", methods=["GET"])
def check_license():
    email = request.args.get("email", "").strip().lower()

    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            # First check if license exists
            cur.execute("SELECT license_key, expiry FROM licenses WHERE email = %s", (email,))
            row = cur.fetchone()

            if row:
                db_license, expiry = row

                # Check provided key
                if not license_key or not hmac.compare_digest(db_license, license_key):
                    return jsonify({"status": "invalid", "message": "Invalid license key"}), 403

                # Check expiry
                now = int(time.time())
                if now > expiry:
                    return jsonify({
                        "status": "expired",
                        "expires_on": time.ctime(expiry)
                    }), 403

                remaining_days = int((expiry - now) / 86400)
                return jsonify({
                    "status": "valid",
                    "email": email,
                    "license_key": db_license,
                    "expires_on": time.ctime(expiry),
                    "days_remaining": int((expiry - now) / 86400)
                })

            # If no license, check payments table
            cur.execute("SELECT status FROM payments WHERE email=%s ORDER BY id DESC LIMIT 1", (email,))
            pay = cur.fetchone()
            if pay:
                if pay[0] == "pending":
                    return jsonify({"status": "pending"})
                elif pay[0] == "rejected":
                    return jsonify({"status": "rejected"})

    # Default fallback
    return jsonify({"status": "inactive", "message": "No license or payment found"}), 404




# --- USER: MARK PAYMENT PENDING ---
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


# --- ADMIN: GET PENDING PAYMENTS ---
@app.route("/api/pending_payments", methods=["GET"])
@require_admin
def pending_payments():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email, plan, status, created_at FROM payments WHERE status='pending'")
            rows = cur.fetchall()

    payments = [
        {"id": r[0], "email": r[1], "plan": r[2], "status": r[3], "created_at": r[4]}
        for r in rows
    ]
    return jsonify({"status": "success", "payments": payments})


# --- ADMIN: APPROVE PAYMENT & ISSUE LICENSE ---
@app.route("/api/approve_payment", methods=["POST"])
@require_admin
def approve_payment():
    """Admin approves a payment and issues a license"""
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    plan = data.get("plan", "").strip().lower()
    days = int(data.get("days", 30))

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

    remaining_days = int((expiry - int(time.time())) / 86400)

    return jsonify({
        "status": "approved",
        "email": email,
        "plan": plan,
        "license_key": license_key,
        "expires_on": time.ctime(expiry),
        "expiry_timestamp": expiry,
        "days_remaining": remaining_days
    })

@app.route("/api/reject_payment", methods=["POST"])
@require_admin
def reject_payment():
    """Admin rejects a pending payment"""
    data = request.get_json(force=True)
    payment_id = data.get("id")

    if not payment_id:
        return jsonify({"status": "error", "message": "Missing payment ID"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE payments
                SET status='rejected'
                WHERE id=%s AND status='pending'
                RETURNING id
            """, (payment_id,))
            row = cur.fetchone()

            if not row:
                return jsonify({"status": "error", "message": "No pending payment found"}), 404

        conn.commit()

    return jsonify({
        "status": "success",
        "message": f"Payment {payment_id} rejected"
    })


# --- ADMIN: MANUAL LICENSE RENEW ---
@app.route("/api/renew_license", methods=["POST"])
@require_admin
def renew_license():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    days = int(data.get("days", 30))

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

    remaining_days = int((expiry - int(time.time())) / 86400)

    return jsonify({
        "status": "renewed",
        "email": email,
        "license_key": license_key,
        "expires_on": time.ctime(expiry),
        "expiry_timestamp": expiry,
        "days_remaining": remaining_days
    })


from flask import send_from_directory

@app.route("/admin")
def admin_page():
    return send_from_directory("static", "admin.html")
# --- MAIN ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)











