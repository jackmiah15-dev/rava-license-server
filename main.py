from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import jwt
import time
import os
import psycopg
import traceback

# --- Environment Setup ---
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@rava.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "1234")
SECRET_KEY = os.getenv("SECRET_KEY", "rava_super_secret_key")
DATABASE_URL = os.getenv("DATABASE_URL")

# --- Flask setup ---
app = Flask(__name__)

# ✅ Allow requests from your Netlify frontend + local dev
CORS(app, origins=[
    "https://rava-ai-trader.netlify.app",
    "http://localhost:3000"
], supports_credentials=True)

# --- Database helper ---
def get_db():
    if not DATABASE_URL:
        raise Exception("❌ DATABASE_URL is not set in environment variables.")
    return psycopg.connect(DATABASE_URL, autocommit=True)

def init_db():
    """Ensure all required tables and columns exist."""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Licenses table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS licenses (
                        id SERIAL PRIMARY KEY,
                        email TEXT NOT NULL,
                        license_key TEXT NOT NULL,
                        expiry_timestamp BIGINT DEFAULT 0,
                        days_remaining INT DEFAULT 0
                    );
                """)
                # Pending payments table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS pending_payments (
                        id SERIAL PRIMARY KEY,
                        email TEXT NOT NULL,
                        plan TEXT NOT NULL,
                        transaction_id TEXT,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                """)
        print("✅ Database tables verified and ready.")
    except Exception as e:
        print("❌ Database initialization failed:", e)
        traceback.print_exc()

# --- Admin authentication ---
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        token = jwt.encode(
            {"admin": True, "exp": time.time() + 86400},
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

# --- All users ---
@app.route("/api/all_users")
def all_users():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT email, license_key, expiry_timestamp, days_remaining
                    FROM licenses
                    ORDER BY id DESC;
                """)
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
    except Exception as e:
        print("❌ Error loading users:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- ✅ Save payment request ---
@app.route("/api/mark_payment_pending", methods=["POST", "OPTIONS"])
def mark_payment_pending():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.json or {}
    email = data.get("email")
    plan = data.get("plan")
    txn_id = data.get("transaction_id")

    if not email or not plan:
        return jsonify({"status": "error", "message": "Missing email or plan"}), 400

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO pending_payments (email, plan, transaction_id)
                    VALUES (%s, %s, %s);
                """, (email, plan, txn_id))
        print(f"💰 Payment pending for {email} ({plan}) TXN={txn_id}")
        return jsonify({"status": "pending", "email": email, "plan": plan}), 200
    except Exception as e:
        print("❌ Error marking payment pending:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- ✅ View pending payments ---
@app.route("/api/pending_payments")
def pending_payments():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, email, plan, transaction_id, created_at
                    FROM pending_payments
                    ORDER BY created_at DESC;
                """)
                rows = cur.fetchall()
                payments = [
                    {
                        "id": r[0],
                        "email": r[1],
                        "plan": r[2],
                        "transaction_id": r[3],
                        "created_at": r[4].isoformat()
                    } for r in rows
                ]
        return jsonify({"status": "success", "payments": payments})
    except Exception as e:
        print("❌ Error fetching pending payments:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- ✅ Approve payment ---
@app.route("/api/approve_payment", methods=["POST"])
def approve_payment():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json or {}
    pid = data.get("id")  # payment ID from pending_payments
    email = data.get("email")
    days = int(data.get("days", 30))

    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400

    try:
        expiry_timestamp = int(time.time()) + days * 86400
        license_key = f"LIC-{int(time.time())}-{email[:3].upper()}"

        with get_db() as conn:
            with conn.cursor() as cur:
                # Create the new license
                cur.execute("""
                    INSERT INTO licenses (email, license_key, expiry_timestamp, days_remaining)
                    VALUES (%s, %s, %s, %s)
                """, (email, license_key, expiry_timestamp, days))

                # Remove the approved payment from pending_payments
                if pid:
                    cur.execute("DELETE FROM pending_payments WHERE id = %s", (pid,))

        return jsonify({
            "status": "approved",
            "message": f"License approved for {days} days and payment cleared."
        })
    except Exception as e:
        print("❌ Error approving payment:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500
# --- ✅ Reject payment ---
@app.route("/api/reject_payment", methods=["POST"])
def reject_payment():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json or {}
    pid = data.get("id")

    if not pid:
        return jsonify({"status": "error", "message": "Missing payment ID"}), 400

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM pending_payments WHERE id = %s", (pid,))
        return jsonify({"status": "success", "message": f"Payment {pid} rejected and removed."})
    except Exception as e:
        print("❌ Error rejecting payment:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500
# --- Check license ---
@app.route("/api/check_license")
def check_license():
    email = request.args.get("email")
    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT license_key, expiry_timestamp, days_remaining
                    FROM licenses
                    WHERE email = %s;
                """, (email,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"status": "invalid"})
                license_key, expiry, days_remaining = row
                if time.time() > expiry:
                    return jsonify({
                        "status": "expired",
                        "expires_on": time.strftime("%Y-%m-%d", time.localtime(expiry))
                    })
                return jsonify({
                    "status": "valid",
                    "email": email,
                    "license_key": license_key,
                    "expires_on": time.strftime("%Y-%m-%d", time.localtime(expiry)),
                    "days_remaining": days_remaining
                })
    except Exception as e:
        print("❌ License check failed:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Reset expiry ---
@app.route("/api/reset_expiry", methods=["GET", "POST"])
def reset_expiry():
    try:
        now = int(time.time())
        new_expiry = now + 30 * 86400
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE licenses
                    SET expiry_timestamp = %s, days_remaining = 30;
                """, (new_expiry,))
        return jsonify({"status": "success", "message": "All licenses reset to 30 days"})
    except Exception as e:
        print("❌ Error resetting expiry:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Debug licenses ---
@app.route("/api/debug/licenses")
def debug_licenses():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT email, license_key, expiry_timestamp,
                           FLOOR((expiry_timestamp - EXTRACT(EPOCH FROM NOW())) / 86400) AS days_remaining
                    FROM licenses
                    ORDER BY email;
                """)
                rows = cur.fetchall()
                return jsonify({
                    "count": len(rows),
                    "licenses": rows
                })
    except Exception as e:
        print("❌ Error fetching licenses:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# --- Fix days remaining ---
@app.route("/api/fix_days", methods=["POST"])
def fix_days():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE licenses
                    SET days_remaining = GREATEST(0, FLOOR((expiry_timestamp - EXTRACT(EPOCH FROM NOW())) / 86400))
                    WHERE expiry_timestamp IS NOT NULL;
                """)
        return jsonify({"status": "success", "message": "days_remaining updated successfully"})
    except Exception as e:
        print("❌ Error updating days_remaining:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Admin UI ---
@app.route("/admin")
def serve_admin():
    return send_from_directory("static", "admin.html")

# --- Debug DB ---
@app.route("/api/debug/db")
def debug_db():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT NOW();")
                ts = cur.fetchone()[0]
        return jsonify({"status": "ok", "db_time": ts.isoformat()})
    except Exception as e:
        print("❌ Database debug failed:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Home ---
@app.route("/")
def home():
    return jsonify({
        "status": "ok",
        "message": "✅ RAVA License API with PostgreSQL is running",
        "endpoints": [
            "/api/admin/login",
            "/api/all_users",
            "/api/pending_payments",
            "/api/check_license",
            "/api/mark_payment_pending",
            "/api/reset_expiry",
            "/api/debug/licenses",
            "/api/fix_days"
        ]
    })

# --- Run ---
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
else:
    # ✅ ensure DB initialized even when gunicorn runs
    try:
        init_db()
    except Exception as e:
        print("⚠️ DB init skipped on import:", e)



