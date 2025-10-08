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
CORS(app)

# --- Database helper ---
def get_db():
    if not DATABASE_URL:
        raise Exception("❌ DATABASE_URL is not set in environment variables.")
    return psycopg.connect(DATABASE_URL, autocommit=True)

def init_db():
    """Ensure the licenses table exists and all required columns are present."""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Create minimal table if not exists
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS licenses (
                        email TEXT NOT NULL,
                        license_key TEXT NOT NULL
                    );
                """)
                # Add missing columns
                cur.execute("""ALTER TABLE licenses ADD COLUMN IF NOT EXISTS id SERIAL PRIMARY KEY;""")
                cur.execute("""ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expiry_timestamp BIGINT DEFAULT 0;""")
                cur.execute("""ALTER TABLE licenses ADD COLUMN IF NOT EXISTS days_remaining INT DEFAULT 0;""")
        print("✅ Database schema verified and fixed if needed.")
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
            {"admin": True, "exp": time.time() + 86400},  # valid 1 day
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
        init_db()  # ensure table + columns exist
        with get_db() as conn:
            with conn.cursor() as cur:
                # Check if id column exists
                cur.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'licenses';
                """)
                cols = [r[0] for r in cur.fetchall()]
                order_clause = "ORDER BY id DESC" if "id" in cols else ""

                cur.execute(f"""
                    SELECT email, license_key, expiry_timestamp, days_remaining
                    FROM licenses
                    {order_clause};
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


# --- Pending payments (now empty, for future use) ---
@app.route("/api/pending_payments")
def pending_payments():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    # return empty list instead of demo data
    return jsonify({"status": "success", "payments": []})

# --- Approve payment ---
@app.route("/api/approve_payment", methods=["POST"])
def approve_payment():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json or {}
    email = data.get("email")
    days = int(data.get("days", 30))

    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400

    try:
        expiry_timestamp = int(time.time()) + days * 86400
        license_key = f"LIC-{int(time.time())}-{email[:3].upper()}"

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO licenses (email, license_key, expiry_timestamp, days_remaining)
                    VALUES (%s, %s, %s, %s)
                """, (email, license_key, expiry_timestamp, days))
        return jsonify({"status": "approved", "message": f"License approved for {days} days"})
    except Exception as e:
        print("❌ Error approving payment:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

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
    """Simplified license check: only requires email"""
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

                # Expired license
                if time.time() > expiry:
                    return jsonify({
                        "status": "expired",
                        "expires_on": time.strftime("%Y-%m-%d", time.localtime(expiry))
                    })

                # Valid license
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


# --- Serve Admin Dashboard ---
@app.route("/admin")
def serve_admin():
    return send_from_directory("static", "admin.html")

# --- Debug DB connection ---
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
@app.route("/api/reset_expiry", methods=["GET", "POST"])
def reset_expiry():
    """Give all licenses a fresh 30-day expiry."""
    try:
        now = int(time.time())
        new_expiry = now + 30 * 86400  # 30 days from now
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE licenses
                    SET expiry_timestamp = %s,
                        days_remaining = 30;
                """, (new_expiry,))
        return jsonify({"status": "success", "message": "All licenses reset to 30 days"})
    except Exception as e:
        print("❌ Error resetting expiry:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Debug and Maintenance Routes ---

@app.route("/api/debug/licenses")
def debug_licenses():
    """View all current licenses and their remaining days"""
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
        return jsonify({"error": str(e)}), 500


@app.route("/api/fix_days", methods=["POST"])
def fix_days():
    """Update the days_remaining values in the licenses table"""
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
        return jsonify({"status": "error", "message": str(e)}), 500


# --- Start app ---
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)








