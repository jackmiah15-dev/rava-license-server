from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
import time
import os
import json

# --- Load env vars safely ---
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@rava.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "1234")
SECRET_KEY = os.getenv("SECRET_KEY", "rava_super_secret_key")
LICENSE_FILE = "licenses.json"

# --- Flask setup ---
app = Flask(__name__)
CORS(app)

# --- Helpers ---
def load_licenses():
    """Read licenses.json safely."""
    if not os.path.exists(LICENSE_FILE):
        return []
    with open(LICENSE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_licenses(data):
    """Write licenses.json safely."""
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# --- Admin authentication ---
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        token = jwt.encode(
            {"admin": True, "exp": time.time() + 86400},  # 1-day expiry
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"status": "success", "token": token})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

def require_admin(request):
    """Verify the admin token in Authorization header."""
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

# --- Protected endpoints ---
@app.route("/api/admin/verify")
def admin_verify():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 401
    return jsonify({"status": "success"})

@app.route("/api/all_users")
def all_users():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = load_licenses()
    return jsonify({"status": "success", "users": data})

@app.route("/api/pending_payments")
def pending_payments():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    # Example: show dummy pending payments (in real use, load from DB)
    pending = [
        {"id": 1, "email": "user1@example.com", "plan": "Pro", "created_at": int(time.time()) - 3600, "txid": "ABC123"},
        {"id": 2, "email": "user2@example.com", "plan": "Standard", "created_at": int(time.time()) - 7200, "txid": "XYZ789"},
    ]
    return jsonify({"status": "success", "payments": pending})

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

    users = load_licenses()
    expiry_timestamp = int(time.time()) + days * 86400
    new_license = {
        "email": email,
        "license_key": f"LIC-{int(time.time())}-{email[:3].upper()}",
        "expiry_timestamp": expiry_timestamp,
        "days_remaining": days,
    }
    users.append(new_license)
    save_licenses(users)

    return jsonify({"status": "approved", "message": f"License approved for {days} days"})

@app.route("/api/reject_payment", methods=["POST"])
def reject_payment():
    if not require_admin(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json or {}
    pid = data.get("id")
    # In real usage, remove from DB instead of print
    print(f"Rejected payment ID {pid}")
    return jsonify({"status": "success", "message": f"Payment {pid} rejected"})

# --- License check for the desktop app ---
@app.route("/api/check_license")
def check_license():
    email = request.args.get("email")
    key = request.args.get("key")

    users = load_licenses()
    for user in users:
        if user["email"] == email and user["license_key"] == key:
            if time.time() > user["expiry_timestamp"]:
                return jsonify({"status": "expired"})
            return jsonify({
                "status": "valid",
                "expires_on": time.strftime("%Y-%m-%d", time.localtime(user["expiry_timestamp"]))
            })
    return jsonify({"status": "invalid"})
@app.route('/')
def home():
    return jsonify({
        "status": "ok",
        "message": "✅ RAVA License API is running",
        "endpoints": [
            "/api/admin/login",
            "/api/all_users",
            "/api/pending_payments",
            "/api/check_license"
        ]
    })


# --- Entry point ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


