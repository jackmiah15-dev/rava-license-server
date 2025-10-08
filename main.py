# main.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import json, time, jwt, os
from functools import wraps

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "jackmiah15@gmail.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "WoGlKaNaAnJm06")

LICENSE_FILE = "licenses.json"

# --- Utilities ---
def load_data():
    if not os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, "w") as f:
            json.dump({"pending": [], "users": []}, f)
    with open(LICENSE_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(LICENSE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"status": "error", "message": "Missing token"}), 401
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"status": "error", "message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": "error", "message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# --- Admin Login ---
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    if data.get("email") == ADMIN_EMAIL and data.get("password") == ADMIN_PASSWORD:
        token = jwt.encode({"email": ADMIN_EMAIL, "exp": time.time() + 3600}, SECRET_KEY, algorithm="HS256")
        return jsonify({"status": "success", "token": token})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route("/api/admin/verify")
@token_required
def verify_admin():
    return jsonify({"status": "success", "message": "Valid token"})

# --- License Management ---
@app.route("/api/pending_payments")
@token_required
def pending_payments():
    data = load_data()
    return jsonify({"status": "success", "payments": data.get("pending", [])})

@app.route("/api/all_users")
@token_required
def all_users():
    data = load_data()
    return jsonify({"status": "success", "users": data.get("users", [])})

@app.route("/api/approve_payment", methods=["POST"])
@token_required
def approve_payment():
    data = load_data()
    req = request.get_json()
    email, plan, days = req.get("email"), req.get("plan"), req.get("days", 30)

    user = {"email": email, "plan": plan, "license_key": f"LIC-{int(time.time())}",
            "expiry_timestamp": int(time.time()) + days * 86400,
            "days_remaining": days}
    data["users"].append(user)
    data["pending"] = [p for p in data["pending"] if p["email"] != email]
    save_data(data)
    return jsonify({"status": "approved", "message": f"License for {email} approved"})

@app.route("/api/reject_payment", methods=["POST"])
@token_required
def reject_payment():
    data = load_data()
    req = request.get_json()
    pid = req.get("id")
    data["pending"] = [p for p in data["pending"] if str(p.get("id")) != str(pid)]
    save_data(data)
    return jsonify({"status": "success", "message": f"Payment {pid} rejected"})

# --- Client License Check ---
@app.route("/api/check_license")
def check_license():
    email = request.args.get("email")
    key = request.args.get("key")
    data = load_data()
    for user in data.get("users", []):
        if user["email"] == email and user["license_key"] == key:
            if time.time() < user["expiry_timestamp"]:
                remaining = int((user["expiry_timestamp"] - time.time()) / 86400)
                return jsonify({"status": "valid", "days_remaining": remaining})
            else:
                return jsonify({"status": "expired"})
    return jsonify({"status": "invalid"})

# --- Health check ---
@app.route("/")
def root():
    return jsonify({"status": "ok", "message": "Rava License Server running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
