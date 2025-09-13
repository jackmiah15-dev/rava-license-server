# file: app.py
import base64
import hashlib
import hmac
import json
import os
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_KEY = b"JXGjfZvXXyt74SuTlBRodp_j-JmfrOd-wZjudTxmGOI"
DB_FILE = "licenses.json"
ADMIN_TOKEN = "supersecrettoken123"  # change before deploying


def generate_license(username: str) -> str:
    """Generate license key from username/email"""
    username_bytes = username.strip().lower().encode()
    signature = hmac.new(SECRET_KEY, username_bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


@app.route("/api/check_license", methods=["GET"])
def check_license():
    """Verify license validity for a user"""
    email = request.args.get("email", "").strip().lower()
    license_key = request.args.get("key", "").strip()

    if not email or not license_key:
        return jsonify({"status": "error", "message": "Missing email or key"}), 400

    expected_key = generate_license(email)
    if not hmac.compare_digest(expected_key, license_key):
        return jsonify({"status": "invalid", "message": "Invalid license key"}), 403

    db = load_db()
    expiry = db.get(email)
    if not expiry:
        return jsonify({"status": "inactive", "message": "No active license"}), 404

    now = int(time.time())
    if now > expiry:
        return jsonify({
            "status": "expired",
            "expires_on": time.ctime(expiry)
        }), 403

    remaining_days = int((expiry - now) / 86400)
    return jsonify({
        "status": "valid",
        "expires_on": time.ctime(expiry),
        "days_remaining": remaining_days
    })


@app.route("/api/renew_license", methods=["POST"])
def renew_license():
    """Extend or create license (admin only)"""
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    days = int(data.get("days", 30))
    token = data.get("token", "")

    if token != ADMIN_TOKEN:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    if not email:
        return jsonify({"status": "error", "message": "Missing email"}), 400

    db = load_db()
    expiry = int(time.time()) + days * 86400
    db[email] = expiry
    save_db(db)

    return jsonify({
        "status": "success",
        "email": email,
        "expires_on": time.ctime(expiry)
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
