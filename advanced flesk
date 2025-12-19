#!/usr/bin/python3
"""
Advanced Flask Authentication Project
- Basic Auth
- JWT Auth
- Registration
- SQLite Database
- Role-based Access Control
- Logging Middleware
- Error Handling
Written with explanatory comments for project submission
"""

from flask import Flask, jsonify, request, g
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    create_refresh_token,
)
from datetime import timedelta
import sqlite3
import logging

# ------------------------------
# APP INITIALIZATION
# ------------------------------
app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
jwt = JWTManager(app)
auth = HTTPBasicAuth()

DATABASE = "users.db"


# ------------------------------
# DATABASE UTILITIES
# ------------------------------
def get_db():
    """Connect to SQLite database (created if missing)."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def init_db():
    """Create users table if not exists."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
        """
    )
    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ------------------------------
# LOGGING SETUP
# ------------------------------
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


@app.before_request
def log_request():
    """Simple logging middleware."""
    logging.info(f"Request: {request.method} {request.path}")


# ------------------------------
# BASIC AUTH SECTION
# ------------------------------
@auth.verify_password
def verify_password(username, password):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if result and check_password_hash(result[0], password):
        return username
    return None


@app.route("/basic-protected")
@auth.login_required
def basic_protected():
    return "Basic Auth: Access Granted"


# ------------------------------
# USER REGISTRATION (NEW FEATURE)
# ------------------------------
@app.route("/register", methods=["POST"])
def register():
    """Allow new users to register into the system."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_pw, role),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "User registered successfully"}), 201


# ------------------------------
# LOGIN → RETURNS ACCESS & REFRESH TOKENS
# ------------------------------
@app.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"error": "Invalid JSON"}), 400

    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT password, role FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user[0], password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity={"username": username, "role": user[1]})
    refresh_token = create_refresh_token(identity={"username": username, "role": user[1]})

    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


# ------------------------------
# TOKEN REFRESH
# ------------------------------
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    new_access = create_access_token(identity=identity)
    return jsonify({"access_token": new_access})


# ------------------------------
# PROTECTED ROUTES
# ------------------------------
@app.route("/jwt-protected")
@jwt_required()
def jwt_protected():
    return "JWT Auth: Access Granted"


@app.route("/admin-only")
@jwt_required()
def admin_only():
    identity = get_jwt_identity()
    if identity.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    return "Admin Access: Granted"


# ------------------------------
# JWT ERROR HANDLING
# ------------------------------
@jwt.unauthorized_loader
def handle_unauthorized_error(err):
    return jsonify({"error": "Missing or invalid token"}), 401


@jwt.invalid_token_loader
def handle_invalid_token_error(err):
    return jsonify({"error": "Invalid token"}), 401


@jwt.expired_token_loader
def handle_expired_token_error(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired"}), 401


@jwt.revoked_token_loader
def handle_revoked_token_error(jwt_header, jwt_payload):
    return jsonify({"error": "Token has been revoked"}), 401


# ------------------------------
# START APPLICATION
# ------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
