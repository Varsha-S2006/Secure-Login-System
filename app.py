"""
Secure Login System
--------------------
Flask web app demonstrating:
- User registration & login with bcrypt password hashing
- Input validation & parameterized SQL queries (SQL injection protection)
- Session management with logout
- Optional TOTP-based Two-Factor Authentication (2FA)
"""

import os
import re
import sqlite3
import secrets
from datetime import timedelta

import bcrypt
import pyotp
import qrcode
import io
import base64

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g
)

# ──────────────────────────────────────────────────────────────────────────
# App Configuration
# ──────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = os.path.join(os.path.dirname(__file__), "users.db")

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


# ──────────────────────────────────────────────────────────────────────────
# Database Helpers
# ──────────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
    """)
    db.commit()
    db.close()


# ──────────────────────────────────────────────────────────────────────────
# Input Validation
# ──────────────────────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username, email, password, confirm):
    errors = []

    if not USERNAME_RE.match(username or ""):
        errors.append("Username must be 3-20 characters (letters, numbers, underscore only).")

    if not EMAIL_RE.match(email or ""):
        errors.append("Please enter a valid email address.")

    if len(password or "") < 8:
        errors.append("Password must be at least 8 characters long.")
    elif not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    elif not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    elif not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")
    elif not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least one special character.")

    if password != confirm:
        errors.append("Passwords do not match.")

    return errors


# ──────────────────────────────────────────────────────────────────────────
# Password Hashing (bcrypt)
# ──────────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ──────────────────────────────────────────────────────────────────────────
# Auth Helper / Decorator
# ──────────────────────────────────────────────────────────────────────────
def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ──────────────────────────────────────────────────────────────────────────
# Routes: Registration
# ──────────────────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = validate_registration(username, email, password, confirm)

        db = get_db()
        if not errors:
            # Parameterized query - prevents SQL injection
            existing = db.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
            if existing:
                errors.append("Username or email is already registered.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email)

        password_hash = hash_password(password)
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", username="", email="")


# ──────────────────────────────────────────────────────────────────────────
# Routes: Login
# ──────────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Check account lockout
        if user and user["locked_until"]:
            from datetime import datetime
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                flash("Account temporarily locked due to too many failed attempts. Try again later.", "error")
                return render_template("login.html")

        # Verify credentials (constant response regardless of which check fails)
        if user and verify_password(password, user["password_hash"]):
            # Reset failed attempts on success
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()

            if user["totp_enabled"]:
                # Require 2FA step before fully logging in
                session["pending_2fa_user_id"] = user["id"]
                return redirect(url_for("verify_2fa"))

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        # Invalid credentials - increment failed attempts
        if user:
            from datetime import datetime, timedelta as td
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_LOGIN_ATTEMPTS:
                locked_until = (datetime.utcnow() + td(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat()
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()

        flash("Invalid username or password.", "error")

    return render_template("login.html")


# ──────────────────────────────────────────────────────────────────────────
# Routes: Two-Factor Authentication
# ──────────────────────────────────────────────────────────────────────────
@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("pending_totp_secret")
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            db.commit()
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid verification code. Please try again.", "error")

    # Generate a new secret + QR code for setup
    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureLoginApp")

    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?",
        (session["user_id"],),
    )
    db.commit()
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("dashboard"))


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()

        if user and user["totp_secret"] and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid authentication code.", "error")

    return render_template("verify_2fa.html")


# ──────────────────────────────────────────────────────────────────────────
# Routes: Dashboard / Logout
# ──────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ──────────────────────────────────────────────────────────────────────────
# Security Headers
# ──────────────────────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


# ──────────────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
