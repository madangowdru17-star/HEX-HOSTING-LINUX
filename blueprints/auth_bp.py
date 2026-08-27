import os
import re
import time
import uuid

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app
from werkzeug.utils import secure_filename

from extensions import get_db
from security.passwords import hash_password, verify_password, password_policy_errors
from security.ratelimit import rate_limited, client_ip, is_locked, lockout_expiry
from security.audit import log_audit
from security.detect import note_failed_login, note_lockout

bp = Blueprint("auth", __name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _save_pfp(pfp):
    if not pfp or not pfp.filename:
        return "default.png"
    ext = pfp.filename.rsplit(".", 1)[-1].lower() if "." in pfp.filename else ""
    if ext not in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return None  # signal: invalid type
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    pfp.save(os.path.join(current_app.config["UPLOAD_FOLDER"], secure_filename(safe_name)))
    return safe_name


@bp.route("/signup", methods=["GET", "POST"])
@rate_limited(limit=10, window_seconds=600, scope="signup")
def signup():
    if request.method == "POST":
        fname = (request.form.get("fname") or "").strip()[:80]
        lname = (request.form.get("lname") or "").strip()[:80]
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        pwd = request.form.get("password") or ""
        cpwd = request.form.get("confirm_password") or ""
        pfp = request.files.get("pfp")

        if not _EMAIL_RE.match(email):
            return jsonify({"status": "error", "msg": "Please enter a valid email address."}), 400
        if not _USERNAME_RE.match(username):
            return jsonify({"status": "error", "msg": "Username must be 3-32 characters (letters, numbers, _ . -)."}), 400
        if pwd != cpwd:
            return jsonify({"status": "error", "msg": "Passwords do not match!"}), 400
        policy_errors = password_policy_errors(pwd)
        if policy_errors:
            return jsonify({"status": "error", "msg": " ".join(policy_errors)}), 400

        db = get_db()
        existing_user = db.execute("SELECT id FROM users WHERE email=? OR username=?", (email, username)).fetchone()
        if existing_user:
            db.close()
            return jsonify({"status": "error", "msg": "Email or Username already taken!"}), 400

        pfp_name = _save_pfp(pfp)
        if pfp_name is None:
            db.close()
            return jsonify({"status": "error", "msg": "Profile picture must be a PNG, JPG, GIF, or WEBP image."}), 400

        db.execute(
            '''INSERT INTO users (fname, lname, username, email, password, pfp, server_limit, role, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (fname, lname, username, email, hash_password(pwd), pfp_name, 1, "free", "active"),
        )
        db.commit()
        new_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        db.close()
        log_audit("user_signup", actor_type="user", actor_id=new_id, actor_name=username, target=username)
        return jsonify({"status": "success", "url": url_for("auth.login")})

    return render_template("web/signup.html")


@bp.route("/login", methods=["GET", "POST"])
@rate_limited(limit=20, window_seconds=300, scope="login_ip")
def login():
    if request.method == "POST":
        identifier = (request.form.get("email") or "").strip()
        pwd = request.form.get("password") or ""
        ip = client_ip()

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE (email=? OR username=?)", (identifier.lower(), identifier)
        ).fetchone()

        if not user:
            db.close()
            note_failed_login(identifier, ip)
            return jsonify({"status": "error", "msg": "Invalid credentials!"}), 401

        if is_locked(user["locked_until"]):
            db.close()
            return jsonify({"status": "error", "msg": "Too many failed attempts. Try again later."}), 429

        if not verify_password(pwd, user["password"]):
            attempts = (user["failed_attempts"] or 0) + 1
            locked_until = None
            if attempts >= current_app.config["LOGIN_MAX_ATTEMPTS"]:
                locked_until = lockout_expiry(current_app.config["LOGIN_LOCKOUT_SECONDS"])
                note_lockout(identifier, ip)
                attempts = 0
            db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                       (attempts, locked_until, user["id"]))
            db.commit()
            db.close()
            note_failed_login(identifier, ip)
            return jsonify({"status": "error", "msg": "Invalid credentials!"}), 401

        if user["status"] == "banned":
            db.close()
            log_audit("login_blocked_banned", actor_type="user", actor_id=user["id"], actor_name=user["username"])
            return jsonify({"status": "banned", "msg": "Your account is suspended!"}), 403

        # Success: reset lockout counters, rotate session, record login metadata
        db.execute(
            "UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_at=?, last_login_ip=? WHERE id=?",
            (str(time.time()), ip, user["id"]),
        )
        db.commit()
        db.close()

        session.clear()  # session fixation protection
        session["user_id"] = user["id"]
        session.permanent = True
        log_audit("user_login", actor_type="user", actor_id=user["id"], actor_name=user["username"])
        return jsonify({"status": "success", "url": url_for("dashboard.dashboard")}), 200

    return render_template("web/login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    uid = session.get("user_id")
    session.clear()
    if uid:
        log_audit("user_logout", actor_type="user", actor_id=uid)
    return redirect(url_for("public.home"))
