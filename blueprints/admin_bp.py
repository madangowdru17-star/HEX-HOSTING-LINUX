import os
import shutil
import signal

import psutil
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app

from extensions import get_db
from security.access import admin_required
from security.passwords import hash_password, verify_password, password_policy_errors
from security.ratelimit import rate_limited, client_ip, is_locked, lockout_expiry
from security.audit import log_audit
from security.detect import note_failed_login, note_lockout, note_admin_access
from security.pathsafe import safe_filename_component
from werkzeug.utils import secure_filename

bp = Blueprint("admin", __name__)


@bp.route("/admin-login", methods=["GET", "POST"])
@rate_limited(limit=15, window_seconds=300, scope="admin_login_ip")
def admin_login():
    if request.method == "POST":
        user, pwd = request.form.get("username", ""), request.form.get("password", "")
        ip = client_ip()
        db = get_db()
        admin = db.execute("SELECT * FROM admin_settings WHERE username=?", (user,)).fetchone()

        if not admin or is_locked(admin["locked_until"]):
            db.close()
            note_failed_login(user, ip, scope="admin")
            note_admin_access(ip, request.path, success=False)
            return jsonify({"status": "error", "msg": "Invalid credentials."}), 401

        if not verify_password(pwd, admin["password"]):
            attempts = (admin["failed_attempts"] or 0) + 1
            locked_until = None
            if attempts >= current_app.config["LOGIN_MAX_ATTEMPTS"]:
                locked_until = lockout_expiry(current_app.config["LOGIN_LOCKOUT_SECONDS"])
                note_lockout(user, ip, scope="admin")
                attempts = 0
            db.execute("UPDATE admin_settings SET failed_attempts=?, locked_until=? WHERE id=1",
                       (attempts, locked_until))
            db.commit()
            db.close()
            note_failed_login(user, ip, scope="admin")
            note_admin_access(ip, request.path, success=False)
            return jsonify({"status": "error", "msg": "Invalid credentials."}), 401

        db.execute("UPDATE admin_settings SET failed_attempts=0, locked_until=NULL WHERE id=1")
        db.commit()
        db.close()
        session.clear()
        session["admin_logged"] = True
        session.permanent = True
        log_audit("admin_login", actor_type="admin", actor_name=user)
        note_admin_access(ip, request.path, success=True)
        return jsonify({"status": "success", "url": url_for("admin.admin_panel")})
    return render_template("web/admin_login.html")


@bp.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    log_audit("admin_logout", actor_type="admin")
    session.pop("admin_logged", None)
    return redirect(url_for("admin.admin_login"))


@bp.route("/admin/panel")
@admin_required
def admin_panel():
    return render_template("web/admin_panel.html")


@bp.route("/admin/stats")
@admin_required
def admin_stats():
    from blueprints.server_bp import running_procs
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    user_list = []
    total_cpu = psutil.cpu_percent()
    total_ram = psutil.virtual_memory().percent
    for u in users:
        srvs = db.execute("SELECT * FROM servers WHERE user_id=?", (u["id"],)).fetchall()
        active_srvs = 0
        for s in srvs:
            is_on = False
            if s["pid"] and psutil.pid_exists(s["pid"]):
                try:
                    proc = psutil.Process(s["pid"])
                    if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                        is_on = True
                except Exception:
                    pass
            elif s["folder"] in running_procs and running_procs[s["folder"]].poll() is None:
                is_on = True
            if is_on:
                active_srvs += 1
        user_list.append({
            "id": u["id"], "fname": u["fname"], "email": u["email"],
            "srv_count": len(srvs), "active_srvs": active_srvs,
            "status": u["status"], "role": u["role"], "server_limit": u["server_limit"],
        })
    db.close()
    return jsonify({"users": user_list, "sys_cpu": f"{total_cpu}%", "sys_ram": f"{total_ram}%"})


@bp.route("/admin/user/update", methods=["POST"])
@admin_required
def update_user():
    d = request.get_json(silent=True) or {}
    role = d.get("role")
    status = d.get("status")
    try:
        limit = int(d.get("limit", 1))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "msg": "Invalid server limit."}), 400
    if role not in ("free", "premium", "vip"):
        return jsonify({"status": "error", "msg": "Invalid role."}), 400
    if status not in ("active", "banned", "suspended"):
        return jsonify({"status": "error", "msg": "Invalid status."}), 400
    limit = max(0, min(limit, 1000))
    db = get_db()
    db.execute("UPDATE users SET role=?, status=?, server_limit=? WHERE id=?",
               (role, status, limit, d.get("user_id")))
    db.commit()
    db.close()
    log_audit("admin_user_update", actor_type="admin", target=str(d.get("user_id")),
              details=f"role={role} status={status} limit={limit}")
    return jsonify({"status": "success"})


@bp.route("/admin/set-popup", methods=["POST"])
@admin_required
def set_popup():
    title, msg, show = request.form.get("title"), request.form.get("msg"), request.form.get("show")
    img = request.files.get("image")
    db = get_db()
    old_data = db.execute("SELECT popup_img FROM admin_settings WHERE id=1").fetchone()
    img_name = old_data["popup_img"] if old_data else None
    if img and img.filename:
        ext = img.filename.rsplit(".", 1)[-1].lower() if "." in img.filename else ""
        if ext not in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
            db.close()
            return jsonify({"status": "error", "msg": "Image must be PNG, JPG, GIF, or WEBP."}), 400
        import uuid
        img_name = secure_filename(f"{uuid.uuid4().hex}.{ext}")
        img.save(os.path.join(current_app.config["UPLOAD_FOLDER"], img_name))
    db.execute("UPDATE admin_settings SET popup_title=?, popup_msg=?, popup_img=?, show_popup=? WHERE id=1",
               (title, msg, img_name, 1 if show == "true" else 0))
    db.commit()
    db.close()
    log_audit("admin_popup_updated", actor_type="admin")
    return jsonify({"status": "success"})


@bp.route("/admin/send-warning", methods=["POST"])
@admin_required
def send_warning():
    d = request.get_json(silent=True) or {}
    db = get_db()
    db.execute("UPDATE users SET notifications=? WHERE id=?", (d.get("message", "")[:2000], d.get("user_id")))
    db.commit()
    db.close()
    log_audit("admin_warning_sent", actor_type="admin", target=str(d.get("user_id")))
    return jsonify({"status": "success"})


@bp.route("/admin/login-as/<int:uid>")
@admin_required
def login_as(uid):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
    db.close()
    if not user:
        return redirect(url_for("admin.admin_panel"))
    session["user_id"] = uid
    log_audit("admin_login_as_user", actor_type="admin", target=str(uid),
              details="Admin impersonated this user for support purposes")
    return redirect(url_for("dashboard.dashboard"))


@bp.route("/admin/manage-user/<int:uid>")
@admin_required
def admin_manage_user_servers(uid):
    from blueprints.server_bp import running_procs
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    rows = db.execute("SELECT * FROM servers WHERE user_id=?", (uid,)).fetchall()
    db.close()
    servers = []
    for r in rows:
        f = r["folder"]
        online = (f in running_procs and running_procs[f].poll() is None) or (r["pid"] and psutil.pid_exists(r["pid"]))
        servers.append({"id": r["id"], "name": r["name"], "folder": f, "online": online, "status": r["server_status"]})
    return render_template("web/admin_manage_user.html", user=user, servers=servers)


@bp.route("/admin/suspend-server/<int:sid>", methods=["POST"])
@admin_required
def admin_suspend_server(sid):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("active", "suspended"):
        return jsonify({"status": "error", "msg": "Invalid status."}), 400
    db = get_db()
    db.execute("UPDATE servers SET server_status=? WHERE id=?", (status, sid))
    db.commit()
    db.close()
    log_audit("admin_server_suspend", actor_type="admin", target=str(sid), details=status)
    return jsonify({"status": "success"})


@bp.route("/admin/delete-server/<int:sid>", methods=["POST"])
@admin_required
def admin_delete_server(sid):
    from blueprints.server_bp import running_procs
    db = get_db()
    srv = db.execute("SELECT folder FROM servers WHERE id=?", (sid,)).fetchone()
    if srv:
        folder = srv["folder"]
        if folder in running_procs:
            try:
                os.killpg(os.getpgid(running_procs[folder].pid), signal.SIGKILL)
            except Exception:
                pass
            del running_procs[folder]
        db.execute("DELETE FROM servers WHERE id=?", (sid,))
        db.commit()
        path = os.path.join(current_app.config["BASE_STORAGE"], folder)
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
        db.close()
        log_audit("admin_server_delete", actor_type="admin", target=folder)
        return jsonify({"status": "deleted"})
    db.close()
    return jsonify({"status": "error", "msg": "Server not found"})


@bp.route("/admin/create-user", methods=["POST"])
@admin_required
def admin_create_user():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    name = (d.get("name") or "").strip()[:80]
    pwd = d.get("pass") or ""
    if not email or not name:
        return jsonify({"status": "error", "msg": "Name and email are required."}), 400
    errors = password_policy_errors(pwd)
    if errors:
        return jsonify({"status": "error", "msg": " ".join(errors)}), 400
    try:
        limit = int(d.get("limit", 1))
    except (TypeError, ValueError):
        limit = 1
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        db.close()
        return jsonify({"status": "error", "msg": "A user with that email already exists."}), 400
    db.execute("INSERT INTO users (fname, email, username, password, server_limit) VALUES (?,?,?,?,?)",
               (name, email, email.split("@")[0], hash_password(pwd), max(0, min(limit, 1000))))
    db.commit()
    db.close()
    log_audit("admin_user_created", actor_type="admin", target=email)
    return jsonify({"status": "success"})


@bp.route("/admin/delete-user/<int:uid>", methods=["POST"])
@admin_required
def delete_user(uid):
    db = get_db()
    srvs = db.execute("SELECT folder FROM servers WHERE user_id=?", (uid,)).fetchall()
    for s in srvs:
        path = os.path.join(current_app.config["BASE_STORAGE"], s["folder"])
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
    db.execute("DELETE FROM servers WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    db.close()
    log_audit("admin_user_deleted", actor_type="admin", target=str(uid))
    return jsonify({"status": "deleted"})


@bp.route("/admin/files/<folder>")
@admin_required
def admin_browse_files(folder):
    if not safe_filename_component(folder):
        return redirect(url_for("admin.admin_panel"))
    return render_template("web/dashboard.html", user={"fname": "Admin"}, is_admin_view=True, admin_folder=folder)


@bp.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    d = request.get_json(silent=True) or {}
    new_pwd = d.get("password") or ""
    errors = password_policy_errors(new_pwd)
    if errors:
        return jsonify({"status": "error", "msg": " ".join(errors)}), 400
    db = get_db()
    db.execute("UPDATE admin_settings SET password=? WHERE id=1", (hash_password(new_pwd),))
    db.commit()
    db.close()
    log_audit("admin_password_changed", actor_type="admin")
    return jsonify({"status": "success"})


# --- New: security & monitoring views (built with the same visual theme
#     as the existing admin panel; no existing page is modified) ---

@bp.route("/admin/security")
@admin_required
def admin_security():
    return render_template("web/admin_security.html")


@bp.route("/admin/security/data")
@admin_required
def admin_security_data():
    db = get_db()
    alerts = db.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 200").fetchall()
    audits = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
    top_ips = db.execute(
        '''SELECT ip, COUNT(*) as hits, SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) as errors
           FROM request_logs GROUP BY ip ORDER BY hits DESC LIMIT 25'''
    ).fetchall()
    recent_requests = db.execute("SELECT * FROM request_logs ORDER BY id DESC LIMIT 200").fetchall()
    db.close()
    return jsonify({
        "alerts": [dict(a) for a in alerts],
        "audit_logs": [dict(a) for a in audits],
        "top_ips": [dict(i) for i in top_ips],
        "recent_requests": [dict(r) for r in recent_requests],
    })


@bp.route("/admin/security/alerts/<int:aid>/resolve", methods=["POST"])
@admin_required
def resolve_alert(aid):
    db = get_db()
    db.execute("UPDATE security_alerts SET resolved=1 WHERE id=?", (aid,))
    db.commit()
    db.close()
    log_audit("admin_alert_resolved", actor_type="admin", target=str(aid))
    return jsonify({"status": "success"})
