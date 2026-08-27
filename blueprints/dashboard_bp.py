import time

import psutil
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename

from extensions import get_db
from security.access import login_required
from security.passwords import hash_password, password_policy_errors
from security.audit import log_audit
from security.ratelimit import rate_limited

bp = Blueprint("dashboard", __name__)


@bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    db.close()
    if not user or user["status"] != "active":
        session.clear()
        return redirect(url_for("auth.login"))
    return render_template("web/dashboard.html", user=user)


@bp.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    uid = session["user_id"]
    fname = (request.form.get("fname") or "").strip()[:80]
    lname = (request.form.get("lname") or "").strip()[:80]
    pwd = request.form.get("password") or ""
    db = get_db()
    if pwd:
        errors = password_policy_errors(pwd)
        if errors:
            db.close()
            return jsonify({"status": "error", "msg": " ".join(errors)}), 400
        db.execute("UPDATE users SET fname=?, lname=?, password=? WHERE id=?",
                   (fname, lname, hash_password(pwd), uid))
        log_audit("password_changed", actor_type="user", actor_id=uid)
    else:
        db.execute("UPDATE users SET fname=?, lname=? WHERE id=?", (fname, lname, uid))
    db.commit()
    db.close()
    return jsonify({"status": "success"})


@bp.route("/ticket/create", methods=["POST"])
@login_required
@rate_limited(limit=10, window_seconds=600, scope="ticket_create")
def create_ticket():
    d = request.get_json(silent=True) or {}
    subject = (d.get("subject") or "")[:200]
    message = (d.get("message") or "")[:5000]
    if not subject.strip() or not message.strip():
        return jsonify({"status": "error", "msg": "Subject and message are required."}), 400
    db = get_db()
    db.execute("INSERT INTO tickets (user_id, subject, message) VALUES (?,?,?)",
               (session["user_id"], subject, message))
    db.commit()
    db.close()
    return jsonify({"status": "success"})


@bp.route("/servers")
def list_servers():
    if "user_id" not in session:
        return jsonify({"servers": []})
    db = get_db()
    rows = db.execute("SELECT * FROM servers WHERE user_id=?", (session["user_id"],)).fetchall()
    db.close()
    from blueprints.server_bp import running_procs, start_times, get_precise_uptime
    srvs = []
    for r in rows:
        f, saved_pid = r["folder"], r["pid"]
        online = False
        if saved_pid and psutil.pid_exists(saved_pid):
            try:
                p = psutil.Process(saved_pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    online = True
            except Exception:
                pass
        elif f in running_procs and running_procs[f].poll() is None:
            online = True
        uptime = get_precise_uptime(start_times.get(f)) if online and f in start_times else ("Online" if online else "Offline")
        cpu, ram = "0%", "0MB"
        if online:
            try:
                p_pid = running_procs[f].pid if f in running_procs else saved_pid
                process = psutil.Process(p_pid)
                cpu, ram = f"{process.cpu_percent(interval=None)}%", f"{process.memory_info().rss / (1024 * 1024):.1f}MB"
            except Exception:
                pass
        srvs.append({
            "name": r["name"], "folder": f, "online": online, "startup": r["startup"],
            "uptime": uptime, "cpu": cpu, "ram": ram, "status": r["server_status"],
        })
    return jsonify({"servers": srvs})


@bp.route("/add", methods=["POST"])
@login_required
@rate_limited(limit=20, window_seconds=600, scope="add_server")
def add_srv():
    import os
    from flask import current_app
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    count = db.execute("SELECT COUNT(*) as count FROM servers WHERE user_id=?", (session["user_id"],)).fetchone()["count"]
    if not user or user["status"] != "active":
        db.close()
        return jsonify({"status": "error", "msg": "Account not active."}), 403
    if count >= user["server_limit"]:
        db.close()
        return jsonify({"status": "error", "msg": f"Limit Reached! Max: {user['server_limit']}"})
    name = (request.get_json(silent=True) or {}).get("name") or ""
    name = name.strip()[:64]
    if not name:
        db.close()
        return jsonify({"status": "error", "msg": "Server name is required."})
    folder = secure_filename(name).lower() + "_" + str(int(time.time()))
    db.execute("INSERT INTO servers (user_id, name, folder, status, startup) VALUES (?,?,?,?,?)",
               (session["user_id"], name, folder, "Offline", "main.py"))
    db.commit()
    db.close()
    os.makedirs(os.path.join(current_app.config["BASE_STORAGE"], folder), exist_ok=True)
    log_audit("server_created", actor_type="user", actor_id=session["user_id"], target=folder)
    return jsonify({"status": "success"})
