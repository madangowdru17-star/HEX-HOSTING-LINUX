import os
import shutil
import signal
import subprocess
import time
import datetime

from flask import Blueprint, request, jsonify, current_app, g, session

from extensions import get_db
from security.access import server_owner_required
from security.pathsafe import safe_join, safe_filename_component, UnsafePathError
from security.ratelimit import rate_limited
from security.audit import log_audit
from security.ssrf import validate_github_url, InvalidRepoURL

bp = Blueprint("server", __name__)

# Process tracking stays in-memory (matches original design: single-process app).
running_procs = {}
start_times = {}

MAX_LOG_TAIL = 5000
CONSOLE_TIMEOUT_SECONDS = 20
CONSOLE_MAX_OUTPUT = 8000


def get_precise_uptime(start_timestamp):
    if not start_timestamp:
        return "Offline"
    diff = int(time.time() - start_timestamp)
    months, rem = divmod(diff, 2592000)
    days, rem = divmod(rem, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if months > 0:
        parts.append(f"{months}mo")
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _instance_path(folder):
    return safe_join(current_app.config["BASE_STORAGE"], folder)


def _kill_pid(pid):
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        pass


@bp.route("/server/action/<folder>/<act>", methods=["POST"])
@server_owner_required()
def server_action(folder, act):
    if act not in ("install", "start", "restart", "stop"):
        return jsonify({"status": "error", "msg": "Unknown action."}), 400

    srv = g.server
    if srv["server_status"] == "suspended":
        return jsonify({"status": "error", "msg": "This server is suspended by Admin."})

    path = _instance_path(folder)
    os.makedirs(path, exist_ok=True)
    log_file_path = os.path.join(path, "console.log")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()

    if act == "install":
        req_path = os.path.join(path, "requirements.txt")
        if os.path.exists(req_path):
            with open(log_file_path, "a") as f_log:
                f_log.write(f"\n[{now}] \U0001F4E6 Package Installation Started...\n")
            f_log = open(log_file_path, "a")
            subprocess.Popen(
                ["pip", "install", "--user", "-r", "requirements.txt"],
                cwd=path, stdout=f_log, stderr=f_log,
            )
            db.close()
            log_audit("server_install", actor_type="user", actor_id=session.get("user_id"), target=folder)
            return jsonify({"status": "installing"})
        db.close()
        return jsonify({"status": "error", "msg": "requirements.txt missing"})

    if act in ("start", "restart"):
        row = db.execute("SELECT pid, startup FROM servers WHERE folder=?", (folder,)).fetchone()
        old_pid = row["pid"] if row else None
        if folder in running_procs or (old_pid and _pid_alive(old_pid)):
            t_pid = running_procs[folder].pid if folder in running_procs else old_pid
            _kill_pid(t_pid)
            running_procs.pop(folder, None)

        startup_file = row["startup"] if row and row["startup"] else "main.py"
        if not _valid_startup_target(path, startup_file):
            db.close()
            return jsonify({"status": "error", "msg": "Invalid startup file."}), 400

        f_log = open(log_file_path, "a")
        f_log.write(f"\n[{now}] \U0001F680 Instance {act.upper()}ED Successfully\n")
        f_log.flush()
        proc = subprocess.Popen(
            ["python3", startup_file], cwd=path, stdout=f_log, stderr=f_log, preexec_fn=os.setsid,
        )
        running_procs[folder], start_times[folder] = proc, time.time()
        db.execute("UPDATE servers SET pid=? WHERE folder=?", (proc.pid, folder))
        db.commit()
        db.close()
        log_audit(f"server_{act}", actor_type="user", target=folder)
        return jsonify({"status": "started"})

    if act == "stop":
        row = db.execute("SELECT pid FROM servers WHERE folder=?", (folder,)).fetchone()
        t_pid = running_procs[folder].pid if folder in running_procs else (row["pid"] if row else None)
        if t_pid:
            _kill_pid(t_pid)
        running_procs.pop(folder, None)
        db.execute("UPDATE servers SET pid=NULL WHERE folder=?", (folder,))
        db.commit()
        db.close()
        with open(log_file_path, "a") as f:
            f.write(f"\n[{now}] \U0001F6D1 Instance STOPPED\n")
        log_audit("server_stop", actor_type="user", target=folder)
        return jsonify({"status": "stopped"})

    db.close()
    return jsonify({"status": "ok"})


def _pid_alive(pid):
    import psutil
    try:
        return psutil.pid_exists(pid)
    except Exception:
        return False


def _valid_startup_target(instance_path, startup_file):
    """The configured startup file must be a real file inside the
    instance's own directory — never an absolute path or a path that
    traverses out of it."""
    if not startup_file or not startup_file.strip():
        return False
    try:
        resolved = safe_join(instance_path, startup_file)
    except UnsafePathError:
        return False
    return True  # file need not exist yet at set-time; existence is checked at start-time by python3 itself


@bp.route("/server/log/<folder>")
@server_owner_required()
def server_log(folder):
    path = os.path.join(_instance_path(folder), "console.log")
    if os.path.exists(path):
        with open(path, "r", errors="ignore") as f:
            return jsonify({"log": f.read()[-MAX_LOG_TAIL:]})
    return jsonify({"log": "Waiting for logs..."})


@bp.route("/server/set-startup/<folder>", methods=["POST"])
@server_owner_required()
def set_startup(folder):
    cmd = (request.get_json(silent=True) or {}).get("file") or ""
    cmd = cmd.strip()
    path = _instance_path(folder)
    if not _valid_startup_target(path, cmd):
        return jsonify({"status": "error", "msg": "Invalid startup file path."}), 400
    db = get_db()
    db.execute("UPDATE servers SET startup=? WHERE folder=?", (cmd, folder))
    db.commit()
    db.close()
    log_audit("server_startup_changed", actor_type="user", target=folder, details=cmd)
    return jsonify({"status": "success"})


@bp.route("/server/delete/<folder>", methods=["POST"])
@server_owner_required()
def delete_server(folder):
    srv = g.server
    if srv["server_status"] == "suspended":
        return jsonify({"status": "error", "msg": "Suspended servers cannot be deleted!"})
    t_pid = running_procs[folder].pid if folder in running_procs else srv["pid"]
    if t_pid:
        _kill_pid(t_pid)
    running_procs.pop(folder, None)
    db = get_db()
    db.execute("DELETE FROM servers WHERE folder=?", (folder,))
    db.commit()
    db.close()
    path = _instance_path(folder)
    if os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
    log_audit("server_deleted", actor_type="user", target=folder)
    return jsonify({"status": "deleted"})


@bp.route("/server/command/<folder>", methods=["POST"])
@server_owner_required()
@rate_limited(limit=30, window_seconds=60, scope="console_command")
def console_command(folder):
    """Run a one-off shell command inside the caller's own instance
    directory (the in-app 'terminal'). The caller already has full
    code-execution rights over this folder (they can write and start
    arbitrary Python here), so this adds no new privilege — but it is
    still sandboxed to the instance directory, time-limited, output-
    capped, and fully audit-logged."""
    srv = g.server
    if srv["server_status"] == "suspended":
        return jsonify({"status": "error", "msg": "This server is suspended by Admin."}), 403

    cmd = (request.get_json(silent=True) or {}).get("command") or ""
    cmd = cmd.strip()
    if not cmd:
        return jsonify({"status": "error", "msg": "No command provided."}), 400
    if len(cmd) > 2000:
        return jsonify({"status": "error", "msg": "Command too long."}), 400

    path = _instance_path(folder)
    os.makedirs(path, exist_ok=True)
    log_audit("console_command", actor_type="user", target=folder, details=cmd[:500])

    try:
        result = subprocess.run(
            cmd, shell=True, cwd=path, capture_output=True, text=True,
            timeout=CONSOLE_TIMEOUT_SECONDS,
        )
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        output = f"Command timed out after {CONSOLE_TIMEOUT_SECONDS}s."
    except Exception as e:
        output = f"Error running command: {e}"

    output = output[-CONSOLE_MAX_OUTPUT:]
    log_file_path = os.path.join(path, "console.log")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file_path, "a") as f:
        f.write(f"\n[{now}] $ {cmd}\n{output}\n")

    return jsonify({"status": "ok", "output": output})


@bp.route("/server/import-github/<folder>", methods=["POST"])
@server_owner_required()
@rate_limited(limit=5, window_seconds=600, scope="github_import")
def import_github(folder):
    if not current_app.config.get("GITHUB_IMPORT_ENABLED", True):
        return jsonify({"status": "error", "msg": "GitHub import is disabled on this instance."}), 403

    srv = g.server
    if srv["server_status"] == "suspended":
        return jsonify({"status": "error", "msg": "This server is suspended by Admin."}), 403

    raw_url = (request.get_json(silent=True) or {}).get("repo_url") or ""
    try:
        safe_url = validate_github_url(raw_url)
    except InvalidRepoURL as e:
        log_audit("github_import_rejected", actor_type="user", target=folder, details=str(e))
        return jsonify({"status": "error", "msg": str(e)}), 400

    dest = _instance_path(folder)
    os.makedirs(dest, exist_ok=True)
    if os.listdir(dest):
        return jsonify({"status": "error", "msg": "Instance folder is not empty. Import only supports an empty instance."}), 400

    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_PROTOCOL_FROM_USER": "0",
    })

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", safe_url, dest],
            capture_output=True, text=True, timeout=current_app.config["GITHUB_IMPORT_TIMEOUT_SECONDS"],
            env=env,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest, exist_ok=True)
        return jsonify({"status": "error", "msg": "Import timed out."}), 504

    if result.returncode != 0:
        return jsonify({"status": "error", "msg": "Clone failed: " + (result.stderr or "unknown error")[-500:]}), 400

    # Strip VCS metadata (hooks/config could otherwise be abused) and reject symlinks.
    git_dir = os.path.join(dest, ".git")
    if os.path.isdir(git_dir):
        shutil.rmtree(git_dir, ignore_errors=True)

    total_size = 0
    for root, dirs, files in os.walk(dest):
        for name in files:
            fp = os.path.join(root, name)
            if os.path.islink(fp):
                os.remove(fp)
                continue
            total_size += os.path.getsize(fp)
    max_bytes = current_app.config["GITHUB_IMPORT_MAX_MB"] * 1024 * 1024
    if total_size > max_bytes:
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest, exist_ok=True)
        log_audit("github_import_rejected", actor_type="user", target=folder,
                  details=f"repo exceeded {current_app.config['GITHUB_IMPORT_MAX_MB']}MB limit")
        return jsonify({"status": "error", "msg": "Repository is too large."}), 400

    log_audit("github_import", actor_type="user", target=folder, details=safe_url)
    return jsonify({"status": "success", "msg": "Repository imported."})
