import os
import time
import zipfile

from flask import Blueprint, request, jsonify, current_app, g, send_file
from werkzeug.utils import secure_filename

from security.access import server_owner_required
from security.pathsafe import safe_join, safe_filename_component, UnsafePathError
from security.audit import log_audit
from security.ratelimit import rate_limited

bp = Blueprint("files", __name__)

PROTECTED_FILES = {"console.log"}


def _base(folder):
    return safe_join(current_app.config["BASE_STORAGE"], folder)


def _resolve(folder, sub_path="", name=None):
    """Safely resolve folder/sub_path[/name] under BASE_STORAGE, raising
    UnsafePathError on any traversal attempt."""
    base = current_app.config["BASE_STORAGE"]
    parts = [folder]
    if sub_path:
        # sub_path may contain multiple segments joined by '/', validate each
        for seg in sub_path.split("/"):
            if seg == "":
                continue
            parts.append(seg)
    if name:
        parts.append(name)
    return safe_join(base, *parts)


def _err(msg, code=400):
    return jsonify({"status": "error", "msg": msg}), code


@bp.route("/files/list/<folder>")
@server_owner_required()
def flist(folder):
    sub_path = request.args.get("path", "")
    try:
        full_path = _resolve(folder, sub_path)
    except UnsafePathError:
        return jsonify([])
    if not os.path.exists(full_path):
        return jsonify([])
    items = []
    for f in sorted(os.listdir(full_path)):
        if f in PROTECTED_FILES:
            continue
        p = os.path.join(full_path, f)
        items.append({
            "name": f, "is_dir": os.path.isdir(p), "is_zip": f.lower().endswith(".zip"),
            "rel_path": os.path.join(sub_path, f),
        })
    return jsonify(items)


@bp.route("/files/read/<folder>")
@bp.route("/files/content/<folder>/<name>")
@server_owner_required()
def fcontent(folder, name=None):
    sub_path = request.args.get("path", "")
    name = name or request.args.get("name", "")
    if not safe_filename_component(name):
        return jsonify({"content": "Invalid file name."}), 400
    try:
        p = _resolve(folder, sub_path, name)
    except UnsafePathError:
        return jsonify({"content": "Access denied."}), 403
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": "Error reading file"})


@bp.route("/files/save/<folder>", methods=["POST"])
@server_owner_required()
def fsave(folder):
    d = request.get_json(silent=True) or {}
    name, sub_path, content = d.get("name", ""), d.get("path", ""), d.get("content", "")
    if not safe_filename_component(name):
        return _err("Invalid file name.")
    if len(content) > 5_000_000:
        return _err("File too large to save (5MB limit).")
    try:
        p = _resolve(folder, sub_path, name)
    except UnsafePathError:
        return _err("Access denied.", 403)
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"status": "saved"})
    except Exception:
        return jsonify({"status": "error"})


@bp.route("/files/delete-bulk/<folder>", methods=["POST"])
@server_owner_required()
def delete_bulk(folder):
    import shutil
    d = request.get_json(silent=True) or {}
    sub_path, names = d.get("path", ""), d.get("names", [])
    try:
        base = _resolve(folder, sub_path)
    except UnsafePathError:
        return _err("Access denied.", 403)
    if not os.path.isdir(base):
        return jsonify({"status": "ok"})
    if not names:
        names = [f for f in os.listdir(base) if f not in PROTECTED_FILES]
    deleted = []
    for name in names:
        if name in PROTECTED_FILES or not safe_filename_component(name):
            continue
        try:
            p = safe_join(base, name)
        except UnsafePathError:
            continue
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
            deleted.append(name)
        except Exception:
            pass
    log_audit("files_deleted", actor_type="user", target=folder, details=",".join(deleted)[:500])
    return jsonify({"status": "ok"})


@bp.route("/files/create-file/<folder>", methods=["POST"])
@server_owner_required()
def create_file_route(folder):
    d = request.get_json(silent=True) or {}
    raw_name = secure_filename(d.get("name") or "")
    if not safe_filename_component(raw_name):
        return _err("Invalid file name.")
    try:
        p = _resolve(folder, d.get("path", ""), raw_name)
    except UnsafePathError:
        return _err("Access denied.", 403)
    if os.path.exists(p):
        return _err("A file with that name already exists.")
    with open(p, "w") as f:
        f.write("")
    return jsonify({"status": "success"})


@bp.route("/files/create-folder/<folder>", methods=["POST"])
@server_owner_required()
def create_folder_route(folder):
    d = request.get_json(silent=True) or {}
    raw_name = secure_filename(d.get("name") or "")
    if not safe_filename_component(raw_name):
        return _err("Invalid folder name.")
    try:
        p = _resolve(folder, d.get("path", ""), raw_name)
    except UnsafePathError:
        return _err("Access denied.", 403)
    os.makedirs(p, exist_ok=True)
    return jsonify({"status": "success"})


@bp.route("/files/upload/<folder>", methods=["POST"])
@server_owner_required()
@rate_limited(limit=60, window_seconds=600, scope="file_upload")
def upload_file(folder):
    sub_path = request.form.get("path", "")
    file = request.files.get("file")
    if not file or not file.filename:
        return _err("No file provided.")
    safe_name = secure_filename(file.filename)
    if not safe_filename_component(safe_name):
        return _err("Invalid file name.")
    try:
        dest_dir = _resolve(folder, sub_path)
    except UnsafePathError:
        return _err("Access denied.", 403)
    os.makedirs(dest_dir, exist_ok=True)
    file.save(os.path.join(dest_dir, safe_name))
    log_audit("file_uploaded", actor_type="user", target=folder, details=safe_name)
    return jsonify({"status": "success"})


@bp.route("/files/rename/<folder>", methods=["POST"])
@server_owner_required()
def rename_file(folder):
    d = request.get_json(silent=True) or {}
    old, new = d.get("old", ""), secure_filename(d.get("new", ""))
    if not safe_filename_component(old) or not safe_filename_component(new):
        return _err("Invalid file name.")
    if old in PROTECTED_FILES:
        return _err("That file cannot be renamed.")
    try:
        base = _resolve(folder, d.get("path", ""))
        old_p = safe_join(base, old)
        new_p = safe_join(base, new)
    except UnsafePathError:
        return _err("Access denied.", 403)
    if not os.path.exists(old_p):
        return _err("File not found.", 404)
    if os.path.exists(new_p):
        return _err("A file with that name already exists.")
    os.rename(old_p, new_p)
    return jsonify({"status": "success"})


@bp.route("/files/download/<folder>/<name>")
@server_owner_required()
def download_file(folder, name):
    sub_path = request.args.get("path", "")
    if not safe_filename_component(name):
        return "Access Denied", 403
    try:
        p = _resolve(folder, sub_path, name)
    except UnsafePathError:
        return "Access Denied", 403
    if not os.path.isfile(p):
        return "Not Found", 404
    return send_file(p, as_attachment=True)


@bp.route("/files/zip-bulk/<folder>", methods=["POST"])
@server_owner_required()
def zip_bulk(folder):
    d = request.get_json(silent=True) or {}
    names, sub_path = d.get("names", []), d.get("path", "")
    try:
        base = _resolve(folder, sub_path)
    except UnsafePathError:
        return _err("Access denied.", 403)
    if not names:
        names = [f for f in os.listdir(base) if f not in PROTECTED_FILES]
    zip_name = f"archive_{int(time.time())}.zip"
    zip_path = os.path.join(base, zip_name)
    with zipfile.ZipFile(zip_path, "w") as z:
        for n in names:
            if not safe_filename_component(n) or n == zip_name:
                continue
            try:
                p = safe_join(base, n)
            except UnsafePathError:
                continue
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    for file in files:
                        full_p = os.path.join(root, file)
                        z.write(full_p, os.path.relpath(full_p, base))
            elif os.path.exists(p):
                z.write(p, n)
    return jsonify({"status": "success", "zip": zip_name})


@bp.route("/files/unzip/<folder>", methods=["POST"])
@server_owner_required()
def unzip_file(folder):
    d = request.get_json(silent=True) or {}
    zip_name = d.get("name")
    sub_path = d.get("path", "")

    if not zip_name or not safe_filename_component(zip_name):
        return _err("Invalid zip file name.")
    try:
        base = _resolve(folder, sub_path)
        zip_path = safe_join(base, zip_name)
    except UnsafePathError:
        return _err("Access denied.", 403)

    if not (os.path.exists(zip_path) and zipfile.is_zipfile(zip_path)):
        return _err("Invalid zip file.")

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            base_real = os.path.realpath(base)
            for member in z.infolist():
                # Zip-slip guard: every entry must resolve inside `base`
                member_path = os.path.normpath(os.path.join(base_real, member.filename))
                if member_path != base_real and not member_path.startswith(base_real + os.sep):
                    return _err(f"Refused to extract unsafe entry: {member.filename}", 400)
                if os.path.isabs(member.filename) or member.filename.startswith(("/", "\\")):
                    return _err(f"Refused to extract unsafe entry: {member.filename}", 400)
            z.extractall(base)
        log_audit("file_unzipped", actor_type="user", target=folder, details=zip_name)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})
