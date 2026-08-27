"""
Authentication / authorization / ownership decorators.

Centralizing these closes the IDOR gaps in the original app, where many
`/files/*` and `/server/*` routes performed no session check at all, and
none of them verified that the requesting user actually owned the
`folder` they were operating on.
"""
import functools

from flask import session, jsonify, redirect, url_for, g

from extensions import get_db
from security.audit import log_audit
from security.detect import note_admin_access


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            if _wants_json():
                return jsonify({"status": "error", "msg": "Authentication required."}), 401
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        from flask import request
        if not session.get("admin_logged"):
            note_admin_access(request.remote_addr, request.path, success=False)
            if _wants_json():
                return jsonify({"status": "error", "msg": "Admin authentication required."}), 401
            return redirect(url_for("admin.admin_login"))
        return view(*args, **kwargs)
    return wrapper


def server_owner_required(folder_param="folder"):
    """Require that the logged-in user owns the server identified by the
    `folder` route parameter, OR that an admin session is active. Loads
    the server row into flask.g.server for the view to use."""

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            folder = kwargs.get(folder_param)
            db = get_db()
            srv = db.execute("SELECT * FROM servers WHERE folder=?", (folder,)).fetchone()
            db.close()
            if not srv:
                return jsonify({"status": "error", "msg": "Server not found."}), 404
            is_admin = bool(session.get("admin_logged"))
            is_owner = session.get("user_id") == srv["user_id"]
            if not (is_admin or is_owner):
                log_audit("idor_attempt", actor_type="user" if session.get("user_id") else "anonymous",
                          actor_id=session.get("user_id"), target=folder,
                          details="Attempted to access a server folder not owned by the caller")
                return jsonify({"status": "error", "msg": "Not authorized for this server."}), 403
            if not is_admin and "user_id" not in session:
                return jsonify({"status": "error", "msg": "Authentication required."}), 401
            g.server = srv
            g.is_admin_context = is_admin
            return view(*args, **kwargs)
        return wrapper
    return decorator


def _wants_json():
    from flask import request
    return request.path.startswith("/api") or request.is_json or "application/json" in (request.headers.get("Accept") or "")
