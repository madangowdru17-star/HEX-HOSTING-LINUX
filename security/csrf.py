"""
CSRF protection.

A per-session secret is stored server-side in the Flask session; a
signed token derived from it (via itsdangerous, already a Flask
dependency) is exposed to templates as `csrf_token()`. State-changing
requests (POST/PUT/PATCH/DELETE) must echo that token back either as
a form field `csrf_token`, a JSON body field `csrf_token`, or the
`X-CSRFToken` header. This is the standard synchronizer-token pattern
and works for both classic form posts and fetch()-based JSON calls
without altering any visible UI.
"""
import functools
import secrets

from flask import session, request, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

_MAX_AGE = 60 * 60 * 12  # 12 hours, matches session lifetime


def _serializer(app):
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="nehost-csrf")


def get_csrf_token(app):
    if "_csrf_seed" not in session:
        session["_csrf_seed"] = secrets.token_hex(16)
    return _serializer(app).dumps(session["_csrf_seed"])


def _extract_token():
    token = request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token")
    if token:
        return token
    if request.is_json:
        data = request.get_json(silent=True) or {}
        if isinstance(data, dict) and data.get("csrf_token"):
            return data.get("csrf_token")
    if request.form.get("csrf_token"):
        return request.form.get("csrf_token")
    return None


def validate_csrf(app) -> bool:
    seed = session.get("_csrf_seed")
    token = _extract_token()
    if not seed or not token:
        return False
    try:
        unsigned = _serializer(app).loads(token, max_age=_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return False
    return secrets.compare_digest(unsigned, seed)


def csrf_protect(app):
    """Register a before_request hook that enforces CSRF on unsafe methods."""

    @app.before_request
    def _check_csrf():
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        # Public, state-safe endpoints (no session-bound side effects worth
        # forging) are exempted individually via the `csrf_exempt` set below
        # rather than blanket-exempting whole blueprints.
        if request.endpoint and request.endpoint in app.config.get("CSRF_EXEMPT_ENDPOINTS", set()):
            return None
        view = app.view_functions.get(request.endpoint) if request.endpoint else None
        if view is not None and getattr(view, "_csrf_exempt_marker", False):
            return None
        if not validate_csrf(app):
            return jsonify({"status": "error", "msg": "Invalid or missing security token. Please refresh the page and try again."}), 400
        return None


def csrf_exempt(view):
    """Decorator to exempt a specific view (e.g. webhook-style endpoints)."""
    view._csrf_exempt_marker = True

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        return view(*args, **kwargs)

    return wrapper
