"""
Rate limiting & brute-force protection.

A dependency-free, thread-safe sliding-window limiter. It's in-memory,
which is fine for a single-process deployment (matches how this app
already tracks running server processes in-memory); for a multi-worker
production deployment behind a load balancer, swap this for
Flask-Limiter backed by Redis (see requirements.txt / SECURITY.md) —
the `rate_limited` decorator's call sites don't need to change.
"""
import time
import threading
import functools

from flask import request, jsonify, current_app

from security.audit import log_alert

_lock = threading.Lock()
_hits = {}  # key -> list[timestamps]


def client_ip():
    """Best-effort client IP. Only trusts X-Forwarded-For when the app
    is explicitly configured to sit behind a trusted reverse proxy —
    otherwise that header is trivially spoofable by any client."""
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _prune(key, window):
    now = time.time()
    _hits[key] = [t for t in _hits.get(key, []) if now - t < window]


def hit(key, limit, window):
    """Record a hit for `key`; return True if still within the limit."""
    with _lock:
        _prune(key, window)
        _hits.setdefault(key, []).append(time.time())
        return len(_hits[key]) <= limit


def current_count(key, window):
    with _lock:
        _prune(key, window)
        return len(_hits.get(key, []))


def rate_limited(limit: int, window_seconds: int, scope: str = "global", key_func=None):
    """Decorator: limit `limit` requests per `window_seconds` per client
    (IP by default, or a custom key_func(request) -> str)."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            ident = key_func() if key_func else client_ip()
            key = f"{scope}:{ident}"
            if not hit(key, limit, window_seconds):
                log_alert(
                    "rate_limit_exceeded", "medium",
                    ip=client_ip(),
                    message=f"Rate limit exceeded on '{scope}' ({limit}/{window_seconds}s)",
                )
                resp = jsonify({"status": "error", "msg": "Too many requests. Please slow down and try again shortly."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(window_seconds)
                return resp
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# --- Account lockout (per-user / per-admin, persisted in DB by callers) ---

def is_locked(locked_until_str) -> bool:
    if not locked_until_str:
        return False
    try:
        return time.time() < float(locked_until_str)
    except (TypeError, ValueError):
        return False


def lockout_expiry(seconds_from_now: int) -> str:
    return str(time.time() + seconds_from_now)
