"""
Audit trail, request logging, and security alerts.

Kept intentionally simple (direct SQLite writes) so it has no extra
dependencies and is easy to inspect/export. Tables are pruned on a
rolling basis so they can't grow unbounded on a long-running instance.
"""
from flask import request, session

REQUEST_LOG_RETENTION_ROWS = 20000
AUDIT_LOG_RETENTION_ROWS = 20000


def _get_db():
    # Local import to avoid a circular import (extensions -> security.passwords,
    # security.audit -> extensions).
    from extensions import get_db
    return get_db()


def _client_ip():
    from security.ratelimit import client_ip
    try:
        return client_ip()
    except RuntimeError:
        return "unknown"  # outside app/request context


def log_audit(action: str, actor_type: str = "anonymous", actor_id=None, actor_name=None,
              target: str = None, details: str = None):
    try:
        db = _get_db()
        db.execute(
            '''INSERT INTO audit_logs (actor_type, actor_id, actor_name, action, target, details, ip, user_agent)
               VALUES (?,?,?,?,?,?,?,?)''',
            (
                actor_type, actor_id, actor_name, action, target, details,
                _client_ip(),
                request.headers.get("User-Agent", "")[:255] if request else "",
            ),
        )
        db.execute(
            '''DELETE FROM audit_logs WHERE id NOT IN (
                 SELECT id FROM audit_logs ORDER BY id DESC LIMIT ?)''',
            (AUDIT_LOG_RETENTION_ROWS,),
        )
        db.commit()
        db.close()
    except Exception:
        pass  # audit logging must never break the actual request


def log_request(status: int):
    try:
        db = _get_db()
        db.execute(
            '''INSERT INTO request_logs (ip, method, path, status, user_id, is_admin, user_agent)
               VALUES (?,?,?,?,?,?,?)''',
            (
                _client_ip(), request.method, request.path, status,
                session.get("user_id"), 1 if session.get("admin_logged") else 0,
                request.headers.get("User-Agent", "")[:255],
            ),
        )
        db.execute(
            '''DELETE FROM request_logs WHERE id NOT IN (
                 SELECT id FROM request_logs ORDER BY id DESC LIMIT ?)''',
            (REQUEST_LOG_RETENTION_ROWS,),
        )
        db.commit()
        db.close()
    except Exception:
        pass


def log_alert(alert_type: str, severity: str, ip: str = None, user_id=None, message: str = ""):
    try:
        db = _get_db()
        db.execute(
            '''INSERT INTO security_alerts (type, severity, ip, user_id, message) VALUES (?,?,?,?,?)''',
            (alert_type, severity, ip or _client_ip(), user_id, message),
        )
        db.commit()
        db.close()
    except Exception:
        pass
