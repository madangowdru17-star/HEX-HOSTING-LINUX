"""
Suspicious activity / attack detection.

A small, explainable rule engine (not ML) that runs on every request
and after failed-auth events. It looks for patterns that are cheap to
compute and have a low false-positive rate:

  - a burst of 4xx/error responses from one IP (scanning / fuzzing)
  - repeated failed logins for one account or from one IP (brute force)
  - path-traversal / injection-looking payloads in the URL or params
  - requests to admin endpoints from an IP with no prior successful admin session

Findings are written to `security_alerts` via security.audit.log_alert
and surfaced in the admin panel.
"""
import re
import time
import threading

from security.audit import log_alert

_lock = threading.Lock()
_error_bursts = {}  # ip -> list[timestamps of 4xx/5xx]
_ERROR_BURST_WINDOW = 60
_ERROR_BURST_THRESHOLD = 15

_SUSPICIOUS_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"<script", re.I),
    re.compile(r"union\s+select", re.I),
    re.compile(r"select\s+.*\s+from", re.I),
    re.compile(r";\s*drop\s+table", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"/etc/passwd"),
    re.compile(r"\bwget\b|\bcurl\b", re.I),
]


def scan_request_for_payload_attacks(path: str, query_string: str, body_snippet: str = "") -> str:
    haystack = f"{path}?{query_string} {body_snippet or ''}"
    for pattern in _SUSPICIOUS_PATTERNS:
        if pattern.search(haystack):
            return pattern.pattern
    return None


def note_response(ip: str, status: int, path: str):
    if status < 400:
        return
    now = time.time()
    with _lock:
        bucket = _error_bursts.setdefault(ip, [])
        bucket.append(now)
        _error_bursts[ip] = [t for t in bucket if now - t < _ERROR_BURST_WINDOW]
        count = len(_error_bursts[ip])
    if count == _ERROR_BURST_THRESHOLD:
        log_alert(
            "error_burst", "high", ip=ip,
            message=f"{count} error responses (4xx/5xx) from {ip} in {_ERROR_BURST_WINDOW}s (possible scanning/fuzzing)",
        )


def note_failed_login(identifier: str, ip: str, scope: str = "user"):
    log_alert(
        "failed_login", "low", ip=ip,
        message=f"Failed {scope} login attempt for '{identifier}'",
    )


def note_lockout(identifier: str, ip: str, scope: str = "user"):
    log_alert(
        "account_lockout", "medium", ip=ip,
        message=f"{scope.capitalize()} account '{identifier}' locked after repeated failed logins",
    )


def note_payload_attack(ip: str, path: str, pattern: str):
    log_alert(
        "malicious_payload", "high", ip=ip,
        message=f"Suspicious payload matching `{pattern}` on {path}",
    )


def note_admin_access(ip: str, path: str, success: bool):
    log_alert(
        "admin_access_attempt", "medium" if not success else "info", ip=ip,
        message=f"Admin endpoint access {'granted' if success else 'denied'}: {path}",
    )
