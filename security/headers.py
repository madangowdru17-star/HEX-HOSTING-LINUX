"""
Security response headers.

CSP is deliberately built from the actual third-party CDNs this app's
templates already load (cdnjs, jsdelivr, googleapis fonts) so it doesn't
break the existing UI/animations/icons, while still blocking inline
event-handler injection vectors and framing attacks.
"""

_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
    "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "connect-src 'self'",
    "frame-ancestors 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
])


def apply_security_headers(app):
    @app.after_request
    def _set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Content-Security-Policy"] = _CSP
        resp.headers.setdefault("X-XSS-Protection", "0")  # superseded by CSP; explicit disable of legacy filter quirks
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        # Sensitive/dynamic pages shouldn't be cached by intermediaries
        if resp.mimetype in ("application/json", "text/html"):
            resp.headers.setdefault("Cache-Control", "no-store, max-age=0")
        return resp
