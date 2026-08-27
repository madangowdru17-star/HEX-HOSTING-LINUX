import os
import time

from flask import Flask, request, session, jsonify, send_from_directory

from config import Config
from extensions import init_db
from security.csrf import get_csrf_token, csrf_protect
from security.headers import apply_security_headers
from security.ratelimit import rate_limited, client_ip
from security.audit import log_request
from security.detect import scan_request_for_payload_attacks, note_response, note_payload_attack


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(app.config["BASE_STORAGE"], exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    init_db()

    # --- Blueprints ---
    from blueprints.public_bp import bp as public_bp
    from blueprints.auth_bp import bp as auth_bp
    from blueprints.dashboard_bp import bp as dashboard_bp
    from blueprints.files_bp import bp as files_bp
    from blueprints.server_bp import bp as server_bp
    from blueprints.admin_bp import bp as admin_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(server_bp)
    app.register_blueprint(admin_bp)

    # Uploaded images live under storage/uploads (persistent-volume-safe;
    # see config.py), but are still served at the familiar /static/uploads/
    # URL so nothing that expects that path shape ever breaks.
    @app.route("/static/uploads/<path:filename>")
    def uploaded_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    # Endpoints that legitimately have no session-bound state to forge
    # (GET-only pages are already exempt from CSRF by method; this set is
    # for any POST/PUT/DELETE endpoint that must remain reachable without
    # a prior page load -- none currently -- kept for future use).
    app.config["CSRF_EXEMPT_ENDPOINTS"] = set()

    # --- Security wiring ---
    apply_security_headers(app)
    csrf_protect(app)

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": get_csrf_token(app)}

    @app.before_request
    def _global_guards():
        # Lightweight global rate limit so no single endpoint (even ones
        # without an explicit per-route limiter) can be hammered.
        ip = client_ip()
        from security.ratelimit import hit
        if not hit(f"global:{ip}", app.config["GLOBAL_RATE_LIMIT_PER_MIN"], 60):
            return jsonify({"status": "error", "msg": "Too many requests."}), 429

        # Attack-payload detection on path/query/body (best-effort, cheap).
        body_snippet = ""
        if request.method in ("POST", "PUT", "PATCH") and request.content_length and request.content_length < 20000:
            try:
                body_snippet = request.get_data(as_text=True)[:2000]
            except Exception:
                body_snippet = ""
        pattern = scan_request_for_payload_attacks(request.path, request.query_string.decode("utf-8", "ignore"), body_snippet)
        if pattern:
            note_payload_attack(ip, request.path, pattern)

    @app.after_request
    def _log_and_monitor(resp):
        try:
            log_request(resp.status_code)
            note_response(client_ip(), resp.status_code, request.path)
        except Exception:
            pass
        return resp

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "msg": "Not found."}), 404

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"status": "error", "msg": "Upload too large."}), 413

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"status": "error", "msg": "Internal server error."}), 500

    return app


app = create_app()

if __name__ == "__main__":
    # debug=False always: the original app ran with debug=True, which
    # exposes the Werkzeug interactive debugger (arbitrary code execution)
    # to anyone who can trigger a 500. Use FLASK_DEBUG=1 for local dev only.
    app.run(host=app.config["HOST"], port=app.config["PORT"], debug=app.config["DEBUG"])
