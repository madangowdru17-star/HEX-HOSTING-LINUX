"""
Central configuration for NE-HOST.

All secrets and environment-specific values are read from environment
variables (or a local .env file — see .env.example). Nothing sensitive
is hard-coded, and the app refuses to boot with unsafe defaults in
production mode.
"""
import os
import secrets


def _load_dotenv(path=".env"):
    """Minimal, dependency-free .env loader.

    Only used to populate os.environ for values that are not already
    set, so real environment variables (e.g. injected by your host/
    container platform) always take priority over the .env file.
    """
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # --- Core / runtime ---
    ENV = os.environ.get("FLASK_ENV", "production")
    IS_PRODUCTION = ENV.lower() == "production"
    DEBUG = _env_bool("FLASK_DEBUG", default=not IS_PRODUCTION)
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))

    # --- Secrets ---
    # In production a SECRET_KEY MUST be supplied via env var. In dev,
    # we auto-generate an ephemeral one so the app still runs locally,
    # but it changes every restart (sessions won't survive a reload).
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError(
                "SECRET_KEY environment variable is required in production. "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        SECRET_KEY = secrets.token_hex(32)

    # --- Storage paths ---
    # Everything that must survive a redeploy (DB, user instance files,
    # uploaded images) lives under STORAGE_DIR, so a single persistent
    # volume mounted at `storage/` (e.g. a Railway Volume) covers all of
    # it. Nothing in the existing templates hardcodes the old
    # static/uploads path, so this is safe to relocate.
    BASE_DIR = os.path.abspath(os.getcwd())
    STORAGE_DIR = os.path.join(BASE_DIR, "storage")
    BASE_STORAGE = os.path.join(STORAGE_DIR, "instances")
    UPLOAD_FOLDER = os.path.join(STORAGE_DIR, "uploads")
    DB_PATH = os.path.join(STORAGE_DIR, "nehost.db")

    # --- Cookies / sessions ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", default=IS_PRODUCTION)
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_SECONDS", "43200"))  # 12h
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024

    # --- Bootstrap admin (first run only; ignored once an admin exists) ---
    BOOTSTRAP_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
    BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

    # --- Rate limiting ---
    LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))
    GLOBAL_RATE_LIMIT_PER_MIN = int(os.environ.get("GLOBAL_RATE_LIMIT_PER_MIN", "120"))

    # --- Uploads ---
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    # --- GitHub import ---
    GITHUB_IMPORT_ENABLED = _env_bool("GITHUB_IMPORT_ENABLED", default=True)
    GITHUB_IMPORT_MAX_MB = int(os.environ.get("GITHUB_IMPORT_MAX_MB", "200"))
    GITHUB_IMPORT_TIMEOUT_SECONDS = int(os.environ.get("GITHUB_IMPORT_TIMEOUT_SECONDS", "60"))

    # --- Reverse proxy ---
    TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", default=False)
