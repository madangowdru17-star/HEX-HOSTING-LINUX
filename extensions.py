"""
Database access layer.

Still SQLite (matches the original project), but:
  - all queries remain parameterized (no string-built SQL anywhere)
  - schema gains audit/security tables and per-account lockout fields
  - WAL mode is enabled for better concurrent read/write behaviour
"""
import os
import sqlite3

from config import Config
from security.passwords import hash_password


def get_db():
    os.makedirs(Config.STORAGE_DIR, exist_ok=True)
    conn = sqlite3.connect(Config.DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _column_exists(db, table, column):
    cols = [r["name"] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
    return column in cols


def _add_column_if_missing(db, table, column, coldef):
    if not _column_exists(db, table, column):
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")


def init_db():
    os.makedirs(Config.STORAGE_DIR, exist_ok=True)
    db = get_db()

    # --- Users ---
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fname TEXT, lname TEXT, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT,
        pfp TEXT DEFAULT 'default.png',
        role TEXT DEFAULT 'free',
        status TEXT DEFAULT 'active',
        server_limit INTEGER DEFAULT 1,
        notifications TEXT DEFAULT '',
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT,
        last_login_at TEXT,
        last_login_ip TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # --- Servers ("instances") ---
    db.execute('''CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT, folder TEXT UNIQUE, status TEXT, startup TEXT, pid INTEGER,
        server_status TEXT DEFAULT 'active',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # --- Support tickets ---
    db.execute('''CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, subject TEXT, message TEXT, status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # --- Admin account + site settings ---
    db.execute('''CREATE TABLE IF NOT EXISTS admin_settings (
        id INTEGER PRIMARY KEY,
        username TEXT, password TEXT,
        popup_title TEXT, popup_msg TEXT, popup_img TEXT, show_popup INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT
    )''')

    # --- Audit log: every sensitive action taken by a user or admin ---
    db.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_type TEXT,      -- 'user' | 'admin' | 'system' | 'anonymous'
        actor_id INTEGER,
        actor_name TEXT,
        action TEXT NOT NULL,
        target TEXT,
        details TEXT,
        ip TEXT,
        user_agent TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # --- Request log: lightweight rolling window for IP/traffic monitoring ---
    db.execute('''CREATE TABLE IF NOT EXISTS request_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, method TEXT, path TEXT, status INTEGER,
        user_id INTEGER, is_admin INTEGER DEFAULT 0,
        user_agent TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_request_logs_created ON request_logs(created_at)')

    # --- Security alerts raised by the detection engine ---
    db.execute('''CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT, severity TEXT, ip TEXT, user_id INTEGER,
        message TEXT, resolved INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # Backfill columns for DBs created by earlier versions of this app
    for col, coldef in [
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until", "TEXT"),
        ("last_login_at", "TEXT"),
        ("last_login_ip", "TEXT"),
        ("created_at", "TEXT DEFAULT CURRENT_TIMESTAMP"),
    ]:
        _add_column_if_missing(db, "users", col, coldef)
    for col, coldef in [
        ("server_status", "TEXT DEFAULT 'active'"),
        ("created_at", "TEXT DEFAULT CURRENT_TIMESTAMP"),
    ]:
        _add_column_if_missing(db, "servers", col, coldef)
    for col, coldef in [
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until", "TEXT"),
    ]:
        _add_column_if_missing(db, "admin_settings", col, coldef)

    # Bootstrap the admin account. Never insert a known default password.
    existing_admin = db.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
    if not existing_admin:
        username = Config.BOOTSTRAP_ADMIN_USERNAME or "admin"
        if Config.BOOTSTRAP_ADMIN_PASSWORD:
            pwd_hash = hash_password(Config.BOOTSTRAP_ADMIN_PASSWORD)
        else:
            # No ADMIN_PASSWORD supplied: generate a strong random one and
            # print it once so the operator can log in and change it.
            import secrets as _secrets
            generated = _secrets.token_urlsafe(18)
            pwd_hash = hash_password(generated)
            print("=" * 70)
            print(" NE-HOST: no ADMIN_PASSWORD set — generated a one-time admin password")
            print(f"   username: {username}")
            print(f"   password: {generated}")
            print(" Change this immediately after logging in, or set ADMIN_USERNAME /")
            print(" ADMIN_PASSWORD env vars before first run.")
            print("=" * 70)
        db.execute(
            "INSERT INTO admin_settings (id, username, password, show_popup) VALUES (1, ?, ?, 0)",
            (username, pwd_hash),
        )
    elif existing_admin["password"] and not existing_admin["password"].startswith(("pbkdf2:", "scrypt:")):
        # Migrate a legacy plaintext admin password to a hash transparently.
        db.execute(
            "UPDATE admin_settings SET password=? WHERE id=1",
            (hash_password(existing_admin["password"]),),
        )

    db.commit()
    db.close()
