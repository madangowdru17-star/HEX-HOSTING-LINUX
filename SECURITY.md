# NE-HOST — Security Audit & Hardening Notes

This document explains what was found in the original codebase, what was
changed, what's new, and what remains your operational responsibility.
**No visible UI (design, layout, colors, animations, pages) was changed.**
All hardening is server-side, plus a handful of invisible additions
(hidden CSRF fields, a `<meta>` tag, and one new "Security" button in the
admin navbar that links to a new page in the existing visual style).

## 1. Critical issues found in the original app, and how they were fixed

| # | Issue | Original state | Fix |
|---|---|---|---|
| 1 | **Plaintext passwords** | User & admin passwords stored and compared as plaintext strings, including a hardcoded default admin password (`neverexits` / `1100`) | Passwords are hashed with `werkzeug.security` (PBKDF2-SHA256, per-password random salt). Legacy plaintext admin passwords are transparently migrated to a hash on next boot. No default admin password ships — a strong random one is generated at first run, or you set your own via `.env`. |
| 2 | **Unauthenticated file/process endpoints** | Most `/files/*` and `/server/*` routes had **no session check at all** — anyone, logged in or not, could list/read/write/delete files or start/stop processes in *any* user's instance folder by guessing/enumerating folder names | Every such route now goes through a `server_owner_required` decorator that (a) requires a logged-in session and (b) verifies the folder belongs to that session's user (or an active admin session). Denied attempts are audit-logged as `idor_attempt`. |
| 3 | **Path traversal** | `folder`, `path`, and `name` parameters were concatenated into filesystem paths with little to no validation in several routes (create/save/rename/delete/upload) | All filesystem access now goes through `security/pathsafe.py`'s `safe_join()`, which rejects absolute paths, `../` traversal, null bytes, and symlink escapes, and re-validates after resolving symlinks. |
| 4 | **Zip-slip** | `/files/unzip` extracted arbitrary zip archives without checking entry paths, so a crafted zip (`../../etc/whatever`) could write outside the instance folder | Every zip entry's resolved path is checked against the instance directory *before* extraction; unsafe archives are rejected outright. The new GitHub-import feature also strips `.git` and rejects symlinks after cloning. |
| 5 | **No CSRF protection** | Every state-changing request (login, signup, file ops, admin actions, etc.) had no CSRF defenses | Synchronizer-token pattern (`security/csrf.py`) using a per-session secret + `itsdangerous`-signed tokens. Delivered invisibly: a hidden `csrf_token` field in existing `<form>`s, and a `<meta>` tag + `fetch()` override for JSON-based calls — no visible UI change. |
| 6 | **No rate limiting / brute-force protection** | Login, signup, and admin login could be hit unlimited times | Per-IP sliding-window rate limits on login/signup/admin-login/file-upload/console/GitHub-import, plus per-account lockout (5 failed attempts → 5 minute lockout, configurable) for both users and the admin account. |
| 7 | **Weak session/cookie config** | Hardcoded `SECRET_KEY` fallback, no explicit cookie flags | `SECRET_KEY` is required from the environment in production (app refuses to boot without it). Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when `SESSION_COOKIE_SECURE=true`. Sessions are cleared and regenerated on every login (fixation protection). |
| 8 | **`debug=True` in production** | The Werkzeug interactive debugger (arbitrary code execution via the browser) was reachable on any unhandled exception | `debug` now defaults to `False` and is only enabled via `FLASK_DEBUG=1` for local development. |
| 9 | **Missing/weak security headers** | No CSP, no clickjacking protection, no MIME-sniffing protection | `security/headers.py` sets CSP (scoped to the CDNs the UI already uses, so nothing breaks), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security` when serving over HTTPS. |
| 10 | **Unrestricted uploads** | Profile picture / popup image uploads accepted any file extension, saved under the user-supplied filename | Uploads are restricted to image extensions, renamed to a random UUID filename server-side (no collisions, no path tricks), and size-capped (`MAX_UPLOAD_MB`). |
| 11 | **Privilege boundaries** | Ad-hoc checks scattered through the code; some admin actions were reachable without verifying the admin session on every branch | Centralized `login_required` / `admin_required` / `server_owner_required` decorators (`security/access.py`) used consistently across every route. |
| 12 | **Two broken features** | The file editor called `/files/read/` (404 — backend only had `/files/content/<folder>/<name>`), and the in-app console called `/server/command/` which didn't exist at all | Both are now implemented and working (verified end-to-end). The console command endpoint is scoped to the caller's own instance directory, timeboxed, output-capped, rate-limited, and fully audit-logged. |

## 2. New capabilities added

- **Admin Security Center** (`/admin/security`, linked from a new button in
  the existing admin navbar): live audit log, IP/traffic monitor, and a
  suspicious-activity alert feed, styled to match the existing admin panel.
- **Audit logging** (`audit_logs` table): every sensitive action (login,
  logout, password change, file delete, server start/stop, admin actions,
  GitHub imports, IDOR attempts, etc.) is recorded with actor, target, IP,
  user agent, and timestamp.
- **Request/IP monitoring** (`request_logs` table, rolling 20k-row window):
  every request's IP, method, path, status, and user is logged for traffic
  analysis in the Security Center.
- **Suspicious activity detection** (`security/detect.py`): a lightweight,
  explainable rule engine flags error bursts (scanning/fuzzing), repeated
  failed logins, brute-force lockouts, path-traversal/SQLi/XSS-looking
  payloads in requests, and unauthorized admin-endpoint access attempts —
  each raises a `security_alerts` row visible (and resolvable) in the
  admin panel.
- **GitHub repository import**, added with strict validation:
  - Only `https://github.com/<owner>/<repo>` URLs are accepted (no other
    hosts, no credentials-in-URL, no query/fragment tricks, no ports).
  - The hostname is resolved and checked against private/loopback/
    link-local/reserved IP ranges before cloning (DNS-rebinding-resistant
    SSRF guard).
  - Shallow, single-branch clone only; `.git` metadata is stripped after
    clone; symlinks in the result are removed; the import is size-capped
    and time-boxed; only works into an empty instance folder.

## 3. Design notes / things worth knowing

- **Rate limiting is in-memory**, scoped to a single process — appropriate
  for the single-process design this app already uses for tracking running
  server processes. If you scale to multiple worker processes/machines,
  swap `security/ratelimit.py` for Flask-Limiter backed by Redis (listed
  as optional in `requirements.txt`) so limits are shared across workers.
- **Password hashing uses Werkzeug's PBKDF2-SHA256**, not bcrypt/argon2 —
  this avoids a native-compiled dependency while still being a salted,
  slow, industry-standard KDF. If you'd prefer bcrypt or argon2, swap the
  two functions in `security/passwords.py`; nothing else needs to change.
- **The in-app "console" (`/server/command`) intentionally still allows
  arbitrary shell commands** inside the caller's own instance directory.
  This is not a new privilege: the same user can already write and run
  arbitrary Python in that same folder via the file manager and
  install/start actions. What's new is that it's properly authenticated,
  ownership-checked, timeboxed, output-capped, and audit-logged, whereas
  before it was an unauthenticated 404.
- **Full OS-level sandboxing (containers, seccomp, cgroups) is out of
  scope** for this pass — that's an infrastructure decision, not an
  application-code one. If you need hard isolation between tenants' code,
  run each instance's `start`/`install`/console commands inside a
  per-tenant container (e.g. gVisor/Firecracker/Docker with resource
  limits) rather than as a subprocess of the Flask app itself.

## 4. Operational checklist before going to production

- [ ] Set a real `SECRET_KEY` (the app will refuse to start without one
      when `FLASK_ENV=production`)
- [ ] Set `ADMIN_USERNAME` / `ADMIN_PASSWORD` (or capture the generated
      one-time password on first boot and change it immediately)
- [ ] Serve over HTTPS and set `SESSION_COOKIE_SECURE=true`
- [ ] Run behind gunicorn/uwsgi + Nginx/Caddy, not `python3 app.py`
- [ ] Only set `TRUST_PROXY_HEADERS=true` if you control the proxy in
      front of the app (otherwise `X-Forwarded-For` is spoofable)
- [ ] Back up `storage/` regularly
- [ ] Review `/admin/security` periodically for alerts
- [ ] Run `python3 tests/test_security.py` after any future changes

## 5. Test coverage

`tests/test_security.py` (20 tests, all passing) covers: signup/login/
dashboard flow, password hashing, weak-password rejection, login lockout
after repeated failures, unauthenticated file-manager access is denied,
cross-user IDOR is denied, path traversal in file read is blocked, zip-slip
is blocked, admin panel requires login, admin login accepts/rejects
correctly, admin password is hashed, and GitHub-import URL validation
rejects non-GitHub hosts / credentials-in-URL / non-HTTPS / sub-paths.
