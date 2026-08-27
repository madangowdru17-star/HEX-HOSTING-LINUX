# NE-HOST — Setup Guide

## 1. Requirements

- Python 3.10+
- `git` binary available on `PATH` (required for the GitHub-import feature)
- (Recommended for production) a reverse proxy like Nginx/Caddy terminating HTTPS

## 2. Install (local)

```bash
python3 -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Configure

```bash
cp .env.example .env
```

Then edit `.env`:

- **`SECRET_KEY`** — required in production. Generate one with:
  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
- **`ADMIN_USERNAME`** / **`ADMIN_PASSWORD`** — set these before the *first*
  run to choose your own admin login. If you skip `ADMIN_PASSWORD`, the app
  will generate a strong random one-time password and print it to the
  console on first boot — log in once and change it immediately from the
  admin panel.
- **`SESSION_COOKIE_SECURE`** — set to `true` once you're serving over HTTPS.

## 4. Run locally

Development:
```bash
FLASK_ENV=development python3 app.py
```

Production (behind a real WSGI server — never use `python3 app.py` in
production):
```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 --timeout 120 app:app
```
Put this behind Nginx/Caddy with TLS termination, and set
`SESSION_COOKIE_SECURE=true` and `TRUST_PROXY_HEADERS=true` (only if the
proxy is one you control) in `.env`.

## 5. Deploying to Railway (recommended — works fine from mobile too)

Everything needed is already in this zip: `Procfile`, `railway.json`,
`nixpacks.toml`, `.python-version`, `runtime.txt`, and `requirements.txt`
(with `gunicorn` included). No manual build/start configuration needed.

1. **Push this code to a GitHub repo.** Keep it **private** — it contains
   your admin/security logic.
2. **Railway → New Project → Deploy from GitHub repo** → select it.
   Railway detects it as a Python app via Nixpacks automatically.
3. **Add a persistent Volume**: Railway dashboard → your service →
   Volumes → mount at `/app/storage`. This one volume covers the
   database, every user's instance files, and uploaded images — they all
   live under `storage/` (see `config.py`). **Skip this and you'll lose
   all data on every redeploy.**
4. **Set environment variables** (Railway → Variables tab):
   ```
   FLASK_ENV=production
   SECRET_KEY=<generate with the command below>
   ADMIN_USERNAME=your_admin_name
   ADMIN_PASSWORD=<a strong password>
   SESSION_COOKIE_SECURE=true
   TRUST_PROXY_HEADERS=true
   ```
   Generate `SECRET_KEY` (from Termux or anywhere with Python):
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```
   The app deliberately refuses to boot in production without
   `SECRET_KEY` set — see SECURITY.md for why.
5. **Deploy.** Railway builds with Nixpacks — `git` is included via
   `nixpacks.toml` (required for the "Import from GitHub" feature) — then
   runs:
   ```
   gunicorn -w 2 -b 0.0.0.0:$PORT --timeout 120 app:app
   ```
   per `Procfile`/`railway.json`. You'll get a public `*.up.railway.app`
   URL; add a custom domain under Settings → Domains if you want one.
6. **First login**: go to `/admin-login` with the credentials from step 4,
   and change the admin password immediately from the admin panel.
   Regular users sign up at `/signup` and log in at `/login`.

### Other platforms (Render, Heroku, a plain VPS)

The same `Procfile`, `requirements.txt`, `.python-version` / `runtime.txt`
work unmodified on Render/Heroku-style platforms — just set the same
environment variables and attach persistent disk/volume storage at
`storage/` the same way. On a bare VPS: `pip install -r requirements.txt`,
run the same `gunicorn` command via systemd, and put Nginx/Caddy in front
for TLS.

## 6. Data & backups

- SQLite database: `storage/nehost.db`
- User "instances" (their uploaded/created code): `storage/instances/<folder>/`
- Uploaded profile pictures / popup images: `storage/uploads/`

Back up the `storage/` directory regularly; it holds all user data.

## 7. Running the test suite

```bash
python3 tests/test_security.py
```

This runs 20 automated checks (auth flow, password hashing, CSRF
enforcement, IDOR/ownership checks, path-traversal & zip-slip blocking,
SSRF-safe GitHub URL validation, admin auth) against an isolated,
throwaway SQLite database — safe to run anywhere.

See `SECURITY.md` for what was fixed, what's still your responsibility,
and how the admin security/audit tooling works.
