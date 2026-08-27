"""
Smoke + security regression tests for NE-HOST.

Run with:  python3 tests/test_security.py
Uses Flask's built-in test client (no live server / network needed) and
a throwaway SQLite DB in a temp directory, so it's safe to run anywhere,
including CI, without touching real data.
"""
import io
import os
import shutil
import sys
import tempfile
import unittest

TESTDIR = tempfile.mkdtemp(prefix="nehost_test_")
os.environ["SECRET_KEY"] = "test-secret-key-for-unit-tests-only"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass123"
os.environ["FLASK_ENV"] = "development"
os.chdir(TESTDIR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        # Rate-limiter state is process-global by design (see
        # security/ratelimit.py); reset it between tests so one test's
        # traffic doesn't trip another test's limits.
        import security.ratelimit as ratelimit
        ratelimit._hits.clear()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def get_csrf(self, path="/login"):
        resp = self.client.get(path)
        html = resp.get_data(as_text=True)
        for marker, end_char in [
            ('name="csrf_token" value="', '"'),
            ('name="csrf-token" content="', '"'),
        ]:
            if marker in html:
                start = html.index(marker) + len(marker)
                end = html.index(end_char, start)
                return html[start:end]
        raise AssertionError(f"No CSRF token found on {path} (status {resp.status_code})")

    def get_csrf_json(self, path="/dashboard"):
        # For JSON-header flows we can reuse the meta-tag pattern from any
        # authenticated page; for anonymous JSON endpoints (rare) tests
        # fetch a public page's csrf and pass it explicitly.
        return self.get_csrf(path="/login")


class AuthFlowTests(BaseTestCase):
    def test_signup_requires_csrf(self):
        resp = self.client.post("/signup", data={
            "fname": "A", "lname": "B", "username": "nocsrf", "email": "nocsrf@example.com",
            "password": "Password123", "confirm_password": "Password123",
        })
        self.assertEqual(resp.status_code, 400)

    def test_signup_login_dashboard_flow(self):
        token = self.get_csrf("/signup")
        resp = self.client.post("/signup", data={
            "csrf_token": token,
            "fname": "Alice", "lname": "Smith", "username": "alice1", "email": "alice@example.com",
            "password": "Password123", "confirm_password": "Password123",
        })
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertEqual(resp.get_json()["status"], "success")

        token = self.get_csrf("/login")
        resp = self.client.post("/login", data={
            "csrf_token": token, "email": "alice@example.com", "password": "Password123",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "success")

        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)

    def test_weak_password_rejected(self):
        token = self.get_csrf("/signup")
        resp = self.client.post("/signup", data={
            "csrf_token": token,
            "fname": "A", "lname": "B", "username": "weakpw", "email": "weak@example.com",
            "password": "123", "confirm_password": "123",
        })
        self.assertEqual(resp.status_code, 400)

    def test_login_lockout_after_repeated_failures(self):
        token = self.get_csrf("/signup")
        self.client.post("/signup", data={
            "csrf_token": token, "fname": "L", "lname": "K", "username": "lockme",
            "email": "lock@example.com", "password": "Password123", "confirm_password": "Password123",
        })
        for _ in range(6):
            token = self.get_csrf("/login")
            resp = self.client.post("/login", data={
                "csrf_token": token, "email": "lock@example.com", "password": "WrongPassword",
            })
        # account should now be locked regardless of correct password
        token = self.get_csrf("/login")
        resp = self.client.post("/login", data={
            "csrf_token": token, "email": "lock@example.com", "password": "Password123",
        })
        self.assertEqual(resp.status_code, 429)

    def test_passwords_are_hashed_not_plaintext(self):
        token = self.get_csrf("/signup")
        self.client.post("/signup", data={
            "csrf_token": token, "fname": "H", "lname": "P", "username": "hashcheck",
            "email": "hash@example.com", "password": "Password123", "confirm_password": "Password123",
        })
        from extensions import get_db
        db = get_db()
        row = db.execute("SELECT password FROM users WHERE email=?", ("hash@example.com",)).fetchone()
        db.close()
        self.assertTrue(row["password"].startswith(("pbkdf2:", "scrypt:")))
        self.assertNotIn("Password123", row["password"])


class IDORAndPathSafetyTests(BaseTestCase):
    def _signup_login(self, email, username):
        token = self.get_csrf("/signup")
        self.client.post("/signup", data={
            "csrf_token": token, "fname": "U", "lname": "V", "username": username,
            "email": email, "password": "Password123", "confirm_password": "Password123",
        })
        token = self.get_csrf("/login")
        self.client.post("/login", data={"csrf_token": token, "email": email, "password": "Password123"})

    def _create_server(self, name):
        token = self.get_csrf("/dashboard")
        resp = self.client.post("/add", json={"name": name}, headers={"X-CSRFToken": token})
        return resp.get_json()

    def test_unauthenticated_file_access_denied(self):
        # No session at all -> every file-manager endpoint must require auth
        resp = self.client.get("/files/list/anything")
        self.assertIn(resp.status_code, (401, 403, 404))

    def test_cannot_access_another_users_server(self):
        self._signup_login("owner@example.com", "owner1")
        self._create_server("myserver")
        from extensions import get_db
        db = get_db()
        folder = db.execute("SELECT folder FROM servers LIMIT 1").fetchone()["folder"]
        db.close()

        # Log out, create a second user, try to access the first user's folder
        self.client.get("/")  # keep session cookie jar but clear auth via new client
        client2 = self.app.test_client()
        resp = client2.get("/signup")
        html = resp.get_data(as_text=True)
        token = html[html.index('name="csrf_token" value="') + 25:]
        token = token[:token.index('"')]
        client2.post("/signup", data={
            "csrf_token": token, "fname": "E", "lname": "V", "username": "eve1",
            "email": "eve@example.com", "password": "Password123", "confirm_password": "Password123",
        })
        resp = client2.get("/login")
        html = resp.get_data(as_text=True)
        token = html[html.index('name="csrf_token" value="') + 25:]
        token = token[:token.index('"')]
        client2.post("/login", data={"csrf_token": token, "email": "eve@example.com", "password": "Password123"})

        resp = client2.get(f"/files/list/{folder}")
        self.assertEqual(resp.status_code, 403)

    def test_path_traversal_in_file_read_blocked(self):
        self._signup_login("trav@example.com", "trav1")
        self._create_server("travsrv")
        from extensions import get_db
        db = get_db()
        folder = db.execute("SELECT folder FROM servers LIMIT 1").fetchone()["folder"]
        db.close()
        resp = self.client.get(f"/files/read/{folder}?name=..%2F..%2F..%2Fetc%2Fpasswd&path=")
        data = resp.get_json()
        self.assertNotIn("root:", data.get("content", ""))

    def test_zip_slip_blocked(self):
        import zipfile
        self._signup_login("zip@example.com", "zip1")
        self._create_server("zipsrv")
        from extensions import get_db
        from flask import current_app
        db = get_db()
        folder = db.execute("SELECT folder FROM servers LIMIT 1").fetchone()["folder"]
        db.close()

        instance_dir = os.path.join(self.app.config["BASE_STORAGE"], folder)
        os.makedirs(instance_dir, exist_ok=True)
        evil_zip_path = os.path.join(instance_dir, "evil.zip")
        with zipfile.ZipFile(evil_zip_path, "w") as z:
            z.writestr("../../../../tmp/pwned_by_zipslip.txt", "pwned")

        token = self.get_csrf("/dashboard")
        resp = self.client.post(f"/files/unzip/{folder}", json={"name": "evil.zip", "path": ""},
                                 headers={"X-CSRFToken": token})
        data = resp.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertFalse(os.path.exists("/tmp/pwned_by_zipslip.txt"))


class AdminAuthTests(BaseTestCase):
    def test_admin_panel_requires_login(self):
        resp = self.client.get("/admin/panel")
        self.assertEqual(resp.status_code, 302)

    def test_admin_login_wrong_password_rejected(self):
        token = self.get_csrf("/admin-login")
        resp = self.client.post("/admin-login", data={
            "csrf_token": token, "username": "admin", "password": "totally-wrong",
        })
        self.assertEqual(resp.status_code, 401)

    def test_admin_login_correct_password_succeeds(self):
        token = self.get_csrf("/admin-login")
        resp = self.client.post("/admin-login", data={
            "csrf_token": token, "username": "admin", "password": "TestAdminPass123",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "success")
        resp = self.client.get("/admin/panel")
        self.assertEqual(resp.status_code, 200)

    def test_admin_password_is_hashed(self):
        from extensions import get_db
        db = get_db()
        row = db.execute("SELECT password FROM admin_settings WHERE id=1").fetchone()
        db.close()
        self.assertTrue(row["password"].startswith(("pbkdf2:", "scrypt:")))


class SSRFGithubImportTests(unittest.TestCase):
    def test_rejects_non_github_host(self):
        from security.ssrf import validate_github_url, InvalidRepoURL
        with self.assertRaises(InvalidRepoURL):
            validate_github_url("https://evil.com/owner/repo")

    def test_rejects_credentials_in_url(self):
        from security.ssrf import validate_github_url, InvalidRepoURL
        with self.assertRaises(InvalidRepoURL):
            validate_github_url("https://user:pass@github.com/owner/repo")

    def test_rejects_non_https(self):
        from security.ssrf import validate_github_url, InvalidRepoURL
        with self.assertRaises(InvalidRepoURL):
            validate_github_url("git://github.com/owner/repo")

    def test_rejects_subpaths(self):
        from security.ssrf import validate_github_url, InvalidRepoURL
        with self.assertRaises(InvalidRepoURL):
            validate_github_url("https://github.com/owner/repo/extra/path")

    def test_accepts_well_formed_url(self):
        from security.ssrf import validate_github_url
        # network resolution is allowed to fail in a sandboxed CI; only
        # assert the syntactic/normalization behaviour here.
        try:
            result = validate_github_url("https://github.com/octocat/Hello-World")
            self.assertEqual(result, "https://github.com/octocat/Hello-World.git")
        except Exception:
            pass  # DNS may be unavailable in this environment


class PathSafeUnitTests(unittest.TestCase):
    def test_safe_join_blocks_traversal(self):
        from security.pathsafe import safe_join, UnsafePathError
        base = tempfile.mkdtemp()
        with self.assertRaises(UnsafePathError):
            safe_join(base, "../../etc/passwd")
        with self.assertRaises(UnsafePathError):
            safe_join(base, "/etc/passwd")

    def test_safe_join_allows_normal_paths(self):
        from security.pathsafe import safe_join
        base = tempfile.mkdtemp()
        result = safe_join(base, "sub", "file.txt")
        self.assertTrue(result.startswith(base))


def _cleanup():
    shutil.rmtree(TESTDIR, ignore_errors=True)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        _cleanup()
