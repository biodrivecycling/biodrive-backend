#!/usr/bin/env python3
"""BioDrive API — auth + profile/powers. Uses Postgres if DATABASE_URL set, else SQLite."""
from __future__ import annotations
import hashlib, json, os, re, secrets, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote, quote

HOST = os.environ.get("BD_HOST") or os.environ.get("HOST") or "0.0.0.0"
PORT = int(os.environ.get("BD_PORT") or os.environ.get("PORT") or "8787")
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()
DB_PATH = os.environ.get("BD_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "biodrive.db"))
CORS_ORIGINS = [o.strip() for o in os.environ.get("BD_CORS_ORIGINS", "https://biodrivecycling.com,https://www.biodrivecycling.com,null").split(",") if o.strip()]
DEMO_EMAIL = os.environ.get("BD_DEMO_EMAIL", "1") == "1"
RESEND_API_KEY = (os.environ.get("RESEND_API_KEY") or "").strip()
EMAIL_FROM = (os.environ.get("EMAIL_FROM") or "BioDrive Cycling <onboarding@resend.dev>").strip()
APP_PUBLIC_URL = (os.environ.get("APP_PUBLIC_URL") or "https://biodrivecycling.com").rstrip("/")
SESSION_DAYS = int(os.environ.get("BD_SESSION_DAYS", "30"))
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
USE_PG = bool(DATABASE_URL)
PG = None
if USE_PG:
    import pg8000
    PG = pg8000

def connect():
    if USE_PG:
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        u = urlparse(url)
        return PG.connect(
            user=unquote(u.username or ""),
            password=unquote(u.password or ""),
            host=u.hostname,
            port=u.port or 5432,
            database=(u.path or "/neondb").lstrip("/") or "neondb",
            ssl_context=True,
        )
    import sqlite3
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c

def q(conn, sql, params=None):
    if USE_PG:
        sql = sql.replace("?", "%s")
    cur = conn.cursor()
    cur.execute(sql, params or ())
    return cur

def one(cur):
    row = cur.fetchone()
    if row is None:
        return None
    if USE_PG:
        cols = [d[0] for d in cur.description]
        return {cols[i]: row[i] for i in range(len(cols))}
    return row

def init_db():
    conn = connect()
    try:
        if USE_PG:
            ddl = """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
              first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '',
              email_verified INTEGER NOT NULL DEFAULT 0,
              created_at DOUBLE PRECISION NOT NULL, updated_at DOUBLE PRECISION NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL);
            CREATE TABLE IF NOT EXISTS email_tokens (
              token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              purpose TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
              expires_at DOUBLE PRECISION NOT NULL, used_at DOUBLE PRECISION);
            CREATE TABLE IF NOT EXISTS profiles (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}', updated_at DOUBLE PRECISION NOT NULL);
            CREATE TABLE IF NOT EXISTS powers (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}', updated_at DOUBLE PRECISION NOT NULL);
            """
            cur = conn.cursor()
            cur.execute(ddl)
            conn.commit()
        else:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
              first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '',
              email_verified INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at REAL NOT NULL, expires_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS email_tokens (
              token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              purpose TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL);
            CREATE TABLE IF NOT EXISTS profiles (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}', updated_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS powers (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}', updated_at REAL NOT NULL);
            """)
            conn.commit()
        print("DB ready:", "postgres/pg8000" if USE_PG else DB_PATH)
    finally:
        conn.close()

def g(row, key):
    if row is None: return None
    try: return row[key]
    except Exception: return row.get(key)

def hash_password(password, salt=None):
    if salt is None: salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return dk.hex(), salt.hex()

def verify_password(password, password_hash, salt_hex):
    try:
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
        return secrets.compare_digest(dk.hex(), password_hash)
    except Exception:
        return False

def strong_password(password):
    if len(password) < 8: return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password): return "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password): return "Password must include a lowercase letter."
    if not re.search(r"[0-9]", password): return "Password must include a number."
    return None

def user_public(row):
    return {"id": g(row,"id"), "email": g(row,"email"), "firstName": g(row,"first_name"),
            "lastName": g(row,"last_name"), "emailVerified": bool(g(row,"email_verified")), "createdAt": g(row,"created_at")}

def create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    q(conn, "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
      (token, user_id, now, now + SESSION_DAYS * 86400))
    return token

def create_email_token(conn, user_id, purpose, hours=48):
    token = secrets.token_urlsafe(24)
    now = time.time()
    q(conn, "INSERT INTO email_tokens (token, user_id, purpose, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)",
      (token, user_id, purpose, now, now + hours * 3600))
    return token

def session_user(conn, token):
    if not token: return None
    cur = q(conn, "SELECT u.id, u.email, u.password_hash, u.password_salt, u.first_name, u.last_name, u.email_verified, u.created_at, u.updated_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?", (token, time.time()))
    return one(cur)

def get_json(conn, table, user_id):
    cur = q(conn, "SELECT data_json FROM %s WHERE user_id = ?" % table, (user_id,))
    row = one(cur)
    if not row: return {}
    try:
        data = json.loads(g(row, "data_json") or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def set_json(conn, table, user_id, data):
    now = time.time()
    payload = json.dumps(data if isinstance(data, dict) else {})
    if USE_PG:
        q(conn, "INSERT INTO %s (user_id, data_json, updated_at) VALUES (?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET data_json = EXCLUDED.data_json, updated_at = EXCLUDED.updated_at" % table, (user_id, payload, now))
    else:
        q(conn, "INSERT INTO %s (user_id, data_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at" % table, (user_id, payload, now))


def send_verification_email(to_email, token):
    """Send verify link via Resend. Returns (ok, detail)."""
    import ssl
    import urllib.error
    import urllib.request

    verify_url = APP_PUBLIC_URL + "/biodrive-verify.html?token=" + token + "&email=" + quote(to_email)
    subject = "Verify your BioDrive Cycling account"
    html = (
        "<p>Welcome to BioDrive Cycling.</p>"
        "<p>Please verify your email by clicking the link below:</p>"
        '<p><a href="%s">Verify my email</a></p>'
        "<p>Or copy this URL:</p><p>%s</p>"
        "<p>This link expires in 48 hours.</p>"
        "<p>If you did not create an account, you can ignore this email.</p>"
    ) % (verify_url, verify_url)
    text = "Verify your BioDrive account: " + verify_url

    print("[email] preparing send to=%s from=%s" % (to_email, EMAIL_FROM), flush=True)
    if not RESEND_API_KEY:
        print("[email] RESEND_API_KEY missing", flush=True)
        return False, "RESEND_API_KEY not set"

    payload = json.dumps({
        "from": EMAIL_FROM,
        "to": [to_email],
        "subject": subject,
        "html": html,
        "text": text,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        method="POST",
        headers={
            "Authorization": "Bearer " + RESEND_API_KEY.strip(),
            "Content-Type": "application/json",
            "User-Agent": "BioDriveCycling/1.0",
        },
    )
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print("[email] sent ok to", to_email, "status", resp.status, body[:300], flush=True)
            return True, body
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(e)
        print("[email] FAILED HTTP", e.code, "to", to_email, detail, flush=True)
        return False, "HTTP %s: %s" % (e.code, detail)
    except Exception as e:
        print("[email] FAILED to", to_email, type(e).__name__, e, flush=True)
        return False, "%s: %s" % (type(e).__name__, e)



def check_resend_api():
    """Call Resend API to validate key. Returns dict."""
    import ssl, urllib.request, urllib.error
    if not RESEND_API_KEY:
        return {"ok": False, "error": "no key"}
    req = urllib.request.Request(
        "https://api.resend.com/domains",
        method="GET",
        headers={"Authorization": "Bearer " + RESEND_API_KEY.strip(), "User-Agent": "BioDriveCycling/1.0"},
    )
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print("[email] resend domains ok", body[:200], flush=True)
            return {"ok": True, "status": resp.status, "body": body[:500]}
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(e)
        print("[email] resend domains FAILED", e.code, detail, flush=True)
        return {"ok": False, "status": e.code, "error": detail}
    except Exception as e:
        print("[email] resend domains ERROR", type(e).__name__, e, flush=True)
        return {"ok": False, "error": str(e)}

class Handler(BaseHTTPRequestHandler):
    server_version = "BioDriveAPI/2.2"
    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))
    def _cors(self):
        origin = self.headers.get("Origin", "")
        allow = None
        if origin in CORS_ORIGINS or origin == "null": allow = origin or "*"
        elif origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"): allow = origin
        elif not origin: allow = "*"
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Vary", "Origin")
    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0: return {}
        try:
            data = json.loads(self.rfile.read(n).decode())
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    def _bearer(self):
        a = self.headers.get("Authorization") or ""
        return a[7:].strip() if a.lower().startswith("bearer ") else None
    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status); self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers(); self.wfile.write(payload)
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._send(200, {"ok": True, "service": "biodrive-auth", "version": 2.3, "demoEmail": DEMO_EMAIL, "emailConfigured": bool(RESEND_API_KEY), "emailFrom": EMAIL_FROM, "database": "postgres" if USE_PG else "sqlite"})
        if path == "/api/email-status":
            result = check_resend_api()
            return self._send(200 if result.get("ok") else 502, {"emailFrom": EMAIL_FROM, "demoEmail": DEMO_EMAIL, "resend": result})
        if path in ("/api/auth/me", "/api/profile", "/api/powers"):
            conn = connect()
            try:
                user = session_user(conn, self._bearer())
                if not user: return self._send(401, {"error": "Not authenticated."})
                uid = g(user, "id")
                if path == "/api/auth/me":
                    return self._send(200, {"user": user_public(user), "profile": get_json(conn, "profiles", uid), "powers": get_json(conn, "powers", uid)})
                if path == "/api/profile":
                    return self._send(200, {"profile": get_json(conn, "profiles", uid)})
                return self._send(200, {"powers": get_json(conn, "powers", uid)})
            finally:
                conn.close()
        return self._send(404, {"error": "Not found."})
    def do_PUT(self):
        return self._write(urlparse(self.path).path, self._read_json())
    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_json()
        if path == "/api/auth/signup": return self._signup(data)
        if path == "/api/auth/login": return self._login(data)
        if path == "/api/auth/logout": return self._logout()
        if path == "/api/auth/verify": return self._verify(data)
        if path == "/api/auth/resend-verification": return self._resend(data)
        if path in ("/api/profile", "/api/powers"): return self._write(path, data)
        return self._send(404, {"error": "Not found."})
    def _write(self, path, data):
        conn = connect()
        try:
            user = session_user(conn, self._bearer())
            if not user: return self._send(401, {"error": "Not authenticated."})
            uid = g(user, "id")
            if path == "/api/profile":
                profile = data.get("profile") if isinstance(data.get("profile"), dict) else data
                if not isinstance(profile, dict): return self._send(400, {"error": "Profile must be a JSON object."})
                set_json(conn, "profiles", uid, profile)
                conn.commit()
                return self._send(200, {"ok": True, "profile": get_json(conn, "profiles", uid)})
            if path == "/api/powers":
                powers = data.get("powers") if isinstance(data.get("powers"), dict) else data
                if not isinstance(powers, dict): return self._send(400, {"error": "Powers must be a JSON object."})
                set_json(conn, "powers", uid, powers)
                conn.commit()
                return self._send(200, {"ok": True, "powers": get_json(conn, "powers", uid)})
            return self._send(404, {"error": "Not found."})
        finally:
            conn.close()
    def _signup(self, data):
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        first = (data.get("firstName") or "").strip()
        last = (data.get("lastName") or "").strip()
        if not first: return self._send(400, {"error": "First name is required."})
        if not last: return self._send(400, {"error": "Last name is required."})
        if not email or not EMAIL_RE.match(email): return self._send(400, {"error": "Please enter a valid email."})
        err = strong_password(password)
        if err: return self._send(400, {"error": err})
        pw_hash, salt = hash_password(password)
        user_id = "usr_" + secrets.token_hex(12)
        now = time.time()
        conn = connect()
        try:
            try:
                q(conn, "INSERT INTO users (id, email, password_hash, password_salt, first_name, last_name, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
                  (user_id, email, pw_hash, salt, first, last, now, now))
                verify_token = create_email_token(conn, user_id, "verify_email", 48)
                set_json(conn, "profiles", user_id, {"firstName": first, "lastName": last, "name": (first+" "+last).strip(), "email": email, "bikes": []})
                conn.commit()
            except Exception as e:
                conn.rollback()
                msg = str(e).lower()
                if "unique" in msg or "duplicate" in msg:
                    return self._send(409, {"error": "An account with that email already exists."})
                print("signup error", e)
                return self._send(500, {"error": "Could not create account."})
        finally:
            conn.close()
        body = {"ok": True, "message": "Account created. Please verify your email to continue.",
                "user": {"id": user_id, "email": email, "firstName": first, "lastName": last, "emailVerified": False}}
        # Real email when Resend is configured and demo mode is off
        if RESEND_API_KEY and not DEMO_EMAIL:
            ok_send, detail = send_verification_email(email, verify_token)
            if not ok_send:
                body["message"] = "Account created, but the verification email could not be sent. Please try resend or contact support."
                body["emailError"] = True
                print("[email] signup send failed:", detail, flush=True)
            else:
                body["message"] = "Account created. Check your email for a verification link."
        else:
            # Demo / local testing path
            body["verificationToken"] = verify_token
            body["verificationPath"] = "biodrive-verify.html?token=" + verify_token + "&email=" + email
            print("[demo-email] token for", email, verify_token)
            if not RESEND_API_KEY:
                print("[email] RESEND_API_KEY not set — using demo verification link", flush=True)
        return self._send(201, body)
    def _login(self, data):
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or not password: return self._send(400, {"error": "Email and password are required."})
        conn = connect()
        try:
            row = one(q(conn, "SELECT * FROM users WHERE email = ?", (email,)))
            if not row or not verify_password(password, g(row,"password_hash"), g(row,"password_salt")):
                return self._send(401, {"error": "Invalid email or password."})
            if not g(row, "email_verified"):
                return self._send(403, {"error": "Email not verified.", "code": "EMAIL_NOT_VERIFIED", "email": g(row,"email")})
            uid = g(row, "id")
            token = create_session(conn, uid)
            conn.commit()
            return self._send(200, {"ok": True, "token": token, "user": user_public(row),
                                    "profile": get_json(conn, "profiles", uid), "powers": get_json(conn, "powers", uid)})
        finally:
            conn.close()
    def _logout(self):
        token = self._bearer()
        if token:
            conn = connect()
            try:
                q(conn, "DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
            finally:
                conn.close()
        return self._send(200, {"ok": True})
    def _verify(self, data):
        token = (data.get("token") or "").strip()
        if not token: return self._send(400, {"error": "Verification token is required."})
        now = time.time()
        conn = connect()
        try:
            row = one(q(conn, "SELECT * FROM email_tokens WHERE token = ? AND purpose = ?", (token, "verify_email")))
            if not row: return self._send(400, {"error": "Invalid verification link."})
            if g(row, "used_at") is not None: return self._send(400, {"error": "This verification link was already used."})
            if g(row, "expires_at") < now: return self._send(400, {"error": "This verification link has expired."})
            q(conn, "UPDATE email_tokens SET used_at = ? WHERE token = ?", (now, token))
            uid = g(row, "user_id")
            q(conn, "UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?", (now, uid))
            user = one(q(conn, "SELECT * FROM users WHERE id = ?", (uid,)))
            session = create_session(conn, uid)
            conn.commit()
            return self._send(200, {"ok": True, "message": "Email verified.", "token": session, "user": user_public(user),
                                    "profile": get_json(conn, "profiles", uid), "powers": get_json(conn, "powers", uid)})
        finally:
            conn.close()
    def _resend(self, data):
        email = (data.get("email") or "").strip().lower()
        if not email or not EMAIL_RE.match(email): return self._send(400, {"error": "Please enter a valid email."})
        body = {"ok": True, "message": "If that account exists and is unverified, a new link was issued."}
        conn = connect()
        try:
            user = one(q(conn, "SELECT * FROM users WHERE email = ?", (email,)))
            if user and not g(user, "email_verified"):
                token = create_email_token(conn, g(user, "id"), "verify_email", 48)
                conn.commit()
                if RESEND_API_KEY and not DEMO_EMAIL:
                    ok_send, detail = send_verification_email(email, token)
                    if not ok_send:
                        print("[email] resend failed:", detail, flush=True)
                else:
                    body["verificationToken"] = token
                    body["verificationPath"] = "biodrive-verify.html?token=" + token + "&email=" + email
        finally:
            conn.close()
        return self._send(200, body)

def main():
    print("Starting BioDrive API... USE_PG=%s PORT=%s" % (USE_PG, PORT))
    try:
        init_db()
    except Exception as e:
        print("FATAL database init:", type(e).__name__, e)
        raise
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Listening on http://%s:%s" % (HOST, PORT))
    httpd.serve_forever()

if __name__ == "__main__":
    main()
