#!/usr/bin/env python3
"""BioDrive API — auth + profile/powers. SQLite by default; Postgres if DATABASE_URL is set."""
from __future__ import annotations
import hashlib, json, os, re, secrets, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = os.environ.get("BD_HOST") or os.environ.get("HOST") or "0.0.0.0"
PORT = int(os.environ.get("BD_PORT") or os.environ.get("PORT") or "8787")
DATABASE_URL = (os.environ.get("DATABASE_URL") or os.environ.get("BD_DATABASE_URL") or "").strip()
DB_PATH = os.environ.get("BD_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "biodrive.db"))
CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "BD_CORS_ORIGINS",
    "http://localhost:5500,http://127.0.0.1:5500,https://biodrivecycling.com,https://www.biodrivecycling.com,null"
).split(",") if o.strip()]
DEMO_EMAIL = os.environ.get("BD_DEMO_EMAIL", "1") == "1"
SESSION_DAYS = int(os.environ.get("BD_SESSION_DAYS", "30"))
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

USE_PG = bool(DATABASE_URL)

if USE_PG:
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError as e:
        raise SystemExit("DATABASE_URL is set but psycopg2 is not installed. pip install psycopg2-binary") from e

class DbConn:
    """Tiny wrapper so call sites can use ? placeholders for both engines."""
    def __init__(self, raw, pg=False):
        self.raw = raw
        self.pg = pg
    def execute(self, sql, params=None):
        if self.pg:
            sql = sql.replace("?", "%s")
            # ON CONFLICT for sqlite uses excluded.; same in PG
            cur = self.raw.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(sql, params or ())
            return cur
        else:
            return self.raw.execute(sql, params or ())
    def executescript(self, script):
        if self.pg:
            cur = self.raw.cursor()
            cur.execute(script)
            return cur
        return self.raw.executescript(script)
    def commit(self):
        self.raw.commit()
    def close(self):
        self.raw.close()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        try:
            self.raw.commit()
        except Exception:
            try:
                self.raw.rollback()
            except Exception:
                pass
        self.raw.close()

def db():
    if USE_PG:
        # Render/Neon sometimes use postgres://
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        raw = psycopg2.connect(url)
        return DbConn(raw, pg=True)
    else:
        import sqlite3
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        raw = sqlite3.connect(DB_PATH)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys = ON")
        return DbConn(raw, pg=False)

def fetchone(cur):
    row = cur.fetchone()
    if row is None:
        return None
    if USE_PG:
        return row  # RealDictCursor already dict-like
    return row

def init_db():
    if USE_PG:
        ddl = """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              password_salt TEXT NOT NULL,
              first_name TEXT NOT NULL DEFAULT '',
              last_name TEXT NOT NULL DEFAULT '',
              email_verified INTEGER NOT NULL DEFAULT 0,
              created_at DOUBLE PRECISION NOT NULL,
              updated_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at DOUBLE PRECISION NOT NULL,
              expires_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS email_tokens (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              purpose TEXT NOT NULL,
              created_at DOUBLE PRECISION NOT NULL,
              expires_at DOUBLE PRECISION NOT NULL,
              used_at DOUBLE PRECISION
            );
            CREATE TABLE IF NOT EXISTS profiles (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}',
              updated_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS powers (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}',
              updated_at DOUBLE PRECISION NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        """
    else:
        ddl = """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              email TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL,
              password_salt TEXT NOT NULL,
              first_name TEXT NOT NULL DEFAULT '',
              last_name TEXT NOT NULL DEFAULT '',
              email_verified INTEGER NOT NULL DEFAULT 0,
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at REAL NOT NULL,
              expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS email_tokens (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              purpose TEXT NOT NULL,
              created_at REAL NOT NULL,
              expires_at REAL NOT NULL,
              used_at REAL
            );
            CREATE TABLE IF NOT EXISTS profiles (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}',
              updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS powers (
              user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data_json TEXT NOT NULL DEFAULT '{}',
              updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens(user_id);
        """
    with db() as conn:
        if USE_PG:
            cur = conn.raw.cursor()
            cur.execute(ddl)
        else:
            conn.executescript(ddl)
    print("DB ready:", "Postgres" if USE_PG else ("SQLite " + DB_PATH))

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return dk.hex(), salt.hex()

def verify_password(password, password_hash, salt_hex):
    try:
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return secrets.compare_digest(dk.hex(), password_hash)
    except Exception:
        return False

def strong_password(password):
    if len(password) < 8: return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password): return "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password): return "Password must include a lowercase letter."
    if not re.search(r"[0-9]", password): return "Password must include a number."
    return None

def row_get(row, key):
    if row is None: return None
    try:
        return row[key]
    except Exception:
        return row.get(key)

def user_public(row):
    return {
        "id": row_get(row, "id"),
        "email": row_get(row, "email"),
        "firstName": row_get(row, "first_name"),
        "lastName": row_get(row, "last_name"),
        "emailVerified": bool(row_get(row, "email_verified")),
        "createdAt": row_get(row, "created_at"),
    }

def create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now, now + SESSION_DAYS * 86400),
    )
    return token

def create_email_token(conn, user_id, purpose, hours=48):
    token = secrets.token_urlsafe(24)
    now = time.time()
    conn.execute(
        "INSERT INTO email_tokens (token, user_id, purpose, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)",
        (token, user_id, purpose, now, now + hours * 3600),
    )
    return token

def session_user(conn, token):
    if not token: return None
    cur = conn.execute(
        "SELECT u.id, u.email, u.password_hash, u.password_salt, u.first_name, u.last_name, u.email_verified, u.created_at, u.updated_at "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?",
        (token, time.time()),
    )
    return fetchone(cur)

def get_profile_json(conn, user_id):
    cur = conn.execute("SELECT data_json FROM profiles WHERE user_id = ?", (user_id,))
    row = fetchone(cur)
    if not row: return {}
    try:
        data = json.loads(row_get(row, "data_json") or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def set_profile_json(conn, user_id, data):
    now = time.time()
    payload = json.dumps(data if isinstance(data, dict) else {})
    if USE_PG:
        conn.execute(
            """INSERT INTO profiles (user_id, data_json, updated_at) VALUES (?, ?, ?)
               ON CONFLICT (user_id) DO UPDATE SET data_json = EXCLUDED.data_json, updated_at = EXCLUDED.updated_at""",
            (user_id, payload, now),
        )
    else:
        conn.execute(
            """INSERT INTO profiles (user_id, data_json, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at""",
            (user_id, payload, now),
        )
    return now

def get_powers_json(conn, user_id):
    cur = conn.execute("SELECT data_json FROM powers WHERE user_id = ?", (user_id,))
    row = fetchone(cur)
    if not row: return {}
    try:
        data = json.loads(row_get(row, "data_json") or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def set_powers_json(conn, user_id, data):
    now = time.time()
    payload = json.dumps(data if isinstance(data, dict) else {})
    if USE_PG:
        conn.execute(
            """INSERT INTO powers (user_id, data_json, updated_at) VALUES (?, ?, ?)
               ON CONFLICT (user_id) DO UPDATE SET data_json = EXCLUDED.data_json, updated_at = EXCLUDED.updated_at""",
            (user_id, payload, now),
        )
    else:
        conn.execute(
            """INSERT INTO powers (user_id, data_json, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at""",
            (user_id, payload, now),
        )
    return now

class Handler(BaseHTTPRequestHandler):
    server_version = "BioDriveAPI/2.1"
    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))
    def _cors(self):
        origin = self.headers.get("Origin", "")
        allow = None
        if origin in CORS_ORIGINS or origin == "null": allow = origin if origin else "*"
        elif origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"): allow = origin
        elif not origin: allow = "*"
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Vary", "Origin")
    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0: return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    def _bearer(self):
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "): return auth[7:].strip()
        return None
    def _send(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._send(200, {
                "ok": True,
                "service": "biodrive-auth",
                "version": 2.1,
                "demoEmail": DEMO_EMAIL,
                "database": "postgres" if USE_PG else "sqlite",
            })
        if path == "/api/auth/me":
            with db() as conn:
                user = session_user(conn, self._bearer())
                if not user: return self._send(401, {"error": "Not authenticated."})
                uid = row_get(user, "id")
                return self._send(200, {"user": user_public(user), "profile": get_profile_json(conn, uid), "powers": get_powers_json(conn, uid)})
        if path == "/api/profile":
            with db() as conn:
                user = session_user(conn, self._bearer())
                if not user: return self._send(401, {"error": "Not authenticated."})
                return self._send(200, {"profile": get_profile_json(conn, row_get(user, "id"))})
        if path == "/api/powers":
            with db() as conn:
                user = session_user(conn, self._bearer())
                if not user: return self._send(401, {"error": "Not authenticated."})
                return self._send(200, {"powers": get_powers_json(conn, row_get(user, "id"))})
        return self._send(404, {"error": "Not found."})
    def do_PUT(self):
        path = urlparse(self.path).path
        data = self._read_json()
        if path == "/api/profile": return self._put_profile(data)
        if path == "/api/powers": return self._put_powers(data)
        return self._send(404, {"error": "Not found."})
    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_json()
        if path == "/api/auth/signup": return self._signup(data)
        if path == "/api/auth/login": return self._login(data)
        if path == "/api/auth/logout": return self._logout()
        if path == "/api/auth/verify": return self._verify(data)
        if path == "/api/auth/resend-verification": return self._resend(data)
        if path == "/api/profile": return self._put_profile(data)
        if path == "/api/powers": return self._put_powers(data)
        return self._send(404, {"error": "Not found."})
    def _put_profile(self, data):
        with db() as conn:
            user = session_user(conn, self._bearer())
            if not user: return self._send(401, {"error": "Not authenticated."})
            profile = data.get("profile") if isinstance(data.get("profile"), dict) else data
            if not isinstance(profile, dict): return self._send(400, {"error": "Profile must be a JSON object."})
            first = (profile.get("firstName") or "").strip()
            last = (profile.get("lastName") or "").strip()
            uid = row_get(user, "id")
            if first or last:
                conn.execute(
                    "UPDATE users SET first_name = CASE WHEN ? = '' THEN first_name ELSE ? END, last_name = CASE WHEN ? = '' THEN last_name ELSE ? END, updated_at = ? WHERE id = ?",
                    (first, first, last, last, time.time(), uid),
                )
            set_profile_json(conn, uid, profile)
            return self._send(200, {"ok": True, "profile": get_profile_json(conn, uid)})
    def _put_powers(self, data):
        with db() as conn:
            user = session_user(conn, self._bearer())
            if not user: return self._send(401, {"error": "Not authenticated."})
            powers = data.get("powers") if isinstance(data.get("powers"), dict) else data
            if not isinstance(powers, dict): return self._send(400, {"error": "Powers must be a JSON object."})
            uid = row_get(user, "id")
            set_powers_json(conn, uid, powers)
            return self._send(200, {"ok": True, "powers": get_powers_json(conn, uid)})

    def _signup(self, data):
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        first = (data.get("firstName") or "").strip()
        last = (data.get("lastName") or "").strip()
        if not first: return self._send(400, {"error": "First name is required."})
        if not last: return self._send(400, {"error": "Last name is required."})
        if not email or not EMAIL_RE.match(email): return self._send(400, {"error": "Please enter a valid email."})
        pw_err = strong_password(password)
        if pw_err: return self._send(400, {"error": pw_err})
        pw_hash, salt = hash_password(password)
        user_id = "usr_" + secrets.token_hex(12)
        now = time.time()
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, password_salt, first_name, last_name, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
                    (user_id, email, pw_hash, salt, first, last, now, now),
                )
                verify_token = create_email_token(conn, user_id, "verify_email", hours=48)
                set_profile_json(conn, user_id, {"firstName": first, "lastName": last, "name": (first + " " + last).strip(), "email": email, "bikes": []})
        except Exception as e:
            msg = str(e).lower()
            if "unique" in msg or "duplicate" in msg or "integrity" in msg:
                return self._send(409, {"error": "An account with that email already exists."})
            print("signup error", e)
            return self._send(500, {"error": "Could not create account."})
        body = {"ok": True, "message": "Account created. Please verify your email to continue.", "user": {"id": user_id, "email": email, "firstName": first, "lastName": last, "emailVerified": False}}
        if DEMO_EMAIL:
            body["verificationToken"] = verify_token
            body["verificationPath"] = "biodrive-verify.html?token=" + verify_token
            print("[demo-email] Verify token for %s: %s" % (email, verify_token))
        return self._send(201, body)

    def _login(self, data):
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or not password: return self._send(400, {"error": "Email and password are required."})
        with db() as conn:
            cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = fetchone(cur)
            if not row or not verify_password(password, row_get(row, "password_hash"), row_get(row, "password_salt")):
                return self._send(401, {"error": "Invalid email or password."})
            if not row_get(row, "email_verified"):
                return self._send(403, {"error": "Email not verified.", "code": "EMAIL_NOT_VERIFIED", "email": row_get(row, "email")})
            uid = row_get(row, "id")
            token = create_session(conn, uid)
            return self._send(200, {"ok": True, "token": token, "user": user_public(row), "profile": get_profile_json(conn, uid), "powers": get_powers_json(conn, uid)})

    def _logout(self):
        token = self._bearer()
        if token:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        return self._send(200, {"ok": True})

    def _verify(self, data):
        token = (data.get("token") or "").strip()
        if not token: return self._send(400, {"error": "Verification token is required."})
        now = time.time()
        with db() as conn:
            cur = conn.execute("SELECT * FROM email_tokens WHERE token = ? AND purpose = ?", (token, "verify_email"))
            row = fetchone(cur)
            if not row: return self._send(400, {"error": "Invalid verification link."})
            if row_get(row, "used_at") is not None: return self._send(400, {"error": "This verification link was already used."})
            if row_get(row, "expires_at") < now: return self._send(400, {"error": "This verification link has expired."})
            conn.execute("UPDATE email_tokens SET used_at = ? WHERE token = ?", (now, token))
            uid = row_get(row, "user_id")
            conn.execute("UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?", (now, uid))
            cur = conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
            user = fetchone(cur)
            session = create_session(conn, uid)
            return self._send(200, {"ok": True, "message": "Email verified.", "token": session, "user": user_public(user), "profile": get_profile_json(conn, uid), "powers": get_powers_json(conn, uid)})

    def _resend(self, data):
        email = (data.get("email") or "").strip().lower()
        if not email or not EMAIL_RE.match(email): return self._send(400, {"error": "Please enter a valid email."})
        with db() as conn:
            cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = fetchone(cur)
            body = {"ok": True, "message": "If that account exists and is unverified, a new link was issued."}
            if user and not row_get(user, "email_verified"):
                token = create_email_token(conn, row_get(user, "id"), "verify_email", hours=48)
                if DEMO_EMAIL:
                    body["verificationToken"] = token
                    body["verificationPath"] = "biodrive-verify.html?token=" + token
            return self._send(200, body)

def main():
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("BioDrive API listening on http://%s:%s" % (HOST, PORT))
    print("  Database:", "Postgres" if USE_PG else DB_PATH)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.server_close()

if __name__ == "__main__":
    main()
