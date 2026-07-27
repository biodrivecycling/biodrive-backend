#!/usr/bin/env python3
"""BioDrive Auth API — stdlib only."""
from __future__ import annotations
import hashlib, json, os, re, secrets, sqlite3, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = os.environ.get("BD_HOST") or os.environ.get("HOST") or "0.0.0.0"
PORT = int(os.environ.get("BD_PORT") or os.environ.get("PORT") or "8787")
DB_PATH = os.environ.get("BD_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "biodrive.db"))
CORS_ORIGINS = [o.strip() for o in os.environ.get("BD_CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500,null").split(",") if o.strip()]
DEMO_EMAIL = os.environ.get("BD_DEMO_EMAIL", "1") == "1"
SESSION_DAYS = int(os.environ.get("BD_SESSION_DAYS", "30"))
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as conn:
        conn.executescript("""
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
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens(user_id);
        """)

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

def user_public(row):
    return {"id": row["id"], "email": row["email"], "firstName": row["first_name"], "lastName": row["last_name"], "emailVerified": bool(row["email_verified"]), "createdAt": row["created_at"]}

def create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", (token, user_id, now, now + SESSION_DAYS * 86400))
    return token

def create_email_token(conn, user_id, purpose, hours=48):
    token = secrets.token_urlsafe(24)
    now = time.time()
    conn.execute("INSERT INTO email_tokens (token, user_id, purpose, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)", (token, user_id, purpose, now, now + hours * 3600))
    return token

def session_user(conn, token):
    if not token: return None
    return conn.execute("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?", (token, time.time())).fetchone()

class Handler(BaseHTTPRequestHandler):
    server_version = "BioDriveAuth/1.0"
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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
            return self._send(200, {"ok": True, "service": "biodrive-auth", "demoEmail": DEMO_EMAIL})
        if path == "/api/auth/me":
            with db() as conn:
                user = session_user(conn, self._bearer())
                if not user: return self._send(401, {"error": "Not authenticated."})
                return self._send(200, {"user": user_public(user)})
        return self._send(404, {"error": "Not found."})
    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_json()
        if path == "/api/auth/signup": return self._signup(data)
        if path == "/api/auth/login": return self._login(data)
        if path == "/api/auth/logout": return self._logout()
        if path == "/api/auth/verify": return self._verify(data)
        if path == "/api/auth/resend-verification": return self._resend(data)
        return self._send(404, {"error": "Not found."})

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
                conn.execute("INSERT INTO users (id, email, password_hash, password_salt, first_name, last_name, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)", (user_id, email, pw_hash, salt, first, last, now, now))
                verify_token = create_email_token(conn, user_id, "verify_email", hours=48)
        except sqlite3.IntegrityError:
            return self._send(409, {"error": "An account with that email already exists."})
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
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not row or not verify_password(password, row["password_hash"], row["password_salt"]):
                return self._send(401, {"error": "Invalid email or password."})
            if not row["email_verified"]:
                return self._send(403, {"error": "Email not verified.", "code": "EMAIL_NOT_VERIFIED", "email": row["email"]})
            token = create_session(conn, row["id"])
            return self._send(200, {"ok": True, "token": token, "user": user_public(row)})
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
            row = conn.execute("SELECT * FROM email_tokens WHERE token = ? AND purpose = ?", (token, "verify_email")).fetchone()
            if not row: return self._send(400, {"error": "Invalid verification link."})
            if row["used_at"] is not None: return self._send(400, {"error": "This verification link was already used."})
            if row["expires_at"] < now: return self._send(400, {"error": "This verification link has expired."})
            conn.execute("UPDATE email_tokens SET used_at = ? WHERE token = ?", (now, token))
            conn.execute("UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?", (now, row["user_id"]))
            user = conn.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
            session = create_session(conn, row["user_id"])
            return self._send(200, {"ok": True, "message": "Email verified.", "token": session, "user": user_public(user)})
    def _resend(self, data):
        email = (data.get("email") or "").strip().lower()
        if not email or not EMAIL_RE.match(email): return self._send(400, {"error": "Please enter a valid email."})
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            body = {"ok": True, "message": "If that account exists and is unverified, a new link was issued."}
            if user and not user["email_verified"]:
                token = create_email_token(conn, user["id"], "verify_email", hours=48)
                if DEMO_EMAIL:
                    body["verificationToken"] = token
                    body["verificationPath"] = "biodrive-verify.html?token=" + token
            return self._send(200, body)

def main():
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("BioDrive auth API listening on http://%s:%s" % (HOST, PORT))
    print("  DB: %s" % DB_PATH)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.server_close()

if __name__ == "__main__":
    main()
