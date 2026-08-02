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
ADMIN_KEY = (os.environ.get("BD_ADMIN_KEY") or "").strip()
ADMIN_NOTIFY_EMAIL = (os.environ.get("BD_ADMIN_NOTIFY_EMAIL") or "founders@biodrivecycling.com").strip()
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
            CREATE TABLE IF NOT EXISTS strategy_orders (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              status TEXT NOT NULL DEFAULT 'pending_payment',
              data_json TEXT NOT NULL DEFAULT '{}',
              created_at DOUBLE PRECISION NOT NULL,
              updated_at DOUBLE PRECISION NOT NULL);
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
            CREATE TABLE IF NOT EXISTS strategy_orders (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              status TEXT NOT NULL DEFAULT 'pending_payment',
              data_json TEXT NOT NULL DEFAULT '{}',
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL);
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




def send_password_reset_email(to_email, token):
    """Send password reset link via Resend. Returns (ok, detail)."""
    import ssl
    import urllib.error
    import urllib.request

    reset_url = APP_PUBLIC_URL + "/biodrive-reset-password.html?token=" + token + "&email=" + quote(to_email)
    subject = "Reset your BioDrive Cycling password"
    html = (
        "<p>We received a request to reset your BioDrive Cycling password.</p>"
        "<p>Click the link below to choose a new password:</p>"
        '<p><a href="%s">Reset my password</a></p>'
        "<p>Or copy this URL:</p><p>%s</p>"
        "<p>This link expires in 1 hour. If you did not request a reset, you can ignore this email.</p>"
    ) % (reset_url, reset_url)
    text = "Reset your BioDrive password: " + reset_url

    print("[email] preparing password-reset to=%s from=%s" % (to_email, EMAIL_FROM), flush=True)
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
            print("[email] password-reset sent ok to", to_email, "status", resp.status, body[:300], flush=True)
            return True, body
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(e)
        print("[email] password-reset FAILED HTTP", e.code, "to", to_email, detail, flush=True)
        return False, "HTTP %s: %s" % (e.code, detail)
    except Exception as e:
        print("[email] password-reset FAILED to", to_email, type(e).__name__, e, flush=True)
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


def list_orders(conn, user_id):
    cur = q(conn, "SELECT id, status, data_json, created_at, updated_at FROM strategy_orders WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    out = []
    while True:
        row = one(cur)
        if not row:
            break
        try:
            data = json.loads(g(row, "data_json") or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data["id"] = g(row, "id")
        data["status"] = g(row, "status") or data.get("status") or "pending_payment"
        ca = g(row, "created_at")
        if ca is not None and not data.get("createdAt"):
            try:
                data["createdAt"] = __import__("datetime").datetime.utcfromtimestamp(float(ca)).isoformat() + "Z"
            except Exception:
                data["createdAt"] = ca
        data["updatedAt"] = g(row, "updated_at")
        out.append(data)
    return out

def insert_order(conn, user_id, status, data):
    oid = "ord_" + secrets.token_hex(12)
    now = time.time()
    payload = dict(data) if isinstance(data, dict) else {}
    payload["id"] = oid
    payload["status"] = status
    q(conn, "INSERT INTO strategy_orders (id, user_id, status, data_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      (oid, user_id, status, json.dumps(payload), now, now))
    return oid, payload


def require_admin(handler):
    if not ADMIN_KEY:
        return False
    key = (handler.headers.get("X-Admin-Key") or "").strip()
    if not key:
        auth = handler.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
    if not key:
        # Allow ?key= for simple browser testing (and some proxies)
        try:
            from urllib.parse import parse_qs
            qs = parse_qs(urlparse(handler.path).query)
            key = (qs.get("key") or [""])[0].strip()
        except Exception:
            key = ""
    if not key:
        return False
    try:
        return secrets.compare_digest(key, ADMIN_KEY)
    except Exception:
        return False

def list_all_users(conn):
    cur = q(conn, "SELECT id, email, first_name, last_name, email_verified, created_at, updated_at FROM users ORDER BY created_at DESC")
    out = []
    while True:
        row = one(cur)
        if not row:
            break
        out.append({
            "id": g(row, "id"),
            "email": g(row, "email"),
            "firstName": g(row, "first_name"),
            "lastName": g(row, "last_name"),
            "emailVerified": bool(g(row, "email_verified")),
            "createdAt": g(row, "created_at"),
            "updatedAt": g(row, "updated_at"),
        })
    return out

def list_all_orders(conn):
    cur = q(conn, "SELECT id, user_id, status, data_json, created_at, updated_at FROM strategy_orders ORDER BY created_at DESC")
    out = []
    while True:
        row = one(cur)
        if not row:
            break
        try:
            data = json.loads(g(row, "data_json") or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        uid = g(row, "user_id")
        user = one(q(conn, "SELECT email, first_name, last_name FROM users WHERE id = ?", (uid,)))
        athlete = {}
        if user:
            athlete = {
                "email": g(user, "email"),
                "firstName": g(user, "first_name"),
                "lastName": g(user, "last_name"),
            }
        ca = g(row, "created_at")
        created_iso = data.get("createdAt")
        if ca is not None and not created_iso:
            try:
                created_iso = __import__("datetime").datetime.utcfromtimestamp(float(ca)).isoformat() + "Z"
            except Exception:
                created_iso = ca
        out.append({
            "id": g(row, "id"),
            "userId": uid,
            "status": g(row, "status") or data.get("status") or "pending_payment",
            "createdAt": created_iso,
            "updatedAt": g(row, "updated_at"),
            "athlete": athlete,
            "raceName": data.get("raceName") or "",
            "raceDate": data.get("raceDate") or "",
            "eventAddress": data.get("eventAddress") or data.get("raceLocation") or "",
            "services": data.get("services") or [],
            "service": data.get("service") or "",
            "estimatedTotal": data.get("estimatedTotal"),
            "coach": data.get("coach"),
            "email": data.get("email") or athlete.get("email") or "",
            "offerStatus": data.get("offerStatus") or None,
            "courseDataSource": data.get("courseDataSource") or "",
            "gpxObtainFee": data.get("gpxObtainFee") or 0,
            "gpxName": data.get("gpxName") or "",
            "data": data,
        })
    return out


def ensure_coaches_table(conn):
    try:
        q(conn, """CREATE TABLE IF NOT EXISTS coaches (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              email TEXT NOT NULL,
              magic_token TEXT NOT NULL UNIQUE,
              link_enabled INTEGER NOT NULL DEFAULT 1,
              created_at DOUBLE PRECISION NOT NULL,
              updated_at DOUBLE PRECISION NOT NULL)""")
        conn.commit()
    except Exception as e:
        print("[db] ensure_coaches_table", e, flush=True)

def send_simple_email(to_email, subject, html, text):
    import ssl, urllib.error, urllib.request
    print("[email] preparing simple to=%s subject=%s" % (to_email, subject), flush=True)
    if not RESEND_API_KEY:
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
            print("[email] simple sent ok", resp.status, body[:200], flush=True)
            return True, body
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(e)
        print("[email] simple FAILED", e.code, detail, flush=True)
        return False, detail
    except Exception as e:
        print("[email] simple ERROR", e, flush=True)
        return False, str(e)

def coach_by_token(conn, token):
    if not token:
        return None
    ensure_coaches_table(conn)
    return one(q(conn, "SELECT * FROM coaches WHERE magic_token = ?", (token,)))

def list_coaches(conn):
    ensure_coaches_table(conn)
    cur = q(conn, "SELECT * FROM coaches ORDER BY created_at DESC")
    out = []
    while True:
        row = one(cur)
        if not row:
            break
        out.append({
            "id": g(row, "id"),
            "name": g(row, "name"),
            "email": g(row, "email"),
            "magicToken": g(row, "magic_token"),
            "linkEnabled": bool(g(row, "link_enabled")),
            "magicLink": APP_PUBLIC_URL + "/biodrive-coach.html?key=" + g(row, "magic_token"),
            "createdAt": g(row, "created_at"),
        })
    return out

def order_row_to_coach_job(conn, row):
    try:
        data = json.loads(g(row, "data_json") or "{}")
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    uid = g(row, "user_id")
    user = one(q(conn, "SELECT email, first_name, last_name FROM users WHERE id = ?", (uid,)))
    profile = get_json(conn, "profiles", uid) or {}
    athlete_email = (user and g(user, "email")) or data.get("email") or ""
    first = (user and g(user, "first_name")) or profile.get("firstName") or ""
    last = (user and g(user, "last_name")) or profile.get("lastName") or ""
    offer = data.get("offerStatus") or None
    status = g(row, "status") or data.get("status") or "pending_payment"
    list_state = "new"
    if offer == "accepted":
        list_state = "ongoing"
    elif offer == "rejected":
        list_state = "rejected"
    elif offer == "done":
        list_state = "done"
    return {
        "id": g(row, "id"),
        "status": status,
        "offerStatus": offer,
        "listState": list_state,
        "raceName": data.get("raceName") or "",
        "raceDate": data.get("raceDate") or "",
        "raceTime": data.get("raceTime") or data.get("startTime") or "",
        "eventAddress": data.get("eventAddress") or data.get("raceLocation") or "",
        "services": data.get("services") or [],
        "service": data.get("service") or "",
        "estimatedTotal": data.get("estimatedTotal"),
        "coach": data.get("coach"),
        "athlete": {
            "firstName": first,
            "lastName": last,
            "email": athlete_email,
            "phone": profile.get("phone") or data.get("phone") or "",
            "preferredContact": profile.get("preferredContact") or data.get("preferredContact") or "",
        },
        "createdAt": data.get("createdAt") or g(row, "created_at"),
        "paidAt": data.get("paidAt"),
        "serviceDescriptions": {
            "2": "Rider guide plus a meeting with a coach before race day. From $300.",
            "3": "Live rider guide plus coach support on race day. From $1000.",
        },
    }

def list_coach_jobs(conn, coach):
    cid = g(coach, "id")
    cemail = (g(coach, "email") or "").strip().lower()
    cname = (g(coach, "name") or "").strip().lower()
    cur = q(conn, "SELECT * FROM strategy_orders ORDER BY created_at DESC")
    out = []
    while True:
        row = one(cur)
        if not row:
            break
        try:
            data = json.loads(g(row, "data_json") or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        status = (g(row, "status") or data.get("status") or "").lower()
        if status in ("pending_payment", "pending", ""):
            continue
        coach_data = data.get("coach") or {}
        assigned_id = data.get("coachId") or (coach_data.get("id") if isinstance(coach_data, dict) else None)
        assigned_email = ""
        assigned_name = ""
        if isinstance(coach_data, dict):
            assigned_email = (coach_data.get("email") or "").strip().lower()
            assigned_name = (coach_data.get("displayName") or coach_data.get("name") or "").strip().lower()
        if assigned_id != cid and assigned_email != cemail and assigned_name != cname:
            continue
        out.append(order_row_to_coach_job(conn, row))
    return out

def load_order(conn, order_id):
    return one(q(conn, "SELECT * FROM strategy_orders WHERE id = ?", (order_id,)))

def save_order_data(conn, order_id, data, status=None):
    now = time.time()
    if status is not None:
        q(conn, "UPDATE strategy_orders SET data_json = ?, status = ?, updated_at = ? WHERE id = ?",
          (json.dumps(data), status, now, order_id))
    else:
        q(conn, "UPDATE strategy_orders SET data_json = ?, updated_at = ? WHERE id = ?",
          (json.dumps(data), now, order_id))

class Handler(BaseHTTPRequestHandler):
    server_version = "BioDriveAPI/2.9"
    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))
    def _cors(self):
        origin = self.headers.get("Origin", "") or ""
        allow = None
        if origin in CORS_ORIGINS or origin == "null":
            allow = origin or "*"
        elif origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
            allow = origin
        elif origin.endswith("biodrivecycling.com") or origin.endswith(".netlify.app"):
            allow = origin
        elif not origin:
            allow = "*"
        else:
            # Still reflect known public site if env list is incomplete
            allow = origin if "biodrive" in origin.lower() else None
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key, X-Coach-Key")
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
            return self._send(200, {"ok": True, "service": "biodrive-auth", "version": 2.9, "demoEmail": DEMO_EMAIL, "emailConfigured": bool(RESEND_API_KEY), "adminConfigured": bool(ADMIN_KEY), "emailFrom": EMAIL_FROM, "database": "postgres" if USE_PG else "sqlite"})
        if path == "/api/email-status":
            result = check_resend_api()
            return self._send(200 if result.get("ok") else 502, {"emailFrom": EMAIL_FROM, "demoEmail": DEMO_EMAIL, "resend": result})
        if path in ("/api/auth/me", "/api/profile", "/api/powers", "/api/orders"):
            conn = connect()
            try:
                user = session_user(conn, self._bearer())
                if not user: return self._send(401, {"error": "Not authenticated."})
                uid = g(user, "id")
                if path == "/api/auth/me":
                    return self._send(200, {"user": user_public(user), "profile": get_json(conn, "profiles", uid), "powers": get_json(conn, "powers", uid), "orders": list_orders(conn, uid)})
                if path == "/api/profile":
                    return self._send(200, {"profile": get_json(conn, "profiles", uid)})
                if path == "/api/powers":
                    return self._send(200, {"powers": get_json(conn, "powers", uid)})
                if path == "/api/orders":
                    return self._send(200, {"orders": list_orders(conn, uid)})
                return self._send(404, {"error": "Not found."})
            finally:
                conn.close()
        if path in ("/api/admin/users", "/api/admin/orders", "/api/admin/summary", "/api/admin/coaches"):
            if not ADMIN_KEY:
                return self._send(503, {"error": "Admin is not configured. Set BD_ADMIN_KEY on the server."})
            if not require_admin(self):
                return self._send(401, {"error": "Invalid or missing admin key."})
            conn = connect()
            try:
                try:
                    if path == "/api/admin/users":
                        return self._send(200, {"users": list_all_users(conn)})
                    if path == "/api/admin/orders":
                        return self._send(200, {"orders": list_all_orders(conn)})
                    if path == "/api/admin/coaches":
                        return self._send(200, {"coaches": list_coaches(conn)})
                    users = list_all_users(conn)
                    orders = list_all_orders(conn)
                    try:
                        coaches = list_coaches(conn)
                    except Exception as ce:
                        print("[admin] list_coaches error", ce, flush=True)
                        coaches = []
                    pending_payment = sum(1 for o in orders if (o.get("status") or "").startswith("pending_payment"))
                    pending_offers = sum(1 for o in orders if (o.get("offerStatus") or "") in ("offered", "pending"))
                    return self._send(200, {
                        "summary": {
                            "userCount": len(users),
                            "orderCount": len(orders),
                            "pendingPaymentCount": pending_payment,
                            "pendingOfferCount": pending_offers,
                            "coachCount": len(coaches),
                        },
                        "users": users,
                        "orders": orders,
                        "coaches": coaches,
                    })
                except Exception as e:
                    print("[admin] error", type(e).__name__, e, flush=True)
                    return self._send(500, {"error": "Admin error: %s: %s" % (type(e).__name__, e)})
            finally:
                conn.close()
        if path == "/api/coach/jobs":
            from urllib.parse import parse_qs
            params = parse_qs(urlparse(self.path).query)
            token = (params.get("key") or [""])[0].strip()
            if not token:
                token = (self.headers.get("X-Coach-Key") or "").strip()
            conn = connect()
            try:
                coach = coach_by_token(conn, token)
                if not coach:
                    return self._send(401, {"error": "Invalid coach link."})
                if not g(coach, "link_enabled"):
                    return self._send(403, {"error": "This coach link has been disabled by BioDrive admin."})
                jobs = list_coach_jobs(conn, coach)
                return self._send(200, {
                    "coach": {"id": g(coach, "id"), "name": g(coach, "name"), "email": g(coach, "email")},
                    "jobs": jobs,
                })
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
        if path == "/api/auth/forgot-password": return self._forgot_password(data)
        if path == "/api/auth/reset-password": return self._reset_password(data)
        if path in ("/api/profile", "/api/powers"): return self._write(path, data)
        if path == "/api/orders": return self._create_order(data)
        if path == "/api/admin/coaches": return self._admin_create_coach(data)
        if path == "/api/admin/coaches/toggle": return self._admin_toggle_coach(data)
        if path == "/api/admin/orders/mark-paid": return self._admin_mark_paid(data)
        if path == "/api/coach/accept": return self._coach_respond(data, accept=True)
        if path == "/api/coach/reject": return self._coach_respond(data, accept=False)
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



    def _admin_create_coach(self, data):
        if not ADMIN_KEY:
            return self._send(503, {"error": "Admin is not configured."})
        if not require_admin(self):
            return self._send(401, {"error": "Invalid or missing admin key."})
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        if not name or not email or not EMAIL_RE.match(email):
            return self._send(400, {"error": "Name and valid email are required."})
        conn = connect()
        try:
            try:
                ensure_coaches_table(conn)
                cid = "coach_" + secrets.token_hex(8)
                token = secrets.token_urlsafe(32)
                now = time.time()
                q(conn, "INSERT INTO coaches (id, name, email, magic_token, link_enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (cid, name, email, token, 1, now, now))
                conn.commit()
                link = APP_PUBLIC_URL + "/biodrive-coach.html?key=" + token
                if RESEND_API_KEY and not DEMO_EMAIL:
                    html = "<p>Hi %s,</p><p>Your BioDrive coach access link:</p><p><a href='%s'>%s</a></p><p>Keep this link private. BioDrive admin can disable it at any time.</p>" % (name, link, link)
                    try:
                        send_simple_email(email, "Your BioDrive coach access", html, "Your BioDrive coach link: " + link)
                    except Exception as ee:
                        print("[email] coach onboard", ee, flush=True)
                return self._send(201, {"ok": True, "coach": {
                    "id": cid, "name": name, "email": email, "magicToken": token,
                    "linkEnabled": True, "magicLink": link,
                }, "coaches": list_coaches(conn)})
            except Exception as e:
                print("[admin] create coach", type(e).__name__, e, flush=True)
                return self._send(500, {"error": "Could not create coach: %s: %s" % (type(e).__name__, e)})
        finally:
            conn.close()

    def _admin_toggle_coach(self, data):
        if not ADMIN_KEY or not require_admin(self):
            return self._send(401, {"error": "Invalid or missing admin key."})
        cid = (data.get("id") or "").strip()
        enabled = data.get("linkEnabled")
        if not cid or enabled is None:
            return self._send(400, {"error": "id and linkEnabled are required."})
        conn = connect()
        try:
            ensure_coaches_table(conn)
            row = one(q(conn, "SELECT * FROM coaches WHERE id = ?", (cid,)))
            if not row:
                return self._send(404, {"error": "Coach not found."})
            val = 1 if enabled else 0
            q(conn, "UPDATE coaches SET link_enabled = ?, updated_at = ? WHERE id = ?", (val, time.time(), cid))
            conn.commit()
            return self._send(200, {"ok": True, "coaches": list_coaches(conn)})
        finally:
            conn.close()

    def _admin_mark_paid(self, data):
        if not ADMIN_KEY or not require_admin(self):
            return self._send(401, {"error": "Invalid or missing admin key."})
        oid = (data.get("id") or data.get("orderId") or "").strip()
        if not oid:
            return self._send(400, {"error": "Order id is required."})
        conn = connect()
        try:
            row = load_order(conn, oid)
            if not row:
                return self._send(404, {"error": "Order not found."})
            try:
                payload = json.loads(g(row, "data_json") or "{}")
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            payload["status"] = "paid"
            payload["paidAt"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
            # Open coach offer if coach assigned
            coach = payload.get("coach")
            if coach and payload.get("offerStatus") not in ("accepted", "rejected", "done"):
                payload["offerStatus"] = "offered"
            save_order_data(conn, oid, payload, status="paid")
            conn.commit()
            # Notify coach if we can match
            if coach and RESEND_API_KEY and not DEMO_EMAIL:
                cemail = ""
                cname = ""
                if isinstance(coach, dict):
                    cemail = (coach.get("email") or "").strip()
                    cname = coach.get("displayName") or coach.get("name") or "Coach"
                if cemail:
                    # Prefer magic link from coaches table by email
                    crow = one(q(conn, "SELECT * FROM coaches WHERE email = ?", (cemail.lower(),)))
                    link = APP_PUBLIC_URL + "/biodrive-coach.html"
                    if crow:
                        link = APP_PUBLIC_URL + "/biodrive-coach.html?key=" + g(crow, "magic_token")
                    html = "<p>Hi %s,</p><p>A BioDrive athlete request is ready for you (paid).</p><p><a href='%s'>Open your coach jobs</a></p>" % (cname, link)
                    send_simple_email(cemail, "New BioDrive coaching request", html, "Open your jobs: " + link)
            return self._send(200, {"ok": True, "orders": list_all_orders(conn)})
        finally:
            conn.close()

    def _coach_respond(self, data, accept=True):
        token = (data.get("key") or data.get("token") or "").strip()
        oid = (data.get("orderId") or data.get("id") or "").strip()
        if not token or not oid:
            return self._send(400, {"error": "key and orderId are required."})
        conn = connect()
        try:
            coach = coach_by_token(conn, token)
            if not coach:
                return self._send(401, {"error": "Invalid coach link."})
            if not g(coach, "link_enabled"):
                return self._send(403, {"error": "This coach link has been disabled."})
            row = load_order(conn, oid)
            if not row:
                return self._send(404, {"error": "Job not found."})
            try:
                payload = json.loads(g(row, "data_json") or "{}")
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            status = (g(row, "status") or "").lower()
            if status == "pending_payment":
                return self._send(403, {"error": "This request is not paid yet."})
            # ownership check (id, email, or display name — same rules as job list)
            cemail = (g(coach, "email") or "").strip().lower()
            cname = (g(coach, "name") or "").strip().lower()
            cid = g(coach, "id")
            coach_data = payload.get("coach") or {}
            assigned_email = ""
            assigned_name = ""
            assigned_id = payload.get("coachId")
            if isinstance(coach_data, dict):
                assigned_email = (coach_data.get("email") or "").strip().lower()
                assigned_name = (coach_data.get("displayName") or coach_data.get("name") or "").strip().lower()
                if not assigned_id:
                    assigned_id = coach_data.get("id")
            if assigned_id != cid and assigned_email != cemail and assigned_name != cname:
                return self._send(403, {"error": "This job is not assigned to you."})
            if accept:
                payload["offerStatus"] = "accepted"
                payload["acceptedAt"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
            else:
                payload["offerStatus"] = "rejected"
                payload["rejectedAt"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
                # Email admin only
                if RESEND_API_KEY and not DEMO_EMAIL:
                    race = payload.get("raceName") or "Race request"
                    athlete = payload.get("email") or ""
                    html = (
                        "<p>A coach rejected a BioDrive offer.</p>"
                        "<p><strong>Coach:</strong> %s (%s)</p>"
                        "<p><strong>Race:</strong> %s</p>"
                        "<p><strong>Athlete email:</strong> %s</p>"
                        "<p><strong>Order:</strong> %s</p>"
                        "<p>Please help the athlete find another coach.</p>"
                    ) % (g(coach, "name"), g(coach, "email"), race, athlete, oid)
                    send_simple_email(
                        ADMIN_NOTIFY_EMAIL,
                        "Coach rejected offer — " + race,
                        html,
                        "Coach %s rejected order %s (%s)" % (g(coach, "name"), oid, race),
                    )
            save_order_data(conn, oid, payload)
            conn.commit()
            return self._send(200, {"ok": True, "jobs": list_coach_jobs(conn, coach)})
        finally:
            conn.close()

    def _create_order(self, data):
        conn = connect()
        try:
            user = session_user(conn, self._bearer())
            if not user:
                return self._send(401, {"error": "Not authenticated."})
            uid = g(user, "id")
            order_data = data.get("order") if isinstance(data.get("order"), dict) else data
            if not isinstance(order_data, dict):
                return self._send(400, {"error": "Order must be a JSON object."})
            # Strip client id/status if any; server owns them for new rows
            order_data = dict(order_data)
            order_data.pop("id", None)
            status = (order_data.get("status") or "pending_payment").strip() or "pending_payment"
            # No real payment yet — normalize paid-looking statuses
            if status in ("paid", "complete", "completed"):
                status = "pending_payment"
            if status not in ("pending_payment", "pending_review", "in_progress", "delivered", "cancelled"):
                status = "pending_payment"
            oid, payload = insert_order(conn, uid, status, order_data)
            conn.commit()
            print("[order] created", oid, "user", uid, "status", status, flush=True)
            return self._send(201, {"ok": True, "order": payload, "orders": list_orders(conn, uid)})
        finally:
            conn.close()

    def _forgot_password(self, data):
        email = (data.get("email") or "").strip().lower()
        if not email or not EMAIL_RE.match(email):
            return self._send(400, {"error": "Please enter a valid email."})
        conn = connect()
        try:
            user = one(q(conn, "SELECT * FROM users WHERE email = ?", (email,)))
            if not user:
                print("[email] forgot-password: no user for", email, flush=True)
                return self._send(404, {
                    "ok": False,
                    "error": "We could not find an account with that email. Check the spelling or sign up.",
                    "code": "NO_ACCOUNT",
                })
            if not g(user, "email_verified"):
                print("[email] forgot-password: unverified user", email, flush=True)
                return self._send(403, {
                    "ok": False,
                    "error": "That account exists but the email is not verified yet. Please verify your email first (or sign up again).",
                    "code": "EMAIL_NOT_VERIFIED",
                })
            token = create_email_token(conn, g(user, "id"), "reset_password", hours=1)
            conn.commit()
            body = {
                "ok": True,
                "exists": True,
                "message": "We found your account. A password reset link is on its way to " + email + ". Check your inbox and spam folder.",
            }
            if RESEND_API_KEY and not DEMO_EMAIL:
                ok_send, detail = send_password_reset_email(email, token)
                if not ok_send:
                    print("[email] forgot-password send failed:", detail, flush=True)
                    return self._send(502, {"error": "We found your account, but the reset email could not be sent. Please try again in a moment."})
            else:
                body["resetToken"] = token
                body["resetPath"] = "biodrive-reset-password.html?token=" + token + "&email=" + email
                print("[demo-email] reset token for", email, token, flush=True)
            return self._send(200, body)
        finally:
            conn.close()

    def _reset_password(self, data):
        token = (data.get("token") or "").strip()
        password = data.get("password") or ""
        if not token:
            return self._send(400, {"error": "Reset token is required."})
        err = strong_password(password)
        if err:
            return self._send(400, {"error": err})
        now = time.time()
        conn = connect()
        try:
            row = one(q(conn, "SELECT * FROM email_tokens WHERE token = ? AND purpose = ?", (token, "reset_password")))
            if not row:
                return self._send(400, {"error": "Invalid or expired reset link."})
            if g(row, "used_at") is not None:
                return self._send(400, {"error": "This reset link was already used."})
            if g(row, "expires_at") < now:
                return self._send(400, {"error": "This reset link has expired. Please request a new one."})
            uid = g(row, "user_id")
            user = one(q(conn, "SELECT * FROM users WHERE id = ?", (uid,)))
            if not user:
                return self._send(400, {"error": "Invalid reset link."})
            pw_hash, salt = hash_password(password)
            q(conn, "UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?",
              (pw_hash, salt, now, uid))
            q(conn, "UPDATE email_tokens SET used_at = ? WHERE token = ?", (now, token))
            # Invalidate existing sessions for security
            q(conn, "DELETE FROM sessions WHERE user_id = ?", (uid,))
            session = create_session(conn, uid)
            conn.commit()
            return self._send(200, {
                "ok": True,
                "message": "Password updated.",
                "token": session,
                "user": user_public(user),
                "profile": get_json(conn, "profiles", uid),
                "powers": get_json(conn, "powers", uid),
            })
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
