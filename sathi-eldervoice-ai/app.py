"""Sathi - ElderVoice AI. Flask backend. Developed and deployed by Kaman Das (c)2026"""
import os, re, json, hashlib
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session, send_file
from flask.json.provider import DefaultJSONProvider
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2, psycopg2.extras

load_dotenv()
HERE = os.path.dirname(os.path.abspath(__file__))

class JP(DefaultJSONProvider):
    @staticmethod
    def default(o):
        return o.isoformat() if isinstance(o, (date, datetime)) else DefaultJSONProvider.default(o)

app = Flask(__name__, static_folder=None)
app.json = JP(app)

def db_url():
    m = re.search(r"postgres(?:ql)?://[^\s'\"]+", os.getenv("NEON_DB_STRING", ""))
    return m.group(0) if m else ""

app.secret_key = os.getenv("SECRET_KEY") or hashlib.sha256(("sathi" + db_url()).encode()).hexdigest()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.getenv("RENDER")), PERMANENT_SESSION_LIFETIME=timedelta(days=30))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS reminders(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, text TEXT NOT NULL, time_of_day TEXT NOT NULL, repeat_mode TEXT DEFAULT 'once', on_date DATE, last_done DATE, active BOOLEAN DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS contacts(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, relationship TEXT, phone TEXT, email TEXT, consent BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS moods(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, mood TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS alerts(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, kind TEXT, message TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
"""
_ready = False

class Err(Exception):
    def __init__(s, m, code=400):
        super().__init__(m); s.code = code

@contextmanager
def db():
    global _ready
    url = db_url()
    if not url:
        raise Err("Database is not configured. Set NEON_DB_STRING.", 503)
    c = psycopg2.connect(url, connect_timeout=10, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        q = c.cursor()
        if not _ready:
            q.execute(SCHEMA); c.commit(); _ready = True
        yield q
        c.commit()
    except Exception:
        c.rollback(); raise
    finally:
        c.close()

def auth(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("uid"):
            raise Err("Please log in.", 401)
        return f(*a, **k)
    return w

def body():
    return request.get_json(silent=True) or {}

@app.errorhandler(Exception)
def oops(e):
    if isinstance(e, Err): return jsonify(error=str(e)), e.code
    if isinstance(e, HTTPException):
        return index() if e.code == 404 and not request.path.startswith("/api") else e
    app.logger.exception(e)
    return jsonify(error="Something went wrong. Please try again."), 500

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Permissions-Policy"] = "microphone=(self)"
    return r

# ---------- pages ----------
@app.get("/")
def index():
    r = send_file(os.path.join(HERE, "index.html"))
    r.headers["Cache-Control"] = "no-cache"
    return r

@app.get("/healthz")
def health():
    return jsonify(ok=True, db=bool(db_url()), gemini=bool(os.getenv("GEMINI_API_KEY")))

# ---------- auth ----------
@app.post("/api/auth/signup")
def signup():
    d = body(); name = (d.get("name") or "").strip()[:60]
    email = (d.get("email") or "").strip().lower(); pw = d.get("password") or ""
    if not name or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) or len(pw) < 8:
        raise Err("Enter your name, a valid email and a password with 8 or more characters.")
    with db() as q:
        q.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if q.fetchone(): raise Err("This email is already registered. Please log in.", 409)
        q.execute("INSERT INTO users(name,email,password_hash) VALUES(%s,%s,%s) RETURNING id,name,email",
                  (name, email, generate_password_hash(pw)))
        u = q.fetchone()
    session.permanent = True; session["uid"] = u["id"]
    return jsonify(user=u)

@app.post("/api/auth/login")
def login():
    d = body(); email = (d.get("email") or "").strip().lower()
    with db() as q:
        q.execute("SELECT * FROM users WHERE email=%s", (email,))
        u = q.fetchone()
    if not u or not check_password_hash(u["password_hash"], d.get("password") or ""):
        raise Err("Email or password is not correct.", 401)
    session.permanent = True; session["uid"] = u["id"]
    return jsonify(user={"id": u["id"], "name": u["name"], "email": u["email"]})

@app.post("/api/auth/logout")
def logout():
    session.clear(); return jsonify(ok=True)

@app.get("/api/auth/me")
def me():
    if not session.get("uid"): return jsonify(user=None)
    with db() as q:
        q.execute("SELECT id,name,email FROM users WHERE id=%s", (session["uid"],))
        u = q.fetchone()
    if not u: session.clear()
    return jsonify(user=u)

# ---------- data ----------
@app.get("/api/data")
@auth
def data():
    uid = session["uid"]; out = {}
    sql = {"reminders": "SELECT * FROM reminders WHERE user_id=%s AND active ORDER BY time_of_day",
           "contacts": "SELECT * FROM contacts WHERE user_id=%s ORDER BY id",
           "moods": "SELECT mood,created_at FROM moods WHERE user_id=%s ORDER BY id DESC LIMIT 7",
           "alerts": "SELECT kind,message,created_at FROM alerts WHERE user_id=%s ORDER BY id DESC LIMIT 8"}
    with db() as q:
        for k, s in sql.items():
            q.execute(s, (uid,)); out[k] = q.fetchall()
    return jsonify(out)

def add_reminder(q, uid, text, t, rep, today, now):
    text = (text or "").strip()
    if not text or not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", t or ""):
        raise Err("Please give a reminder and a time.")
    rep = rep if rep in ("daily", "once") else "once"; d = None
    if rep == "once":
        d = date.fromisoformat(today)
        if t <= now: d += timedelta(days=1)
    q.execute("INSERT INTO reminders(user_id,text,time_of_day,repeat_mode,on_date) VALUES(%s,%s,%s,%s,%s)",
              (uid, text[:140], t, rep, d))

def safe_today(v):
    try: return date.fromisoformat(v).isoformat()
    except Exception: return date.today().isoformat()

@app.post("/api/reminders")
@auth
def reminders_add():
    d = body()
    with db() as q:
        add_reminder(q, session["uid"], d.get("text"), d.get("time"), d.get("repeat"), safe_today(d.get("today")), d.get("now") or "00:00")
    return jsonify(ok=True)

@app.patch("/api/reminders/<int:rid>")
@auth
def reminders_done(rid):
    with db() as q:
        q.execute("UPDATE reminders SET last_done=%s, active=(repeat_mode='daily') WHERE id=%s AND user_id=%s",
                  (safe_today(body().get("today")), rid, session["uid"]))
    return jsonify(ok=True)

@app.delete("/api/reminders/<int:rid>")
@auth
def reminders_del(rid):
    with db() as q: q.execute("DELETE FROM reminders WHERE id=%s AND user_id=%s", (rid, session["uid"]))
    return jsonify(ok=True)

@app.post("/api/contacts")
@auth
def contacts_add():
    d = body(); name = (d.get("name") or "").strip()[:60]
    phone = (d.get("phone") or "").strip()[:25]; email = (d.get("email") or "").strip()[:120]
    if not name or not (phone or email): raise Err("Enter a name and a phone number or email.")
    with db() as q:
        q.execute("INSERT INTO contacts(user_id,name,relationship,phone,email,consent) VALUES(%s,%s,%s,%s,%s,%s)",
                  (session["uid"], name, (d.get("relationship") or "")[:40], phone, email, bool(d.get("consent"))))
    return jsonify(ok=True)

@app.delete("/api/contacts/<int:cid>")
@auth
def contacts_del(cid):
    with db() as q: q.execute("DELETE FROM contacts WHERE id=%s AND user_id=%s", (cid, session["uid"]))
    return jsonify(ok=True)

MOODS = ("happy", "okay", "sad", "lonely", "anxious", "unwell")

@app.post("/api/mood")
@auth
def mood():
    m = body().get("mood")
    if m not in MOODS: raise Err("Unknown mood.")
    with db() as q: q.execute("INSERT INTO moods(user_id,mood) VALUES(%s,%s)", (session["uid"], m))
    return jsonify(ok=True)

def raise_alert(q, uid, kind, msg):
    q.execute("INSERT INTO alerts(user_id,kind,message) VALUES(%s,%s,%s)", (uid, kind, msg))
    q.execute("SELECT name,phone,email FROM contacts WHERE user_id=%s AND consent", (uid,))
    return {"contacts": q.fetchall()}

@app.post("/api/help")
@auth
def help_():
    with db() as q:
        return jsonify(raise_alert(q, session["uid"], "help", "Asked for help using the SOS button."))

# ---------- AI ----------
SYS = """You are Sathi, a warm, patient voice companion for senior citizens. Reply ONLY with JSON:
{"reply":str,"intent":"chat|add_reminder|delete_reminder|request_help","reminder":{"text":str,"time":"HH:MM 24-hour","repeat":"once|daily"}|null,"delete_text":str|null,"mood":"happy|okay|sad|lonely|anxious|unwell"|null,"suggest_family":bool}
Rules: reply in the user's language, 1-3 short spoken sentences (longer only for a requested story), no markdown or emojis. Be kind and never diagnose; for health worries give gentle general advice and suggest a doctor. Emergencies (chest pain, a fall, cannot breathe) -> intent request_help and tell them to call their local emergency number. Loneliness or sadness -> comfort, suggest a gentle activity, set suggest_family true if it seems serious. If a reminder time is missing, ask for it (intent chat). User name: %s. Local date and time now: %s."""

def ask_gemini(name, now, hist, msg):
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key: return None
    try:
        import google.generativeai as genai
        genai.configure(api_key=key)
        m = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-3.5-flash"), system_instruction=SYS % (name, now),
                                  generation_config={"response_mime_type": "application/json", "temperature": 0.7})
        turns = [{"role": "model" if h.get("role") == "ai" else "user", "parts": [str(h.get("text", ""))[:500]]}
                 for h in hist[-6:] if isinstance(h, dict)] + [{"role": "user", "parts": [msg]}]
        txt = re.sub(r"^```(?:json)?|```$", "", m.generate_content(turns).text.strip()).strip()
        return json.loads(txt)
    except Exception as e:
        app.logger.warning("Gemini error: %s", e); return None

def fallback(msg):
    m = re.search(r"remind me (?:to )?(.+?) at (\d{1,2})(?::(\d{2}))?\s*([ap])\.?m", msg, re.I)
    if m:
        h = int(m[2]) % 12 + (12 if m[4].lower() == "p" else 0); t = "%02d:%s" % (h, m[3] or "00")
        return {"reply": "Of course! I'll remind you at %s." % t, "intent": "add_reminder",
                "reminder": {"text": m[1], "time": t, "repeat": "once"}}
    if re.search(r"\b(help|emergency|ambulance)\b", msg, re.I):
        return {"reply": "I'm alerting your family now.", "intent": "request_help"}
    return {"reply": "I'm here with you. My thinking service is not connected yet, but I can still set reminders and call for help.", "intent": "chat"}

@app.post("/api/chat")
@auth
def chat():
    d = body(); msg = (d.get("message") or "").strip()[:600]
    if not msg: raise Err("I did not catch that.")
    today = safe_today(d.get("today")); now = d.get("now") or "00:00"; uid = session["uid"]
    with db() as q:
        q.execute("SELECT name FROM users WHERE id=%s", (uid,)); name = q.fetchone()["name"]
        r = ask_gemini(name, today + " " + now, d.get("history") or [], msg) or fallback(msg)
        out = {"reply": str(r.get("reply") or "I'm here with you."), "refresh": False, "alert": None,
               "suggest_family": bool(r.get("suggest_family"))}
        it = r.get("intent")
        if it == "add_reminder" and isinstance(r.get("reminder"), dict):
            x = r["reminder"]
            try:
                add_reminder(q, uid, x.get("text"), x.get("time"), x.get("repeat"), today, now); out["refresh"] = True
            except Err:
                out["reply"] = "Sorry, what time should I remind you?"
        elif it == "delete_reminder" and r.get("delete_text"):
            q.execute("DELETE FROM reminders WHERE id=(SELECT id FROM reminders WHERE user_id=%s AND text ILIKE %s LIMIT 1)",
                      (uid, "%" + str(r["delete_text"]) + "%")); out["refresh"] = True
        elif it == "request_help":
            out["alert"] = raise_alert(q, uid, "help", "Asked for help by voice: " + msg[:200]); out["refresh"] = True
        if r.get("mood") in MOODS:
            q.execute("INSERT INTO moods(user_id,mood) VALUES(%s,%s)", (uid, r["mood"])); out["refresh"] = True
    return jsonify(out)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
