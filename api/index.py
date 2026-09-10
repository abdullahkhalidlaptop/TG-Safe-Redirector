import os
import time
import json
import base64
import secrets
import datetime
import threading
from urllib.parse import urlparse, quote

from dotenv import load_dotenv
load_dotenv()

import requests
from flask import (
    Flask, request, render_template_string, abort, jsonify,
    redirect as flask_redirect,
)

import firebase_admin
from firebase_admin import credentials, firestore, db as rtdb


# ==================================================================
#  CONFIG
# ==================================================================
def env(key, default=""):
    return os.getenv(key, default)

def env_int(key, default):
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default

def env_bool(key, default=False):
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes", "on")


# Firebase
FIREBASE_RTDB_URL   = env("FIREBASE_RTDB_URL")
FIREBASE_KEY_PATH   = env("FIREBASE_KEY_PATH", "./serviceAccountKey.json")
FIREBASE_KEY_JSON   = env("FIREBASE_SERVICE_ACCOUNT_KEY")   # for Vercel

# Admin / Gate
ADMIN_KEY    = env("ADMIN_KEY")
GATE_KEY     = env("GATE_KEY")
SESSION_TTL  = env_int("SESSION_TTL_MINUTES", 15)

# Referer
ALLOWED_REFERER_HOSTS = [
    h.strip().lower()
    for h in env("ALLOWED_REFERER_HOSTS", "tpi.li,shrinkearn.com").split(",")
    if h.strip()
]

# Rate limit
RL_WINDOW = env_int("RATE_LIMIT_WINDOW_SECONDS", 60)
RL_LIMIT  = env_int("RATE_LIMIT_MAX_REQUESTS", 10)

# ShrinkEarn
SHRINKEARN_API_KEY  = env("SHRINKEARN_API_KEY")
SHRINKEARN_ENDPOINT = env("SHRINKEARN_ENDPOINT", "https://shrinkearn.com/api")

# Public base URL (used to build gate URLs)
PUBLIC_BASE_URL = env("PUBLIC_BASE_URL", "http://127.0.0.1:8999").rstrip("/")

# Branding
BRAND = {
    "name":          env("BRAND_NAME",     "AK Mods Files"),
    "tagline":       env("BRAND_TAGLINE",  "Premium Mods & Files"),
    "logo":          env("BRAND_LOGO",     ""),
    "logo_fallback": env("BRAND_LOGO_FALLBACK", "🎬"),
    "accent":        env("BRAND_ACCENT",   "#0088cc"),
    "bg":            env("BRAND_BG",       "#0f172a"),
    "card":          env("BRAND_CARD",     "#1e293b"),
    "text":          env("BRAND_TEXT",     "#e2e8f0"),
    "footer":        env("BRAND_FOOTER",   "Powered by AK Mods"),
}

# Server (used only when running locally)
SERVER_HOST  = env("HOST", "0.0.0.0")
SERVER_PORT  = env_int("PORT", 8999)
SERVER_DEBUG = env_bool("DEBUG", True)


# ==================================================================
#  FIREBASE INIT
# ==================================================================
def init_firebase():
    if firebase_admin._apps:
        return

    if FIREBASE_KEY_JSON:
        # Vercel — JSON string in env var
        cred = credentials.Certificate(json.loads(FIREBASE_KEY_JSON))
    else:
        # Local — path to JSON file
        key_path = FIREBASE_KEY_PATH
        if not os.path.isabs(key_path):
            key_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                key_path,
            )
        if not os.path.exists(key_path):
            raise RuntimeError(f"Service account JSON not found: {key_path}")
        cred = credentials.Certificate(key_path)

    firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_RTDB_URL})


init_firebase()
db = firestore.client()
rt = rtdb.reference()

app = Flask(__name__)


# ==================================================================
#  HELPERS
# ==================================================================
def is_allowed_referer(referer: str) -> bool:
    if not referer:
        return False
    try:
        host = urlparse(referer).netloc.lower().split(":")[0]
    except Exception:
        return False
    return any(host == a or host.endswith("." + a) for a in ALLOWED_REFERER_HOSTS)


def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "")


def admin_ok() -> bool:
    """Accepts key via ?key= or X-Admin-Key header."""
    if not ADMIN_KEY:
        return False
    if request.args.get("key", "") == ADMIN_KEY:
        return True
    if request.headers.get("X-Admin-Key", "") == ADMIN_KEY:
        return True
    return False


# ---- rate limiter ----
_rl_lock = threading.Lock()
_rl_hits = {}

def rate_ok(ip: str) -> bool:
    now = time.time()
    with _rl_lock:
        hits = [t for t in _rl_hits.get(ip, []) if now - t < RL_WINDOW]
        if len(hits) >= RL_LIMIT:
            _rl_hits[ip] = hits
            return False
        hits.append(now)
        _rl_hits[ip] = hits
        return True


# ==================================================================
#  FIRESTORE / RTDB WRITES
# ==================================================================
def log_bypass(reason, ip, ua, referer, extra=None):
    try:
        doc = {
            "reason": reason,
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "ip": ip[:64],
            "userAgent": ua[:500],
            "referer": referer[:500],
        }
        if extra:
            doc.update(extra)
        db.collection("bypasses").add(doc)
        print(f"  [BYP] {reason} ip={ip}")
    except Exception as e:
        print(f"  [BYP ERR] {e}")


def increment_downloads(token, alias, ip, ua):
    try:
        db.collection("links").document(token).update(
            {"downloads": firestore.Increment(1)}
        )
        db.collection("clicks").add({
            "token": token, "alias": alias,
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "ip": ip[:64], "userAgent": ua[:500],
        })
        try:
            ref = rt.child(f"counters/{token}/downloads")
            cur = ref.get() or 0
            ref.set(int(cur) + 1)
            rt.child(f"counters/{token}/lastClick").set(int(time.time()))
        except Exception:
            pass
        print(f"  [DL ] +1 for '{alias}'")
    except Exception as e:
        print(f"  [DL ERR] {e}")


def create_session(url, alias, token):
    sid = secrets.token_urlsafe(20)
    now = datetime.datetime.now(datetime.timezone.utc)
    db.collection("sessions").document(sid).set({
        "url": url,
        "alias": alias,
        "token": token,
        "used": False,
        "createdAt": now,
        "expiresAt": now + datetime.timedelta(minutes=SESSION_TTL),
    })
    print(f"  [SES] {sid[:8]}… → {alias}")
    return sid


def get_session(sid):
    try:
        doc = db.collection("sessions").document(sid).get()
        return doc.to_dict() if doc.exists else None
    except Exception:
        return None


@firestore.transactional
def consume_session_txn(transaction, doc_ref):
    snap = doc_ref.get(transaction=transaction)
    if not snap.exists:
        return ("missing", None)
    data = snap.to_dict()
    if data.get("used"):
        return ("used", data)
    exp = data.get("expiresAt")
    if exp and exp.replace(tzinfo=None) < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        return ("expired", data)
    transaction.update(doc_ref, {
        "used": True,
        "usedAt": datetime.datetime.now(datetime.timezone.utc),
    })
    return ("ok", data)


def call_shrinkearn(destination_url: str, alias: str):
    """Call ShrinkEarn API. Returns dict {ok, short_url, error}."""
    if not SHRINKEARN_API_KEY:
        return {"ok": False, "error": "SHRINKEARN_API_KEY not configured"}

    params = {
        "api": SHRINKEARN_API_KEY,
        "url": destination_url,
        "alias": alias,
    }
    try:
        r = requests.get(SHRINKEARN_ENDPOINT, params=params, timeout=25)
        data = r.json()
    except Exception as e:
        return {"ok": False, "error": f"ShrinkEarn request failed: {e}"}

    if str(data.get("status", "")).lower() == "success" and data.get("shortenedUrl"):
        return {"ok": True, "short_url": data["shortenedUrl"]}
    return {"ok": False, "error": data.get("message", "Unknown ShrinkEarn error")}


def build_gate_url(file_id: str) -> str:
    return f"{PUBLIC_BASE_URL}/gate?k={GATE_KEY}&t={file_id}"


# ==================================================================
#  TEMPLATES
# ==================================================================
REDIRECT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="{{ b.accent }}">
<title>{{ b.name }} — Open in Telegram</title>
<style>
    :root {
        --accent: {{ b.accent }};
        --bg: {{ b.bg }}; --card: {{ b.card }}; --text: {{ b.text }};
        --card-size: min(92vw, 92dvh, 560px);
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    html, body {
        margin: 0; padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
        background: var(--bg); color: var(--text);
        min-height: 100vh; min-height: 100dvh;
        display: flex; align-items: center; justify-content: center; padding: 12px;
    }
    .card {
        width: var(--card-size); height: var(--card-size);
        aspect-ratio: 1 / 1; background: var(--card); border-radius: 26px;
        padding: 5% 7%;
        display: flex; flex-direction: column; justify-content: space-between;
        box-shadow: 0 24px 70px rgba(0,0,0,.5), 0 0 0 1px rgba(255,255,255,.05) inset;
        animation: pop .38s ease-out; overflow: hidden;
    }
    @keyframes pop {
        from { opacity: 0; transform: translateY(14px) scale(.97); }
        to   { opacity: 1; transform: translateY(0) scale(1); }
    }
    .top { display: flex; flex-direction: column; align-items: center;
           justify-content: center; flex: 1; min-height: 0; }
    .logo-wrap {
        width: 30%; aspect-ratio: 1 / 1; border-radius: 50%; margin: 0 auto 6%;
        display: flex; align-items: center; justify-content: center;
        background: linear-gradient(135deg, var(--accent) 0%,
                     color-mix(in srgb, var(--accent) 55%, #fff) 100%);
        box-shadow: 0 14px 34px -10px var(--accent);
        overflow: hidden; user-select: none; flex-shrink: 0;
    }
    .logo-wrap img { width: 100%; height: 100%; object-fit: cover; display: block; }
    .logo-emoji { font-size: clamp(36px, 11vw, 68px); line-height: 1; }
    h1 { margin: 0 0 2%; font-size: clamp(17px, 5vw, 25px);
         font-weight: 700; letter-spacing: -.3px; line-height: 1.15;
         text-align: center; padding: 0 4%; }
    .tagline { margin: 0; font-size: clamp(11px, 3.2vw, 13.5px);
               opacity: .6; line-height: 1.45; text-align: center; padding: 0 6%; }
    .counter {
        margin-top: 4%; display: inline-flex; align-items: center; gap: 6px;
        padding: 6px 14px; background: rgba(34,197,94,.12);
        border: 1px solid rgba(34,197,94,.3); border-radius: 999px;
        font-size: clamp(11px, 3.1vw, 13px); color: #22c55e; font-weight: 600;
    }
    .counter .dot { width: 7px; height: 7px; border-radius: 50%;
                    background: #22c55e; animation: blink 1.6s ease-in-out infinite; }
    @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
    .counter b { color: #4ade80; font-weight: 800; }
    .bottom { padding-top: 4%; flex-shrink: 0; }
    .btn {
        display: block; width: 100%; padding: 4.2% 0; border: none; border-radius: 14px;
        background: var(--accent); color: #fff;
        font-size: clamp(14px, 4vw, 17px); font-weight: 600;
        letter-spacing: .2px; cursor: pointer; text-decoration: none;
        box-shadow: 0 10px 26px -8px var(--accent);
        transition: transform .12s ease, box-shadow .12s ease; user-select: none;
    }
    .btn:active { transform: scale(.97); box-shadow: 0 5px 14px -8px var(--accent); }
    .footer { margin-top: 3%; font-size: clamp(9px, 2.6vw, 11px);
              opacity: .38; letter-spacing: .4px; text-align: center; }
    .spinner {
        display: none; width: 16px; height: 16px;
        border: 2px solid rgba(255,255,255,.4); border-top-color: #fff;
        border-radius: 50%; margin-right: 8px;
        animation: spin .7s linear infinite; vertical-align: -3px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .loading .spinner { display: inline-block; }
    .loading .btn-label { opacity: .85; }
</style>
</head>
<body>
<div class="card">
    <div class="top">
        <div class="logo-wrap">
            {% if b.logo %}<img src="{{ b.logo }}" alt="{{ b.name }}">
            {% else %}<span class="logo-emoji">{{ b.logo_fallback }}</span>{% endif %}
        </div>
        <h1>{{ b.name }}</h1>
        <p class="tagline">{{ b.tagline }}</p>
        <div class="counter">
            <span class="dot"></span>
            Downloads: <b id="dl-count">…</b>
        </div>
    </div>
    <div class="bottom">
        <button class="btn" id="openBtn" onclick="openOnce()">
            <span class="spinner"></span>
            <span class="btn-label">Open in Telegram</span>
        </button>
        <div class="footer">{{ b.footer }}</div>
    </div>
</div>
<script>
    const TOKEN = {{ token|tojson }};
    const INITIAL = {{ initial_count|tojson }};
    const dlEl = document.getElementById('dl-count');
    dlEl.textContent = (INITIAL || 0).toLocaleString();
    async function refreshCount() {
        try {
            const r = await fetch('/api/count/' + encodeURIComponent(TOKEN));
            const d = await r.json();
            dlEl.textContent = (d.count || 0).toLocaleString();
        } catch (e) {}
    }
    setInterval(refreshCount, 4000);
    setTimeout(refreshCount, 500);
    function openOnce() {
        const btn = document.getElementById('openBtn');
        btn.classList.add("loading");
        btn.querySelector(".btn-label").textContent = "Opening…";
        window.location.href = "/go?s=" + encodeURIComponent({{ sid|tojson }});
    }
</script>
</body>
</html>
"""


BYPASS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#dc2626">
<meta name="robots" content="noindex,nofollow">
<title>Verification Required — {{ b.name }}</title>
<style>
    :root { --danger: #dc2626; --danger-soft: #7f1d1d;
            --bg: {{ b.bg }}; --card: {{ b.card }}; --text: {{ b.text }};
            --card-size: min(92vw, 92dvh, 560px); }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    html, body {
        margin: 0; padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
        background: var(--bg); color: var(--text);
        min-height: 100vh; min-height: 100dvh;
        display: flex; align-items: center; justify-content: center; padding: 12px;
    }
    .card {
        width: var(--card-size); height: var(--card-size);
        aspect-ratio: 1 / 1; background: var(--card); border-radius: 26px;
        padding: 7% 8%;
        display: flex; flex-direction: column; justify-content: space-between;
        text-align: center;
        box-shadow: 0 24px 70px rgba(0,0,0,.5), 0 0 0 1px rgba(220,38,38,.25) inset;
        animation: pop .38s ease-out, shake .6s ease-in-out .3s;
        overflow: hidden; border: 1px solid rgba(220,38,38,.35);
    }
    @keyframes pop {
        from { opacity: 0; transform: translateY(14px) scale(.97); }
        to   { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes shake {
        0%,100% { transform: translateX(0); }
        20% { transform: translateX(-6px); }
        40% { transform: translateX(6px); }
        60% { transform: translateX(-4px); }
        80% { transform: translateX(4px); }
    }
    .top { display: flex; flex-direction: column; align-items: center;
           justify-content: center; flex: 1; min-height: 0; }
    .icon-wrap {
        width: 28%; aspect-ratio: 1 / 1; border-radius: 50%; margin: 0 auto 6%;
        display: flex; align-items: center; justify-content: center;
        background: linear-gradient(135deg, var(--danger), var(--danger-soft));
        box-shadow: 0 14px 34px -10px var(--danger); flex-shrink: 0;
        animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
        0%,100% { box-shadow: 0 14px 34px -10px var(--danger); }
        50%     { box-shadow: 0 14px 44px -6px var(--danger); }
    }
    .icon-emoji { font-size: clamp(34px, 10vw, 62px); line-height: 1; }
    h1 { margin: 0 0 3%; font-size: clamp(16px, 5vw, 24px);
         font-weight: 800; letter-spacing: -.3px; line-height: 1.15;
         color: #fca5a5; padding: 0 3%; }
    .subtitle { margin: 0 0 4%; font-size: clamp(11px, 3.1vw, 13px);
                opacity: .6; line-height: 1.5; padding: 0 5%; }
    .msg { font-size: clamp(10.5px, 2.9vw, 12.5px); line-height: 1.55;
           opacity: .85; padding: 0 6%; margin: 0; }
    .msg strong { color: #fca5a5; font-weight: 600; }
    .bottom { padding-top: 5%; flex-shrink: 0; }
    .btn {
        display: block; width: 100%; padding: 4.2% 0;
        border: none; border-radius: 14px;
        background: rgba(220,38,38,.12); color: #fca5a5;
        font-size: clamp(13px, 3.8vw, 15px); font-weight: 600;
        cursor: pointer; text-decoration: none;
        border: 1px solid rgba(220,38,38,.35);
        transition: transform .12s ease, background .12s ease;
    }
    .btn:active { transform: scale(.97); background: rgba(220,38,38,.2); }
    .footer { margin-top: 3%; font-size: clamp(9px, 2.5vw, 10.5px);
              opacity: .35; letter-spacing: .4px; }
</style>
</head>
<body>
<div class="card">
    <div class="top">
        <div class="icon-wrap"><span class="icon-emoji">{{ icon }}</span></div>
        <h1>{{ title }}</h1>
        <p class="subtitle">{{ subtitle }}</p>
        <p class="msg">{{ message|safe }}</p>
    </div>
    <div class="bottom">
        <button class="btn" onclick="history.length > 1 ? history.back() : window.close()">
            ← {{ cta }}
        </button>
        <div class="footer">{{ b.footer }}</div>
    </div>
</div>
</body>
</html>
"""


ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ b.name }} — Admin</title>
<style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
           background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px 16px; }
    .wrap { max-width: 1100px; margin: 0 auto; }
    h1 { margin: 0 0 4px; font-size: 22px; }
    h2 { font-size: 16px; margin-top: 36px; }
    .sub { opacity: .55; margin-bottom: 24px; font-size: 13px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
             gap: 14px; margin-bottom: 24px; }
    .stat { background: #1e293b; border-radius: 12px; padding: 16px 18px;
            border: 1px solid rgba(255,255,255,.06); }
    .stat-label { font-size: 11px; opacity: .55; text-transform: uppercase; letter-spacing: .8px; }
    .stat-value { font-size: 26px; font-weight: 700; margin-top: 6px; color: #22c55e; }
    .stat-value.danger { color: #f87171; }
    table { width: 100%; border-collapse: collapse; background: #1e293b;
            border-radius: 12px; overflow: hidden; border: 1px solid rgba(255,255,255,.06); }
    th, td { padding: 12px 14px; text-align: left;
             border-bottom: 1px solid rgba(255,255,255,.06); font-size: 13.5px; }
    th { background: #0b1220; font-size: 11px;
         text-transform: uppercase; letter-spacing: .8px; opacity: .6; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.02); }
    .clicks { font-weight: 700; color: #22c55e; font-size: 15px; }
    .empty { padding: 50px; text-align: center; opacity: .5; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .url-cell { max-width: 320px; word-break: break-all; font-size: 12px; opacity: .8; }
    .refresh { display: inline-block; padding: 8px 14px; margin-bottom: 16px;
               background: #1e293b; border: 1px solid rgba(255,255,255,.08);
               color: #e2e8f0; border-radius: 8px; cursor: pointer; font-size: 13px; }
    .refresh:hover { background: #273449; }
    .error { color: #f87171; padding: 20px; text-align: center; }
    .tag { font-size: 10px; padding: 2px 6px; background: #334155; border-radius: 4px; opacity: .7; }
</style>
</head>
<body>
<div class="wrap">
    <h1>{{ b.name }} — Admin Dashboard</h1>
    <div class="sub">All registered files, downloads, and bypass attempts</div>

    <div class="stats">
        <div class="stat"><div class="stat-label">Total Files</div><div class="stat-value" id="totalLinks">—</div></div>
        <div class="stat"><div class="stat-label">Total Downloads</div><div class="stat-value" id="totalClicks">—</div></div>
        <div class="stat"><div class="stat-label">Active Sessions</div><div class="stat-value" id="totalSessions">—</div></div>
        <div class="stat"><div class="stat-label">Bypass Attempts</div><div class="stat-value danger" id="totalBypasses">—</div></div>
    </div>

    <button class="refresh" onclick="load()">↻ Refresh</button>

    <table>
        <thead>
            <tr><th>File ID</th><th>Destination</th><th>Downloads</th><th>Created</th></tr>
        </thead>
        <tbody id="rows"><tr><td colspan="4" class="empty">Loading…</td></tr></tbody>
    </table>

    <h2>Recent Bypass Attempts</h2>
    <table style="margin-top:12px;">
        <thead>
            <tr><th>When</th><th>Reason</th><th>Referer</th><th>IP</th></tr>
        </thead>
        <tbody id="bypassRows"><tr><td colspan="4" class="empty">Loading…</td></tr></tbody>
    </table>
</div>
<script>
    const KEY = new URLSearchParams(location.search).get("key");
    const api = (path) => fetch(path + (path.includes("?") ? "&" : "?") + "key=" + encodeURIComponent(KEY));

    function load() {
        api("/api/links")
            .then(r => r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)))
            .then(data => {
                const tbody = document.getElementById("rows");
                const total = data.reduce((s,l) => s + (l.downloads || 0), 0);
                document.getElementById("totalLinks").textContent = data.length;
                document.getElementById("totalClicks").textContent = total;
                if (!data.length) {
                    tbody.innerHTML = '<tr><td colspan="4" class="empty">No files yet.</td></tr>';
                    return;
                }
                tbody.innerHTML = data.map(l => `
                    <tr>
                        <td><strong>${l.token || l.alias || "—"}</strong></td>
                        <td class="url-cell"><a href="${l.url}" target="_blank">${l.url}</a></td>
                        <td class="clicks">${(l.downloads || 0).toLocaleString()}</td>
                        <td>${(l.createdAt || "").slice(0, 10)}</td>
                    </tr>`).join("");
            })
            .catch(err => { document.getElementById("rows").innerHTML =
                '<tr><td colspan="4" class="error">' + err.message + '</td></tr>'; });

        api("/api/bypasses")
            .then(r => r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)))
            .then(data => {
                const tbody = document.getElementById("bypassRows");
                document.getElementById("totalBypasses").textContent = data.length;
                if (!data.length) {
                    tbody.innerHTML = '<tr><td colspan="4" class="empty">No bypass attempts 🎉</td></tr>';
                    return;
                }
                tbody.innerHTML = data.slice(0, 50).map(b => `
                    <tr>
                        <td>${(b.timestamp || "").slice(0, 19).replace("T", " ")}</td>
                        <td><span class="tag">${b.reason || "unknown"}</span></td>
                        <td class="url-cell">${b.referer || "—"}</td>
                        <td>${b.ip || "—"}</td>
                    </tr>`).join("");
            })
            .catch(() => {});

        api("/api/sessions/stats")
            .then(r => r.ok ? r.json() : Promise.reject())
            .then(d => { document.getElementById("totalSessions").textContent = d.active || 0; })
            .catch(() => {});
    }
    load();
    setInterval(load, 15000);
</script>
</body>
</html>
"""


# ==================================================================
#  ROUTE HELPER
# ==================================================================
def render_wall(title, subtitle, message, cta="Go Back", icon="🔒", status=403):
    return render_template_string(
        BYPASS_HTML, b=BRAND,
        title=title, subtitle=subtitle, message=message, cta=cta, icon=icon,
    ), status


# ==================================================================
#  PUBLIC ROUTES
# ==================================================================
@app.route("/")
def home():
    return jsonify({
        "service": BRAND["name"],
        "status": "live",
        "endpoints": [
            "GET  /gate?k=GATE_KEY&t=FILE_ID",
            "GET  /card?s=SESSION_ID",
            "GET  /go?s=SESSION_ID",
            "GET  /admin?key=ADMIN_KEY",
            "GET  /api/count/<file_id>",
            "GET  /api/links?key=ADMIN_KEY",
            "GET  /api/bypasses?key=ADMIN_KEY",
            "POST /api/shorten    (JSON: {id, url, alias})",
            "POST /api/register   (JSON: {id, url, alias})",
        ],
    })


@app.route("/gate")
def gate():
    ip = client_ip()
    ua = request.headers.get("User-Agent", "")
    referer = request.headers.get("Referer", "")

    if request.args.get("k", "") != GATE_KEY:
        log_bypass("bad_gate_key", ip, ua, referer)
        return render_wall("Access Denied", "This link is not valid.",
            "The link you used is <strong>missing a valid key</strong>.",
            "Go Back", "🚫", 403)

    if not rate_ok(ip):
        log_bypass("rate_limit_gate", ip, ua, referer)
        return render_wall("Too Many Requests", "Slow down a little.",
            "Please wait a minute and try again.", "Go Back", "⏱️", 429)

    if not is_allowed_referer(referer):
        log_bypass("bad_referer_gate", ip, ua, referer)
        return render_wall("Verification Bypass Detected",
            "This link is protected by an integrity check.",
            "You accessed this link <strong>directly</strong>, bypassing "
            "the verification step. Please open the original short link and "
            "complete the verification to continue.",
            "Go Back & Verify Properly", "🔒", 403)

    file_id = request.args.get("t", "").strip()
    if not file_id:
        return render_wall("Invalid Link", "Missing file ID.",
            "The link you used is incomplete.", "Go Back", "🚫", 400)

    try:
        doc = db.collection("links").document(file_id).get()
        if not doc.exists:
            return render_wall("Link Not Found", "This file doesn't exist.",
                "Please open the original short link again.", "Go Back", "❓", 404)
        link = doc.to_dict()
    except Exception as e:
        print(f"  [GATE ERR] {e}")
        return render_wall("Server Error", "Something went wrong.",
            "Please try again in a moment.", "Go Back", "⚠️", 500)

    sid = create_session(link["url"], link.get("alias", file_id), file_id)
    print(f"  [OK ] gate → {sid[:8]}… → {link['url']}")
    return flask_redirect(f"/card?s={sid}")


@app.route("/card")
def card():
    sid = request.args.get("s", "").strip()
    if not sid:
        return render_wall("Invalid Link", "", "No session found.", "Go Back", "🚫", 400)

    session = get_session(sid)
    if not session:
        return render_wall("Link Expired or Invalid", "This link can no longer be used.",
            "The session is missing or has expired. Please start again from the original short link.",
            "Go Back", "⏳", 404)

    if session.get("used"):
        return render_wall("Link Already Used", "This one-time link has already been opened.",
            "Each link can be used <strong>only once</strong>. Please return "
            "to the original short link to get a fresh one.", "Go Back", "🔁", 410)

    exp = session.get("expiresAt")
    if exp and exp.replace(tzinfo=None) < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        return render_wall("Link Expired", "This link took too long to open.",
            f"For security, links expire after {SESSION_TTL} minutes.",
            "Go Back", "⏳", 410)

    try:
        cur = rt.child(f"counters/{session['token']}/downloads").get() or 0
        initial_count = int(cur)
    except Exception:
        initial_count = 0

    return render_template_string(
        REDIRECT_HTML, b=BRAND,
        token=session["token"], sid=sid, initial_count=initial_count,
    )


@app.route("/go")
def go():
    sid = request.args.get("s", "").strip()
    if not sid:
        return render_wall("Invalid Link", "", "No session found.", "Go Back", "🚫", 400)

    ip = client_ip()
    ua = request.headers.get("User-Agent", "")

    doc_ref = db.collection("sessions").document(sid)
    status, data = consume_session_txn(db.transaction(), doc_ref)

    if status == "missing":
        return render_wall("Link Invalid", "This link doesn't exist.",
            "Please start again from the original short link.", "Go Back", "🚫", 404)

    if status == "used":
        log_bypass("session_reuse", ip, ua, request.headers.get("Referer", ""),
                   {"session_id": sid})
        return render_wall("Link Already Used", "This one-time link has already been opened.",
            "Each link can be used <strong>only once</strong>. Please return "
            "to the original short link to get a fresh one.", "Go Back", "🔁", 410)

    if status == "expired":
        return render_wall("Link Expired", "This link took too long to open.",
            f"For security, links expire after {SESSION_TTL} minutes.", "Go Back", "⏳", 410)

    url   = data.get("url", "")
    alias = data.get("alias", "")
    token = data.get("token", "")

    increment_downloads(token, alias, ip, ua)

    return render_template_string(
        """
        <!DOCTYPE html>
        <html><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Opening…</title>
        <style>
            body { margin:0; height:100vh; display:flex; align-items:center; justify-content:center;
                   background:{{ bg }}; color:{{ text }}; font-family:-apple-system,sans-serif; }
            .spin { width:36px;height:36px;border:3px solid rgba(255,255,255,.2);
                    border-top-color:{{ accent }};border-radius:50%;
                    animation:s .8s linear infinite;margin:0 auto 18px; }
            @keyframes s { to { transform: rotate(360deg); } }
            .t { font-size:15px; opacity:.75; text-align:center; }
        </style></head>
        <body><div>
        <div class="spin"></div><div class="t">Opening in Telegram…</div>
        </div>
        <script>
            const target = {{ url|tojson }};
            function launch() {
                if (target.startsWith("https://t.me/") || target.startsWith("https://telegram.me/")) {
                    const p = new URL(target);
                    const path = p.pathname + p.search;
                    if (/android/i.test(navigator.userAgent)) {
                        window.location.href = "intent://t.me" + path +
                            "#Intent;scheme=https;package=org.telegram.messenger;" +
                            "S.browser_fallback_url=" + encodeURIComponent(target) + ";end";
                        setTimeout(() => { window.location.href = target; }, 1500);
                        return;
                    }
                    if (/iphone|ipad|ipod/i.test(navigator.userAgent)) {
                        window.location.href = "tg://resolve?domain=" +
                            p.pathname.replace("/","") +
                            (p.search ? "&" + p.search.slice(1) : "");
                        setTimeout(() => { window.location.href = target; }, 1200);
                        return;
                    }
                }
                window.location.href = target;
            }
            launch();
        </script>
        </body></html>
        """,
        url=url, bg=BRAND["bg"], text=BRAND["text"], accent=BRAND["accent"],
    )


# ==================================================================
#  PUBLIC API — live counter
# ==================================================================
@app.route("/api/count/<token>")
def api_count(token):
    try:
        val = rt.child(f"counters/{token}/downloads").get() or 0
        return jsonify({"count": int(val)})
    except Exception:
        return jsonify({"count": 0})


# ==================================================================
#  ADMIN API
# ==================================================================
@app.route("/admin")
def admin_panel():
    if not admin_ok():
        return "<h2>403 — Access denied</h2>", 403
    return render_template_string(ADMIN_HTML, b=BRAND)


@app.route("/api/links")
def api_links():
    if not admin_ok():
        abort(403)
    out = []
    for d in db.collection("links").stream():
        x = d.to_dict()
        x["token"] = d.id
        if "createdAt" in x and hasattr(x["createdAt"], "isoformat"):
            x["createdAt"] = x["createdAt"].isoformat()
        out.append(x)
    out.sort(key=lambda z: z.get("downloads", 0), reverse=True)
    return jsonify(out)


@app.route("/api/bypasses")
def api_bypasses():
    if not admin_ok():
        abort(403)
    docs = db.collection("bypasses").order_by(
        "timestamp", direction=firestore.Query.DESCENDING
    ).limit(200).stream()
    out = []
    for d in docs:
        x = d.to_dict()
        if "timestamp" in x and hasattr(x["timestamp"], "isoformat"):
            x["timestamp"] = x["timestamp"].isoformat()
        out.append(x)
    return jsonify(out)


@app.route("/api/sessions/stats")
def api_sessions_stats():
    if not admin_ok():
        abort(403)
    try:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        active = 0
        for d in db.collection("sessions").stream():
            s = d.to_dict()
            if s.get("used"):
                continue
            exp = s.get("expiresAt")
            if exp and exp.replace(tzinfo=None) > now:
                active += 1
        return jsonify({"active": active})
    except Exception:
        return jsonify({"active": 0})


# ------------------------------------------------------------------
#  REGISTER — adds a file (no ShrinkEarn call)
# ------------------------------------------------------------------
@app.route("/api/register", methods=["GET", "POST"])
def api_register():
    if not admin_ok():
        abort(403)

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        file_id = data.get("id", "")
        url     = data.get("url", "")
        alias   = data.get("alias", file_id)
    else:
        file_id = request.args.get("id", "")
        url     = request.args.get("url", "")
        alias   = request.args.get("alias", file_id)

    file_id = file_id.strip()
    url     = url.strip()
    alias   = (alias or file_id).strip()

    if not file_id or not url:
        return jsonify({"ok": False, "error": "Missing id or url"}), 400

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"ok": False, "error": "Invalid URL scheme"}), 400

    db.collection("links").document(file_id).set({
        "url": url,
        "alias": alias,
        "createdAt": datetime.datetime.now(datetime.timezone.utc),
        "creatorId": "api",
        "downloads": 0,
    })

    gate_url = build_gate_url(file_id)
    return jsonify({
        "ok": True,
        "id": file_id,
        "gate_url": gate_url,
    })


# ------------------------------------------------------------------
#  SHORTEN — register + call ShrinkEarn (the one-shot endpoint)
# ------------------------------------------------------------------
@app.route("/api/shorten", methods=["POST", "GET"])
def api_shorten():
    if not admin_ok():
        abort(403)

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        file_id = data.get("id", "")
        url     = data.get("url", "")
        alias   = data.get("alias", "")
    else:
        file_id = request.args.get("id", "")
        url     = request.args.get("url", "")
        alias   = request.args.get("alias", "")

    file_id = file_id.strip()
    url     = url.strip()
    alias   = (alias or file_id).strip()

    if not file_id or not url:
        return jsonify({"ok": False, "error": "Missing id or url"}), 400

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"ok": False, "error": "Invalid URL scheme"}), 400

    # 1. Save in Firestore
    db.collection("links").document(file_id).set({
        "url": url,
        "alias": alias,
        "createdAt": datetime.datetime.now(datetime.timezone.utc),
        "creatorId": "api",
        "downloads": 0,
    })

    # 2. Build gate URL
    gate_url = build_gate_url(file_id)

    # 3. Call ShrinkEarn
    result = call_shrinkearn(gate_url, alias)
    if not result["ok"]:
        return jsonify({
            "ok": False,
            "id": file_id,
            "gate_url": gate_url,
            "error": result["error"],
        }), 502

    return jsonify({
        "ok": True,
        "id": file_id,
        "gate_url": gate_url,
        "short_url": result["short_url"],
    })


# ------------------------------------------------------------------
#  DELETE — remove a file
# ------------------------------------------------------------------
@app.route("/api/links/<file_id>", methods=["DELETE"])
def api_delete_link(file_id):
    if not admin_ok():
        abort(403)
    try:
        db.collection("links").document(file_id).delete()
        try:
            rt.child(f"counters/{file_id}").delete()
        except Exception:
            pass
        return jsonify({"ok": True, "deleted": file_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ==================================================================
#  ERROR HANDLERS
# ==================================================================
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"ok": False, "error": e.description}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"ok": False, "error": "Forbidden"}), 403


# ==================================================================
#  RUN (local only — on Vercel this is ignored)
# ==================================================================
# Vercel WSGI entry point — required for @vercel/python
handler = app

if __name__ == "__main__":
    print("\n" + "=" * 74)
    print(f"🚀 Redirector           http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"📊 Admin panel          http://127.0.0.1:{SERVER_PORT}/admin?key={ADMIN_KEY}")
    print(f"🔑 Gate key             {GATE_KEY}")
    print(f"🌐 Public base URL      {PUBLIC_BASE_URL}")
    print(f"🔥 Firebase RTDB        {FIREBASE_RTDB_URL}")
    print("=" * 74 + "\n")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=SERVER_DEBUG)
