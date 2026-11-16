#!/usr/bin/env python3
"""Site-Engine: Schlanker, produktionsgehärteter Webshop- und Website-Server mit /admin-Cockpit.

Liefert die Webseite aus /data/site/public (Fallback: app/public) aus, nimmt
Bestellungen (POST /api/bestellung) und Kontaktanfragen (POST /api/kontakt) an
und bietet unter /admin ein Verwaltungs-UI. Nur Python-Standardbibliothek.

Admin-Zugang: «Sign in with Google» – erlaubte Konten in ADMIN_EMAILS, Client ID in
GOOGLE_CLIENT_ID (beides ConfigMap, kein Secret nötig). Notfall: Notfall-Codes im Admin
oder `python /app/server.py notfall-link`.
"""
import base64
import csv
import datetime as dt
import fcntl
import hashlib
import hmac
import html as htmllib
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import signal
import smtplib
import ssl
import struct
import sys
import threading
import time
import zipfile
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

# ---------------------------------------------------------------- Einstellungen
ENV = os.environ.get
PORT = int(ENV("PORT", "8080"))
PUBLIC_DIR = Path(ENV("PUBLIC_DIR", Path(__file__).with_name("public"))).resolve()
ADMIN_DIR = Path(ENV("ADMIN_DIR", Path(__file__).with_name("admin"))).resolve()
CONFIG_FILE = Path(ENV("CONFIG_FILE", Path(__file__).with_name("config") / "site.json")).resolve()
DATA_DIR = Path(ENV("DATA_DIR", "/data")).resolve()
TESTMODUS = ENV("TESTMODUS", "1") == "1"
TRUST_PROXY = ENV("TRUST_PROXY", "1") == "1"

# Login & Sitzungen
COOKIE_SECURE = ENV("COOKIE_SECURE", "1") == "1"
SESSION_COOKIE = "__Host-se_session" if COOKIE_SECURE else "se_session"
SESSION_IDLE = int(ENV("SESSION_IDLE", "7200"))        # 2 h Inaktivität
SESSION_MAX_AGE = int(ENV("SESSION_MAX_AGE", "43200"))  # max. 12 h
NONCE_COOKIE = "__Host-se_nonce" if COOKIE_SECURE else "se_nonce"
NOTFALL_TTL = 900            # Notfall-Link (CLI): 15 Min.
NOTFALL_TTL_INITIAL = 86400  # Notfall-Link beim Start ohne jede Anmeldemöglichkeit: 24 h
MAX_SETUP_TOKENS = 5
NOTFALL_CODE_COUNT = 10
GOOGLE_CERTS_URL = ENV("GOOGLE_CERTS_URL", "https://www.googleapis.com/oauth2/v3/certs")
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 900
LOGIN_GLOBAL_MAX = 50

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("site-engine")

ALLOWED_ASSET_EXTS = {".html", ".css", ".js", ".json", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".woff2", ".txt"}
ALLOWED_IMAGE_EXTS = {".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif"}
MAX_BODY = 32 * 1024
MAX_AUTH_BODY = 8 * 1024
MAX_ADMIN_BODY = 50 * 1024 * 1024  # 50 MB für ZIP-/Bild-Uploads im Admin-UI
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_TOTAL = 300 * 1024 * 1024
RATE_MAX = int(ENV("RATE_MAX", "5"))
RATE_WINDOW = int(ENV("RATE_WINDOW", "900"))


# ------------------------------------------------------------------ Dateipfade
def config_dir() -> Path:
    return (DATA_DIR / "site" / "config").resolve()


def custom_public_dir() -> Path:
    return (DATA_DIR / "site" / "public").resolve()


def custom_pages_dir() -> Path:
    return (DATA_DIR / "site" / "pages").resolve()


def custom_config_file() -> Path:
    return config_dir() / "site.json"


def custom_settings_file() -> Path:
    return config_dir() / "settings.json"


def auth_file() -> Path:
    return config_dir() / "auth.json"


def setup_token_file() -> Path:
    return config_dir() / "setup-token.json"


def bilder_file() -> Path:
    return config_dir() / "bilder.json"


def read_json(path: Path, default):
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Fehler beim Lesen von %s: %s", path, e)
        return default


def write_private_json(path: Path, data):
    """Schreibt atomar mit Dateirechten 0600 (nur der Engine-User kann lesen)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_runtime_settings() -> dict:
    d = read_json(custom_settings_file(), {})
    return d if isinstance(d, dict) else {}


def save_runtime_settings(data: dict):
    write_private_json(custom_settings_file(), data)


# ------------------------------------------------------------ Feature-Schalter
# Jedes Feature ist fest im Code verdrahtet und nur ein/aus: kein Plugin-Loading.
# Reihenfolge: Admin-UI (settings.json) > Umgebungsvariable FEATURE_<NAME> > Standard.
FEATURE_DEFAULTS = {"shop": "1", "kontakt": "0", "seo": "0", "wartung": "0"}
FEATURES = tuple(FEATURE_DEFAULTS)


def feature_enabled(name: str) -> bool:
    saved = load_runtime_settings().get("features")
    if isinstance(saved, dict) and name in saved:
        return bool(saved[name])
    return ENV("FEATURE_" + name.upper(), FEATURE_DEFAULTS.get(name, "0")) == "1"


# ------------------------------------------------------------------ Unterseiten
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
RESERVED_SLUGS = {"admin", "api", "healthz", "readyz", "img", "pages", "index", "static", "assets",
                  "robots", "sitemap"}
MAX_PAGE_BYTES = 1024 * 1024


def valid_slug(slug) -> bool:
    return isinstance(slug, str) and bool(SLUG_RE.match(slug)) and slug not in RESERVED_SLUGS


def page_file(slug: str) -> Path:
    # Der Slug ist per Regex auf [a-z0-9-] beschränkt -> kein Path-Traversal möglich.
    base = custom_pages_dir()
    f = (base / f"{slug}.html").resolve()
    if not valid_slug(slug) or not f.is_relative_to(base):
        raise ValueError("Ungültiger Seitenname")
    return f


def list_pages() -> list:
    base = custom_pages_dir()
    if not base.is_dir():
        return []
    out = []
    for f in sorted(base.glob("*.html")):
        if valid_slug(f.stem) and f.is_file():
            out.append({"slug": f.stem, "size": f.stat().st_size})
    return out


def active_index_file() -> Path:
    c_idx = custom_public_dir() / "index.html"
    if c_idx.is_file():
        return c_idx
    return PUBLIC_DIR / "index.html"


# ------------------------------------------------- Konfiguration & Katalog laden
def load_config_and_catalog(strict=True):
    cfg = {}
    for cpath in (CONFIG_FILE, custom_config_file()):
        if cpath.exists():
            try:
                cfg.update(json.loads(cpath.read_text(encoding="utf-8")))
                log.info("Konfiguration aus %s geladen", cpath)
            except Exception as e:
                log.warning("Fehler beim Lesen von %s: %s", cpath, e)

    # Wenn in der aktiven index.html ein <script id="produkte"> Block existiert, hat dieser Vorrang
    idx_file = active_index_file()
    if idx_file.exists():
        try:
            text = idx_file.read_text(encoding="utf-8")
            m = re.search(r'<script id="produkte" type="application/json">(.*?)</script>', text, re.S)
            if m:
                html_catalog = json.loads(m.group(1))
                cfg.update(html_catalog)
        except Exception as e:
            log.warning("Fehler beim Lesen des Katalogs aus %s: %s", idx_file, e)

    if "produkte" not in cfg:
        if strict and feature_enabled("shop"):
            raise SystemExit("Produktliste weder in site.json noch in public/index.html gefunden")
        cfg["produkte"] = []

    for p in cfg.get("produkte", []):
        if "preis" not in p and "price" in p:
            p["preis"] = p["price"]
    cfg["by_id"] = {p["id"]: p for p in cfg.get("produkte", [])}
    return cfg


CAT = load_config_and_catalog()


def reload_catalog():
    global CAT
    CAT = load_config_and_catalog(strict=False)
    return CAT


# Einstellungen: Umgebungsvariable überschreibt site.json, Fallback auf Standardwert
SHOP_NAME = ENV("SHOP_NAME", CAT.get("shop_name", "Shop"))
SHOP_URL = ENV("SHOP_URL", CAT.get("shop_url", "https://example.com"))
SHOP_ADDRESS = ENV("SHOP_ADDRESS", CAT.get("shop_address", ""))
CURRENCY = ENV("CURRENCY", CAT.get("currency", "CHF"))
ORDER_PREFIX = ENV("ORDER_PREFIX", CAT.get("order_prefix", "ORD"))
MAIL_TO = ENV("MAIL_TO", CAT.get("contact_email", "admin@example.com"))
SMTP_HOST = ENV("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(ENV("SMTP_PORT", "465"))
SMTP_USER = ENV("SMTP_USER", "")
SMTP_PASS = ENV("SMTP_PASS", "")
MAIL_FROM = ENV("MAIL_FROM", SMTP_USER or MAIL_TO)


def fmt_money(n):
    return f"{float(n):.2f}"


# ------------------------------------------------------------------ Validierung
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class Fehler(Exception):
    pass


def clean(v, n):
    v = str(v or "").strip()
    v = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", v)
    if len(v) > n:
        raise Fehler("Eine Eingabe ist zu lang.")
    return v


def one_line(v, n):
    """Wie clean(), aber ohne Zeilenumbrüche (für Betreff, Namen, Header)."""
    return re.sub(r"\s+", " ", clean(v, n)).strip()


def clip(v, n):
    v = re.sub(r"[\x00-\x1f\x7f]", " ", str(v or "")).strip()
    return v[:n]


def validate(payload):
    if not isinstance(payload, dict):
        raise Fehler("Ungültige Anfrage.")
    # Honigtopf gegen Bots
    if payload.get("website"):
        raise Fehler("Ungültige Anfrage.")
    if "agb" in payload and not payload.get("agb"):
        raise Fehler("Bitte bestätige die AGB.")

    k = payload.get("kunde") or {}
    # Unterstützt sowohl {adresse, plz_ort} als auch {strasse, plz, ort}
    strasse = clean(k.get("strasse") or k.get("adresse"), 120)
    plz = clean(k.get("plz"), 10)
    ort = clean(k.get("ort"), 80)
    if "plz" in k or "ort" in k:
        if not re.fullmatch(r"[1-9]\d{3}", plz):
            raise Fehler("Bitte gib eine Schweizer Postleitzahl mit 4 Ziffern ein.")
        if len(ort) < 2:
            raise Fehler("Bitte gib den Ort ein.")
        plz_ort = f"{plz} {ort}".strip()
    else:
        plz_ort = clean(k.get("plz_ort"), 80)

    kunde = {
        "name": one_line(k.get("name"), 80),
        "adresse": strasse,
        "strasse": strasse,
        "plz": plz,
        "ort": ort,
        "plz_ort": plz_ort,
        "email": clean(k.get("email"), 120),
        "telefon": one_line(k.get("telefon"), 40),
    }
    for field in ("name", "adresse", "plz_ort", "email"):
        if not kunde[field]:
            raise Fehler("Bitte fülle alle Pflichtfelder der Adresse aus.")
    if not EMAIL_RE.match(kunde["email"]):
        raise Fehler("Bitte gib eine gültige E-Mail-Adresse ein.")

    raw_pos = payload.get("positionen") if "positionen" in payload else payload.get("items")
    if not isinstance(raw_pos, list) or not raw_pos or len(raw_pos) > 30:
        raise Fehler("Der Warenkorb ist leer oder zu gross.")

    motive_set = set(CAT.get("motive", []))
    positionen, subtotal = [], 0
    for it in raw_pos:
        if not isinstance(it, dict):
            raise Fehler("Ungültige Anfrage.")
        pid = str(it.get("id") or "")
        p = CAT["by_id"].get(pid)
        if not p:
            raise Fehler("Ein ausgewähltes Produkt existiert nicht.")
        try:
            qty = int(it.get("qty", 0))
        except (ValueError, TypeError):
            qty = 0
        if qty < 1 or qty > 50:
            raise Fehler("Ungültige Menge (erlaubt: 1 bis 50 pro Position).")

        motive = it.get("motive") or []
        expected_motive = int(p.get("motive", 0))
        if not isinstance(motive, list) or len(motive) != expected_motive:
            raise Fehler("Bitte wähle für jedes Produkt die richtige Anzahl Motive.")
        for m in motive:
            if m not in motive_set:
                raise Fehler("Ein gewähltes Motiv ist ungültig.")

        unit_price = p.get("preis", p.get("price", 0))
        betrag = unit_price * qty
        subtotal += betrag
        positionen.append({
            "id": pid,
            "name": p["name"],
            "groesse": p.get("groesse", ""),
            "preis": unit_price,
            "qty": qty,
            "motive": motive,
            "betrag": betrag,
        })

    v_rule = CAT.get("versand", {"preis": 0, "gratis_ab_betrag": 0})
    versand = 0 if subtotal >= v_rule.get("gratis_ab_betrag", 0) else v_rule.get("preis", 0)
    total = subtotal + versand

    zahlung = clean(payload.get("zahlung"), 20)
    if zahlung not in ("Twint", "Rechnung"):
        zahlung = "Rechnung"

    return {
        "kunde": kunde,
        "positionen": positionen,
        "zwischensumme": subtotal,
        "versand": versand,
        "total": total,
        "nachricht": clean(payload.get("nachricht"), 1000),
        "zahlung": zahlung,
    }


def validate_contact(payload):
    if not isinstance(payload, dict) or payload.get("website"):
        raise Fehler("Ungültige Anfrage.")
    msg = {
        "name": one_line(payload.get("name"), 80),
        "email": clean(payload.get("email"), 120),
        "telefon": one_line(payload.get("telefon"), 40),
        "betreff": one_line(payload.get("betreff"), 120),
        "nachricht": clean(payload.get("nachricht"), 5000),
    }
    if not msg["name"] or not msg["nachricht"]:
        raise Fehler("Bitte fülle Name und Nachricht aus.")
    if not EMAIL_RE.match(msg["email"]):
        raise Fehler("Bitte gib eine gültige E-Mail-Adresse ein.")
    return msg


# ------------------------------------------------------------- Rate-Limiter
RATES, RATES_LOCK = {}, threading.Lock()


def check_rate(ip):
    now = time.time()
    with RATES_LOCK:
        if len(RATES) > 1000:
            expired = [k for k, v in RATES.items() if not v or (now - v[-1] >= RATE_WINDOW)]
            for k in expired:
                del RATES[k]
        times = [t for t in RATES.get(ip, []) if now - t < RATE_WINDOW]
        if len(times) >= RATE_MAX:
            return False
        times.append(now)
        RATES[ip] = times
    return True


# ------------------------------------------------------ Anmeldung mit Google
# «Sign in with Google» (Google Identity Services): Der Browser erhält von Google ein
# signiertes ID-Token (JWT, RS256) und schickt es an /admin/google. Der Server prüft
# Signatur (Googles öffentliche Schlüssel), Aussteller, Client ID, Ablauf, Nonce und die
# bestätigte E-Mail gegen die Liste erlaubter Konten. Es braucht KEIN Client Secret:
# Die Client ID ist öffentlich und darf in der ConfigMap stehen (GOOGLE_CLIENT_ID).
AUTH_LOCK = threading.Lock()
CLIENT_ID_RE = re.compile(r"^[0-9]{6,30}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com$")


class AuthFehler(Exception):
    pass


def load_auth() -> dict:
    d = read_json(auth_file(), {})
    return d if isinstance(d, dict) else {}


def save_auth(d: dict):
    write_private_json(auth_file(), d)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def norm_email(e) -> str:
    return str(e or "").strip().lower()


def env_admin_emails() -> list:
    out = {norm_email(e) for e in re.split(r"[,;\s]+", ENV("ADMIN_EMAILS", "")) if e.strip()}
    return sorted(e for e in out if EMAIL_RE.match(e))


def admin_emails(a=None) -> list:
    """Erlaubte Google-Konten: ADMIN_EMAILS (ConfigMap) + im Admin hinzugefügte."""
    a = load_auth() if a is None else a
    ui = [norm_email(e) for e in a.get("emails") or [] if EMAIL_RE.match(norm_email(e))]
    return sorted(set(env_admin_emails()) | set(ui))


def google_client_id(a=None) -> str:
    env = ENV("GOOGLE_CLIENT_ID", "").strip()
    if env:
        return env
    a = load_auth() if a is None else a
    return str(a.get("google_client_id") or "").strip()


def b64url_decode(s) -> bytes:
    s = str(s)
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("kein base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_sha256_verify(n: int, e: int, msg: bytes, sig: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 / SHA-256 (RFC 8017). Verglichen wird die GESAMTE erwartete
    Kodierung statt die Padding-Struktur zu parsen – das schliesst Signaturfälschungen
    (Bleichenbacher 2006) aus. Nur Schlüssel >= 2048 Bit mit e = 65537."""
    k = (n.bit_length() + 7) // 8
    if n.bit_length() < 2048 or e != 65537 or len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = SHA256_DIGEST_INFO + hashlib.sha256(msg).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


JWKS = {"keys": {}, "expires": 0.0, "fetched": 0.0}
JWKS_LOCK = threading.Lock()


def _fetch_google_keys():
    import urllib.request
    req = urllib.request.Request(GOOGLE_CERTS_URL, headers={"User-Agent": "site-engine"})
    with urllib.request.urlopen(req, timeout=5) as r:
        cache = r.headers.get("Cache-Control", "")
        data = json.loads(r.read(256 * 1024).decode("utf-8"))
    m = re.search(r"max-age=(\d+)", cache)
    ttl = min(int(m.group(1)), 86400) if m else 3600
    keys = {}
    for k in data.get("keys", []) if isinstance(data, dict) else []:
        if (isinstance(k, dict) and k.get("kty") == "RSA" and k.get("kid") and k.get("alg", "RS256") == "RS256"
                and k.get("use", "sig") == "sig"):
            keys[str(k["kid"])] = (int.from_bytes(b64url_decode(k["n"]), "big"), int.from_bytes(b64url_decode(k["e"]), "big"))
    return keys, ttl


def google_key(kid: str):
    """Öffentlicher Schlüssel zu `kid`. Cache gemäss Cache-Control; bei unbekanntem kid
    neu laden (höchstens alle 30 s). Ist Google kurz nicht erreichbar, gilt der alte Cache."""
    now = time.time()
    with JWKS_LOCK:
        if (kid not in JWKS["keys"] or now >= JWKS["expires"]) and now - JWKS["fetched"] >= 30:
            JWKS["fetched"] = now
            try:
                keys, ttl = _fetch_google_keys()
                JWKS["keys"], JWKS["expires"] = keys, now + ttl
            except Exception as e:
                log.warning("Google-Schlüssel konnten nicht geladen werden: %s", e)
        return JWKS["keys"].get(kid)


def verify_google_token(token, client_id: str, nonce: str, now=None) -> dict:
    """Prüft ein Google-ID-Token vollständig und gibt die Claims zurück (sonst AuthFehler)."""
    if not client_id:
        raise AuthFehler("Google-Anmeldung ist noch nicht eingerichtet")
    if not isinstance(token, str) or len(token) > 8192 or token.count(".") != 2:
        raise AuthFehler("ungültiges Token")
    h64, p64, s64 = token.split(".")
    try:
        header = json.loads(b64url_decode(h64))
        claims = json.loads(b64url_decode(p64))
        sig = b64url_decode(s64)
    except (ValueError, UnicodeDecodeError):
        raise AuthFehler("ungültiges Token")
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get("alg") != "RS256":
        raise AuthFehler("ungültiges Token")
    key = google_key(str(header.get("kid") or ""))
    if not key or not rsa_sha256_verify(key[0], key[1], f"{h64}.{p64}".encode("ascii"), sig):
        raise AuthFehler("Signatur ungültig")
    now = time.time() if now is None else now
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise AuthFehler("falscher Aussteller")
    if claims.get("aud") != client_id:
        raise AuthFehler("Token gehört zu einer anderen Anwendung")
    exp, iat = claims.get("exp"), claims.get("iat")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp < now - 60:
        raise AuthFehler("Token abgelaufen")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool) or iat > now + 300:
        raise AuthFehler("ungültiger Ausstellungszeitpunkt")
    tn = claims.get("nonce")
    if not nonce or not isinstance(tn, str) or not hmac.compare_digest(tn.encode(), nonce.encode()):
        raise AuthFehler("Anmeldung abgelaufen, bitte Seite neu laden")
    if claims.get("email_verified") not in (True, "true"):
        raise AuthFehler("E-Mail-Adresse ist bei Google nicht bestätigt")
    email = norm_email(claims.get("email"))
    if not EMAIL_RE.match(email):
        raise AuthFehler("keine E-Mail-Adresse im Token")
    return dict(claims, email=email)


USED_NONCES, NONCE_LOCK = {}, threading.Lock()


def nonce_unused(nonce: str) -> bool:
    """Jede Nonce (und damit jedes Google-Token) gilt nur für EINE Anmeldung (Replay-Schutz)."""
    now = time.time()
    with NONCE_LOCK:
        for k in [k for k, exp in USED_NONCES.items() if exp < now]:
            del USED_NONCES[k]
        if nonce in USED_NONCES or len(USED_NONCES) > 10000:
            return False
        USED_NONCES[nonce] = now + 3600
        return True


# Notfall-Codes (wie bei GitHub): 10 Einmal-Codes für den Fall, dass Google nicht geht.
def new_notfall_codes() -> list:
    codes = [base64.b32encode(secrets.token_bytes(10)).decode() for _ in range(NOTFALL_CODE_COUNT)]
    return ["-".join(c[i:i + 4] for i in range(0, 16, 4)) for c in codes]


def norm_notfall_code(code) -> str:
    return re.sub(r"[^A-Z2-7]", "", str(code or "").upper())[:32]


def use_notfall_code(code):
    """Muss unter AUTH_LOCK aufgerufen werden. Gibt die Anzahl übriger Codes oder None zurück."""
    c = norm_notfall_code(code)
    if len(c) != 16:
        return None
    a = load_auth()
    hashes = [h for h in a.get("notfall_codes") or [] if isinstance(h, str)]
    h = sha256_hex(c).encode()
    for i, stored in enumerate(hashes):
        if hmac.compare_digest(h, stored.encode()):
            del hashes[i]
            a["notfall_codes"] = hashes
            save_auth(a)
            return len(hashes)
    return None


# Notfall-Link (letzter Ausweg per CLI): öffnet direkt eine Admin-Sitzung.
def _load_setup_tokens() -> list:
    d = read_json(setup_token_file(), {})
    toks = d.get("tokens") if isinstance(d, dict) else None
    if not isinstance(toks, list):
        toks = []
    now = time.time()
    return [t for t in toks if isinstance(t, dict) and t.get("hash") and float(t.get("expires", 0)) > now]


def create_setup_token(ttl: int = NOTFALL_TTL, force: bool = False):
    """Einmal-Token; gespeichert wird nur der SHA-256-Hash. Bestehende werden nie
    überschrieben; sind MAX_SETUP_TOKENS aktiv, gibt es (ausser mit force) keinen neuen."""
    toks = _load_setup_tokens()
    if len(toks) >= MAX_SETUP_TOKENS:
        if not force:
            return None
        toks = sorted(toks, key=lambda t: float(t["expires"]))[-(MAX_SETUP_TOKENS - 1):]
    tok = secrets.token_urlsafe(32)
    toks.append({"hash": sha256_hex(tok), "expires": time.time() + ttl})
    write_private_json(setup_token_file(), {"tokens": toks})
    return tok


def check_setup_token(tok) -> bool:
    if not isinstance(tok, str) or not tok or len(tok) > 200:
        return False
    h = sha256_hex(tok).encode()
    return any(hmac.compare_digest(h, str(t["hash"]).encode()) for t in _load_setup_tokens())


def clear_setup_tokens():
    setup_token_file().unlink(missing_ok=True)


def consume_setup_token(tok) -> bool:
    if check_setup_token(tok):
        clear_setup_tokens()
        return True
    return False


def log_setup_link(tok: str, ttl: int, reason: str):
    base = site_base_url()
    log.warning("=" * 72)
    log.warning("ADMIN-%s – Notfall-Link (gültig %s):", reason, f"{ttl // 3600} h" if ttl >= 3600 else f"{ttl // 60} Min.")
    log.warning("  %s/admin/setup#%s", base or "https://<deine-domain>", tok)
    log.warning("=" * 72)


SESSIONS, SESS_LOCK = {}, threading.Lock()


def new_session(email: str = ""):
    tok = secrets.token_urlsafe(32)
    now = time.time()
    sess = {"csrf": secrets.token_urlsafe(32), "created": now, "seen": now, "email": email}
    with SESS_LOCK:
        for k in [k for k, s in SESSIONS.items() if session_expired(s, now)]:
            del SESSIONS[k]
        while len(SESSIONS) >= 100:
            del SESSIONS[min(SESSIONS, key=lambda k: SESSIONS[k]["seen"])]
        SESSIONS[sha256_hex(tok)] = sess
    return tok, sess


def session_expired(s, now):
    return now - s["seen"] > SESSION_IDLE or now - s["created"] > SESSION_MAX_AGE


def get_session(tok):
    if not tok or len(tok) > 200:
        return None
    key = sha256_hex(tok)
    now = time.time()
    with SESS_LOCK:
        s = SESSIONS.get(key)
        if not s:
            return None
        if session_expired(s, now):
            del SESSIONS[key]
            return None
        s["seen"] = now
        return dict(s, key=key)


def drop_sessions(keep_key=None):
    with SESS_LOCK:
        for k in [k for k in SESSIONS if k != keep_key]:
            del SESSIONS[k]


FAILS, GLOBAL_FAILS, FAILS_LOCK = {}, [], threading.Lock()


def _prune_fails(now):
    GLOBAL_FAILS[:] = [t for t in GLOBAL_FAILS if now - t < LOGIN_WINDOW]
    for ip in list(FAILS):
        FAILS[ip] = [t for t in FAILS[ip] if now - t < LOGIN_WINDOW]
        if not FAILS[ip]:
            del FAILS[ip]


def login_blocked(ip) -> bool:
    now = time.time()
    with FAILS_LOCK:
        _prune_fails(now)
        return len(FAILS.get(ip, [])) >= LOGIN_MAX_FAILS or len(GLOBAL_FAILS) >= LOGIN_GLOBAL_MAX


def login_failed(ip):
    now = time.time()
    with FAILS_LOCK:
        FAILS.setdefault(ip, []).append(now)
        GLOBAL_FAILS.append(now)
        if len(FAILS) > 5000:
            _prune_fails(now)


def login_succeeded(ip):
    with FAILS_LOCK:
        FAILS.pop(ip, None)


def migrate_legacy_auth():
    """Entfernt Passwort-Altlasten (1.x: settings.json, 2.0-rc.1: auth.json). Anmeldung nur noch über Google."""
    s = load_runtime_settings()
    if any(k in s for k in ("admin_user", "admin_password_hash")):
        for k in ("admin_user", "admin_password_hash"):
            s.pop(k, None)
        save_runtime_settings(s)
        log.info("Altes Admin-Passwort aus settings.json entfernt (Anmeldung jetzt mit Google).")
    with AUTH_LOCK:
        a = load_auth()
        old = [k for k in ("pw", "totp", "totp_pending", "geaendert", "email") if k in a]
        if old:
            for k in old:
                a.pop(k)
            save_auth(a)
            log.info("Passwort-/2FA-Daten aus auth.json entfernt (Anmeldung jetzt mit Google).")
    for k in ("ADMIN_USER", "ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH", "ADMIN_EMAIL"):
        if ENV(k):
            log.warning("Umgebungsvariable %s wird nicht mehr unterstützt und ignoriert.", k)


def admin_login_possible(a=None) -> bool:
    a = load_auth() if a is None else a
    return bool((google_client_id(a) and admin_emails(a)) or a.get("notfall_codes"))


# ---------------------------------------------------------------- Speichern
STORE_LOCK = threading.Lock()
SHOP_ADMIN_PATHS = {"/api/admin/catalog"}


def sanitize_csv(v):
    """Verhindert CSV/Formula-Injection in Excel/Calc (CWE-1236)."""
    s = str(v or "")
    if s.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + s
    return s


def next_order_number(year):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cfile = DATA_DIR / f"zaehler-{year}.txt"
    with open(cfile, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        c = f.read().strip()
        n = int(c) + 1 if c.isdigit() else 1
        f.seek(0)
        f.truncate()
        f.write(str(n) + "\n")
        f.flush()
        fcntl.flock(f, fcntl.LOCK_UN)
    prefix = get_effective_settings()["order_prefix"]
    return f"{prefix}-{year}-{n:03d}"


def save_order(o):
    now = dt.datetime.now(dt.timezone.utc).astimezone()
    o["datum"] = now.strftime("%Y-%m-%d %H:%M:%S")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with STORE_LOCK:
        o["bestellnummer"] = next_order_number(now.year)

        jsonl = DATA_DIR / "bestellungen.jsonl"
        with open(jsonl, "a", encoding="utf-8") as f:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")

        csv_path = DATA_DIR / "bestellungen.csv"
        neu = not csv_path.exists()
        fields = ["Bestellnummer", "Datum", "Name", "Adresse", "PLZ_Ort", "E-Mail", "Telefon",
                  "Zahlung", "Positionen", "Zwischensumme", "Versand", "Total", "Nachricht"]
        with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields, delimiter=";")
            if neu:
                w.writeheader()
            pos_txt = " | ".join(f"{p['qty']}x {p['name']}" +
                                 (f" ({', '.join(p['motive'])})" if p["motive"] else "")
                                 for p in o["positionen"])
            k = o["kunde"]
            w.writerow({
                "Bestellnummer": o["bestellnummer"],
                "Datum": o["datum"],
                "Name": sanitize_csv(k["name"]),
                "Adresse": sanitize_csv(k["adresse"]),
                "PLZ_Ort": sanitize_csv(k["plz_ort"]),
                "E-Mail": sanitize_csv(k["email"]),
                "Telefon": sanitize_csv(k["telefon"]),
                "Zahlung": sanitize_csv(o["zahlung"]),
                "Positionen": sanitize_csv(pos_txt),
                "Zwischensumme": fmt_money(o["zwischensumme"]),
                "Versand": fmt_money(o["versand"]),
                "Total": fmt_money(o["total"]),
                "Nachricht": sanitize_csv(o["nachricht"])
            })
    return o["bestellnummer"]


def messages_file() -> Path:
    return DATA_DIR / "nachrichten.jsonl"


def save_message(m: dict) -> dict:
    m = dict(m, id=secrets.token_hex(8),
             datum=dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with STORE_LOCK:
        with open(messages_file(), "a", encoding="utf-8") as f:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    return m


def read_jsonl(path: Path) -> list:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return list(reversed(out))


def read_orders():
    return read_jsonl(DATA_DIR / "bestellungen.jsonl")


def delete_message(msg_id: str) -> bool:
    """Muss unter STORE_LOCK aufgerufen werden."""
    f = messages_file()
    if not f.is_file():
        return False
    keep, found = [], False
    for line in f.read_text(encoding="utf-8").splitlines():
        try:
            if json.loads(line).get("id") == msg_id:
                found = True
                continue
        except Exception:
            pass
        if line.strip():
            keep.append(line)
    tmp = f.with_name(f.name + ".tmp")
    tmp.write_text("".join(x + "\n" for x in keep), encoding="utf-8")
    os.replace(tmp, f)
    return found


# ------------------------------------------------------------- E-Mail-Versand
def summary(o):
    out = [f"Bestellung {o['bestellnummer']} – {o['datum']}", ""]
    k = o["kunde"]
    out.append(f"Lieferadresse:\n{k['name']}\n{k['adresse']}\n{k['plz_ort']}\n")
    out.append(f"Zahlung: {o['zahlung']}\n\nPositionen:")
    for p in o["positionen"]:
        m = f" ({', '.join(p['motive'])})" if p["motive"] else ""
        out.append(f"{p['qty']} × {p['name']} {p['groesse']}{m}   {CURRENCY} {fmt_money(p['betrag'])}")
    out.append("")
    out.append(
        f"Zwischensumme: {CURRENCY} {fmt_money(o['zwischensumme'])}\n"
        f"Versand: {'gratis' if o['versand'] == 0 else CURRENCY + ' ' + fmt_money(o['versand'])}\n"
        f"Total: {CURRENCY} {fmt_money(o['total'])}\n\n"
    )
    return "\n".join(out)


def get_effective_settings() -> dict:
    s = load_runtime_settings()
    testmodus = s.get("testmodus")
    if testmodus is None:
        testmodus = TESTMODUS
    else:
        testmodus = bool(testmodus)
    smtp_user = str(s.get("smtp_user") if "smtp_user" in s else SMTP_USER).strip()
    mail_to = str(s.get("mail_to") if "mail_to" in s else MAIL_TO).strip()
    return {
        "shop_name": str(s.get("shop_name") or SHOP_NAME).strip(),
        "shop_url": str(s.get("shop_url") or SHOP_URL).strip(),
        "shop_address": str(s.get("shop_address") if "shop_address" in s else SHOP_ADDRESS).strip(),
        "order_prefix": str(s.get("order_prefix") or ORDER_PREFIX).strip(),
        "mail_to": mail_to,
        "smtp_host": str(s.get("smtp_host") or SMTP_HOST).strip(),
        "smtp_port": int(s.get("smtp_port") or SMTP_PORT),
        "smtp_user": smtp_user,
        "smtp_pass": str(s.get("smtp_pass") if "smtp_pass" in s else SMTP_PASS),
        "mail_from": smtp_user or mail_to or MAIL_FROM,
        "testmodus": testmodus,
        "seo_titel": str(s.get("seo_titel") or "").strip(),
        "seo_beschreibung": str(s.get("seo_beschreibung") or "").strip(),
        "seo_bild": str(s.get("seo_bild") or "").strip(),
        "wartung_titel": str(s.get("wartung_titel") or "Wir sind bald zurück").strip(),
        "wartung_text": str(s.get("wartung_text") or "Die Webseite wird gerade überarbeitet. Bitte schau später wieder vorbei.").strip(),
    }


def site_base_url() -> str:
    """Öffentliche Basis-URL (für Sitemap, Canonical, Setup-Link) oder '' wenn nicht gesetzt."""
    u = get_effective_settings()["shop_url"].rstrip("/")
    if not re.match(r"^https?://[^/\s]+", u) or "example.com" in u:
        return ""
    return u


def send_mail(to, subject, body, reply_to=None, force_live=False):
    cfg = get_effective_settings()
    msg = EmailMessage()
    msg["Subject"] = one_line(subject, 300)
    msg["From"] = formataddr((one_line(cfg["shop_name"], 120), cfg["mail_from"]))
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain=re.sub(r"[^a-z0-9.-]", "", cfg["shop_name"].lower()) + ".internal")
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(body)

    if cfg["testmodus"] and not force_live:
        log.info("[TESTMODUS] E-Mail an %s NICHT gesendet. Betreff: %s", to, subject)
        return
    if not cfg["smtp_user"] or not cfg["smtp_pass"]:
        raise RuntimeError("SMTP-Benutzer oder SMTP-Passwort ist noch nicht hinterlegt.")
    ctx = ssl.create_default_context()
    if cfg["smtp_port"] == 465:
        with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], context=ctx, timeout=20) as s:
            s.login(cfg["smtp_user"], cfg["smtp_pass"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=20) as s:
            s.starttls(context=ctx)
            s.login(cfg["smtp_user"], cfg["smtp_pass"])
            s.send_message(msg)


def notify(o):
    cfg = get_effective_settings()
    k, nr = o["kunde"], o["bestellnummer"]
    shop_body = (f"Neue Bestellung {nr} vom {o['datum']}\n\n{summary(o)}\n\n"
                 f"E-Mail: {k['email']}\nTelefon: {k['telefon'] or '–'}\n"
                 f"Nachricht: {o['nachricht'] or '–'}\n\n"
                 f"Zahlungsart: {o.get('zahlung', 'Rechnung')}")
    kunde_body = (f"Hallo {k['name'].split()[0]}\n\n"
                  f"Danke für deine Bestellung bei {cfg['shop_name']}! Wir haben sie erhalten.\n\n"
                  f"Bestellnummer: {nr}\n\n{summary(o)}\n\n"
                  f"Als Nächstes schicken wir dir die "
                  f"{'Twint-Zahlungsanfrage' if o.get('zahlung') == 'Twint' else 'Rechnung (zahlbar innert 10 Tagen)'}. "
                  f"Nach dem Zahlungseingang wird deine Bestellung bearbeitet und versendet.\n\n"
                  f"Fragen? Antworte einfach auf diese E-Mail.\n\n"
                  f"Liebe Grüsse\n{cfg['shop_name']}\n{cfg['shop_address']}\n{cfg['shop_url']}".strip())
    ok = True
    for to, subj, body, rt in ((cfg["mail_to"], f"Neue Bestellung {nr} – {CURRENCY} {fmt_money(o['total'])}", shop_body, k["email"]),
                               (k["email"], f"Deine Bestellung {nr} bei {cfg['shop_name']}", kunde_body, cfg["mail_to"])):
        try:
            send_mail(to, subj, body, rt)
        except Exception as e:
            ok = False
            log.error("E-Mail an %s fehlgeschlagen (%s): %s", to, nr, e)
    return ok


def notify_contact(m) -> bool:
    """Nur an den Betreiber. Bewusst keine automatische Antwort an den Absender:
    sonst liesse sich das Formular nutzen, um Dritten E-Mails zu schicken."""
    cfg = get_effective_settings()
    body = (f"Neue Kontaktanfrage über {cfg['shop_url']}\n\n"
            f"Name: {m['name']}\nE-Mail: {m['email']}\nTelefon: {m['telefon'] or '–'}\n"
            f"Betreff: {m['betreff'] or '–'}\nDatum: {m['datum']}\n\n{m['nachricht']}\n")
    try:
        send_mail(cfg["mail_to"], f"Kontaktanfrage: {m['betreff'] or m['name']}", body, reply_to=m["email"])
        return True
    except Exception as e:
        log.error("Kontakt-E-Mail fehlgeschlagen (%s): %s", m["id"], e)
        return False


# ------------------------------------------------------------------- Bilder
# Bereiche = Ordner unter img/ im Kunden-Verzeichnis. Eine optionale bilder.json
# (im ZIP) legt Titel, Beschreibung, Maximalanzahl, Format und Beschriftungen fest.
FOLDER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
IMG_SIZE_CACHE = {}


def folder_ok_loose(folder: str) -> bool:
    if folder == "":
        return True
    parts = folder.split("/")
    return (len(parts) <= 4 and len(folder) <= 120 and
            all(p and p not in (".", "..") and not re.search(r"[\x00-\x1f\x7f\\]", p) for p in parts))


def norm_folder(v, strict=False) -> str:
    f = str(v or "").strip().strip("/")
    if f == "img":
        f = ""
    elif f.startswith("img/"):
        f = f[4:]
    if strict:
        f = f.lower()
        if f and not all(FOLDER_RE.match(p) for p in f.split("/")) or f.count("/") > 2:
            raise Fehler("Ungültiger Ordnername (erlaubt: a-z, 0-9, - und _).")
    elif not folder_ok_loose(f):
        raise Fehler("Ungültiger Ordner.")
    return f


def folder_title(folder: str) -> str:
    if not folder:
        return "Allgemein"
    return re.sub(r"[-_]+", " ", folder.split("/")[-1]).strip().capitalize() or folder


def norm_img_path(v):
    """'img/...'-Pfad mit erlaubter Endung ohne Traversal oder None."""
    p = unquote(str(v or "")).split("?")[0].split("#")[0].replace("\\", "/").lstrip("/")
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if len(parts) < 2 or parts[0] != "img" or ".." in parts:
        return None
    if Path(parts[-1]).suffix.lower() not in ALLOWED_IMAGE_EXTS:
        return None
    if not folder_ok_loose("/".join(parts[1:-1])):
        return None
    return "/".join(parts)


def folder_of(rel: str) -> str:
    parent = rel.rsplit("/", 1)[0]
    return parent[4:] if parent.startswith("img/") else ""


def safe_image_name(name) -> str:
    base = Path(str(name or "").replace("\\", "/")).name.lower()
    stem, ext = os.path.splitext(base)
    if ext == ".jpeg":
        ext = ".jpg"
    if ext not in ALLOWED_IMAGE_EXTS:
        raise Fehler("Nicht erlaubter Dateityp (erlaubt: PNG, JPG, WEBP, GIF, SVG).")
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem).strip("-._")[:80] or "bild"
    return stem + ext


def sniff_image(data: bytes, ext: str) -> bool:
    """Prüft die Magic Bytes, damit z. B. kein HTML als .png hochgeladen wird."""
    if ext == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in (".jpg", ".jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == ".gif":
        return data[:6] in (b"GIF87a", b"GIF89a")
    if ext == ".webp":
        return data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    if ext == ".svg":
        head = data[:4096].lstrip(b"\xef\xbb\xbf").lstrip().lower()
        return head.startswith(b"<svg") or (head.startswith((b"<?xml", b"<!--", b"<!doctype svg")) and b"<svg" in head)
    return False


def image_size(d: bytes):
    """Breite/Höhe aus dem Datei-Header (PNG, GIF, JPEG, WebP) oder None."""
    try:
        if d.startswith(b"\x89PNG") and d[12:16] == b"IHDR":
            return struct.unpack(">II", d[16:24])
        if d[:6] in (b"GIF87a", b"GIF89a"):
            return struct.unpack("<HH", d[6:10])
        if d[:4] == b"RIFF" and d[8:12] == b"WEBP":
            kind = d[12:16]
            if kind == b"VP8 ":
                w, h = struct.unpack("<HH", d[26:30])
                return w & 0x3FFF, h & 0x3FFF
            if kind == b"VP8L":
                b = int.from_bytes(d[21:25], "little")
                return (b & 0x3FFF) + 1, ((b >> 14) & 0x3FFF) + 1
            if kind == b"VP8X":
                return int.from_bytes(d[24:27], "little") + 1, int.from_bytes(d[27:30], "little") + 1
        if d.startswith(b"\xff\xd8"):
            i = 2
            while i + 9 < len(d):
                if d[i] != 0xFF:
                    i += 1
                    continue
                m = d[i + 1]
                if m == 0xFF:
                    i += 1
                    continue
                if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
                    i += 2
                    continue
                seg_len = struct.unpack(">H", d[i + 2:i + 4])[0]
                if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", d[i + 5:i + 9])
                    return w, h
                i += 2 + seg_len
    except (struct.error, IndexError):
        pass
    return None


def cached_image_size(f: Path):
    st = f.stat()
    key = (str(f), st.st_mtime_ns, st.st_size)
    if key not in IMG_SIZE_CACHE:
        if len(IMG_SIZE_CACHE) > 5000:
            IMG_SIZE_CACHE.clear()
        with open(f, "rb") as fh:
            IMG_SIZE_CACHE[key] = image_size(fh.read(256 * 1024))
    return IMG_SIZE_CACHE[key]


def parse_manifest(obj) -> dict:
    """Validiert eine bilder.json. Unbekanntes wird ignoriert, nie ausgeführt."""
    if not isinstance(obj, dict):
        raise Fehler("bilder.json: Objekt erwartet.")
    out = {"bereiche": [], "nur_bereiche": obj.get("nur_bereiche") is True, "bilder": {}}
    for b in (obj.get("bereiche") or [])[:50]:
        if not isinstance(b, dict):
            continue
        try:
            folder = norm_folder(b.get("ordner", ""))
        except Fehler:
            continue
        if any(x["ordner"] == folder for x in out["bereiche"]):
            continue
        mx = b.get("max")
        mx = int(mx) if isinstance(mx, int) and not isinstance(mx, bool) and 0 < mx <= 1000 else None
        fmt = str(b.get("format") or "")
        out["bereiche"].append({
            "ordner": folder,
            "titel": clip(b.get("titel"), 80) or folder_title(folder),
            "beschreibung": clip(b.get("beschreibung"), 300),
            "max": mx,
            "format": fmt if re.fullmatch(r"[1-9]\d?:[1-9]\d?", fmt) else "",
            "beschriftung": b.get("beschriftung", True) is not False,
        })
    bilder = obj.get("bilder")
    if isinstance(bilder, dict):
        for p, m in list(bilder.items())[:5000]:
            p = norm_img_path(p)
            if p and isinstance(m, dict):
                out["bilder"][p] = {"text": clip(m.get("text"), 300), "alt": clip(m.get("alt"), 200)}
    return out


def load_bilder_meta() -> dict:
    d = read_json(bilder_file(), {})
    if not isinstance(d, dict):
        d = {}
    d.setdefault("bereiche", [])
    d.setdefault("bilder", {})
    d["nur_bereiche"] = d.get("nur_bereiche") is True
    return d


def save_bilder_meta(d: dict):
    write_private_json(bilder_file(), d)


def collect_images():
    """(Dateien, Ordner) nur aus dem Kunden-Verzeichnis – die Vorlagen-Bilder
    des Images (Platzhalter, Logo) erscheinen nicht im Admin."""
    base = custom_public_dir()
    img = base / "img"
    files, folders = [], {""}
    if img.is_dir():
        for f in sorted(img.rglob("*")):
            rel = f.relative_to(base).as_posix()
            if f.is_symlink():
                continue
            if f.is_dir():
                sub = rel[4:]
                if folder_ok_loose(sub):
                    folders.add(sub)
            elif f.is_file() and f.suffix.lower() in ALLOWED_IMAGE_EXTS:
                files.append(rel)
    return files, folders


REF_RE = re.compile(
    r"""\bsrcset\s*=\s*["']([^"']+)["']"""
    r"""|\b(?:src|href|poster|data-src|content)\s*=\s*["']([^"']+)["']"""
    r"""|url\(\s*["']?([^"')]+?)["']?\s*\)""", re.I)


def extract_image_refs(html: str) -> list:
    out = []
    for m in REF_RE.finditer(html or ""):
        if m.group(1):
            cands = [c.strip().split()[0] for c in m.group(1).split(",") if c.strip()]
        else:
            cands = [m.group(2) or m.group(3)]
        for c in cands:
            c = c.strip()
            if "${" in c or c.startswith("data:"):
                continue
            if Path(c.split("?")[0].split("#")[0]).suffix.lower() in ALLOWED_IMAGE_EXTS and c not in out:
                out.append(c)
    return out


def classify_ref(ref: str):
    """('lokal', 'img/x.png') | ('extern', url) | None"""
    if re.match(r"^[a-z][a-z0-9+.-]*:", ref, re.I) or ref.startswith("//"):
        return ("extern", ref) if re.match(r"^(https?:)?//", ref, re.I) else None
    p = unquote(ref.split("?")[0].split("#")[0]).replace("\\", "/")
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return ("lokal", "/".join(parts))


def page_sources():
    """[(Adresse, Titel, HTML)] für Startseite und Unterseiten."""
    out = []
    idx = custom_public_dir() / "index.html"
    if idx.is_file():
        out.append(("/", "Startseite", idx.read_text(encoding="utf-8", errors="replace")))
    for pg in list_pages():
        out.append(("/" + pg["slug"], "/" + pg["slug"], page_file(pg["slug"]).read_text(encoding="utf-8", errors="replace")))
    return out


def page_images():
    """Welche Bilder werden auf welcher Seite verwendet (inkl. fehlender Dateien)."""
    c_pub = custom_public_dir()
    seiten, nutzung = [], {}
    for addr, title, html in page_sources():
        items = []
        for ref in extract_image_refs(html):
            kind = classify_ref(ref)
            if not kind:
                continue
            if kind[0] == "extern":
                items.append({"ref": ref, "status": "extern"})
                continue
            rel = kind[1]
            cand = (c_pub / rel).resolve()
            if cand.is_relative_to(c_pub) and cand.is_file():
                items.append({"ref": ref, "path": rel, "status": "ok"})
                nutzung.setdefault(rel, [])
                if addr not in nutzung[rel]:
                    nutzung[rel].append(addr)
            elif (PUBLIC_DIR / rel).resolve().is_file():
                continue  # Vorlagen-Bild des Images (Platzhalter) – nicht anzeigen
            else:
                items.append({"ref": ref, "path": rel, "status": "fehlt"})
        if items:
            seiten.append({"seite": addr, "titel": title, "bilder": items})
    return seiten, nutzung


def build_bilder_state(with_usage=True) -> dict:
    meta = load_bilder_meta()
    files, folders = collect_images()
    c_pub = custom_public_dir()
    seiten, nutzung = page_images() if with_usage else ([], {})
    by_folder = {}
    for rel in files:
        by_folder.setdefault(folder_of(rel), []).append(rel)
    sections, seen = [], set()
    defs = [dict(b, manifest=True) for b in meta["bereiche"]]
    extra = sorted((folders | set(by_folder)) - {b["ordner"] for b in defs}, key=lambda f: (f != "", f))
    for f in extra:
        if f == "" and not by_folder.get(""):
            continue
        defs.append({"ordner": f, "titel": folder_title(f), "beschreibung": "", "max": None,
                     "format": "", "beschriftung": True, "manifest": False})
    for d in defs:
        if d["ordner"] in seen:
            continue
        seen.add(d["ordner"])
        imgs = []
        for rel in by_folder.get(d["ordner"], []):
            m = meta["bilder"].get(rel, {})
            f = c_pub / rel
            size = cached_image_size(f)
            item = {"path": rel, "text": m.get("text", ""), "alt": m.get("alt", ""),
                    "pos": m.get("pos"), "bytes": f.stat().st_size,
                    "w": size[0] if size else None, "h": size[1] if size else None}
            if with_usage:
                item["verwendet"] = nutzung.get(rel, [])
            imgs.append(item)
        imgs.sort(key=lambda i: (i["pos"] if isinstance(i["pos"], int) else 10 ** 6, i["path"]))
        for i in imgs:
            i.pop("pos")
        sections.append(dict(d, bilder=imgs))
    return {"bereiche": sections, "nur_bereiche": meta["nur_bereiche"], "seiten": seiten}


def public_bilder() -> dict:
    st = build_bilder_state(with_usage=False)
    return {"bereiche": [{
        "ordner": b["ordner"], "titel": b["titel"], "beschreibung": b["beschreibung"],
        "bilder": [{"src": "/" + i["path"], "text": i["text"], "alt": i["alt"], "breite": i["w"], "hoehe": i["h"]}
                   for i in b["bilder"]],
    } for b in st["bereiche"]]}


def section_def(folder: str):
    for b in load_bilder_meta()["bereiche"]:
        if b["ordner"] == folder:
            return b
    return None


def save_uploaded_image(folder_raw, name_raw, data: bytes) -> str:
    """Muss unter STORE_LOCK aufgerufen werden."""
    meta = load_bilder_meta()
    folder = norm_folder(folder_raw)
    known = {b["ordner"] for b in meta["bereiche"]}
    _, existing_folders = collect_images()
    if folder not in known and folder not in existing_folders:
        if meta["nur_bereiche"]:
            raise Fehler("Dieser Bereich ist für diese Webseite nicht vorgesehen.")
        folder = norm_folder(folder, strict=True)
    name = safe_image_name(name_raw)
    if not data or not sniff_image(data, Path(name).suffix):
        raise Fehler("Die Datei ist kein gültiges Bild.")
    rel = "/".join(x for x in ("img", folder, name) if x)
    c_pub = ensure_custom_public()
    dest = (c_pub / rel).resolve()
    if not dest.is_relative_to(c_pub / "img"):
        raise Fehler("Ungültiger Zielpfad.")
    d = section_def(folder)
    if d and d.get("max") and not dest.exists():
        count = sum(1 for f in (dest.parent.iterdir() if dest.parent.is_dir() else [])
                    if f.is_file() and f.suffix.lower() in ALLOWED_IMAGE_EXTS)
        if count >= d["max"]:
            raise Fehler(f"Im Bereich «{d['titel']}» sind maximal {d['max']} Bilder erlaubt.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name("." + dest.name + ".upload")
    tmp.write_bytes(data)
    os.replace(tmp, dest)
    return rel


# --------------------------------------------------------- Admin-Hilfsfunktionen
def ensure_custom_public():
    """Stellt sicher, dass /data/site/public existiert und eine index.html besitzt."""
    c_pub = custom_public_dir()
    c_pub.mkdir(parents=True, exist_ok=True)
    c_idx = c_pub / "index.html"
    if not c_idx.exists() and (PUBLIC_DIR / "index.html").exists():
        c_idx.write_text((PUBLIC_DIR / "index.html").read_text(encoding="utf-8"), encoding="utf-8")
    return c_pub


def import_zip_bytes(raw_bytes: bytes) -> int:
    """Entpackt Web-Assets (index.html, img/...) aus einem hochgeladenen ZIP nach /data/site/public.
    Eine bilder.json (im ZIP-Wurzelverzeichnis, public/ oder config/) steuert die Bild-Bereiche."""
    c_pub = ensure_custom_public()
    c_cfg = custom_config_file()
    c_cfg.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise Fehler(f"ZIP enthält zu viele Dateien (max. {MAX_ZIP_ENTRIES}).")
        if sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
            raise Fehler("ZIP ist entpackt zu gross (max. 300 MB).")
        for info in infos:
            if info.is_dir() or info.file_size > 20 * 1024 * 1024:
                continue
            norm = info.filename.replace("\\", "/").lstrip("/")
            if ".." in norm.split("/"):
                continue
            if norm.split("/")[-1] == "bilder.json":
                try:
                    man = parse_manifest(json.loads(zf.read(info).decode("utf-8")))
                except (ValueError, Fehler) as e:
                    raise Fehler(f"bilder.json ist ungültig: {e}")
                meta = load_bilder_meta()
                meta["bereiche"] = man["bereiche"]
                meta["nur_bereiche"] = man["nur_bereiche"]
                for p, m in man["bilder"].items():
                    meta["bilder"][p] = dict(meta["bilder"].get(p, {}), **m)
                save_bilder_meta(meta)
                count += 1
                continue
            # Erkenne public/-Unterpfad im ZIP (z. B. template/app/public/...)
            rel_pub = None
            if "/app/public/" in norm:
                rel_pub = norm.split("/app/public/", 1)[1]
            elif norm.startswith("app/public/"):
                rel_pub = norm[len("app/public/"):]
            elif "/public/" in norm:
                rel_pub = norm.split("/public/", 1)[1]
            elif norm.startswith("public/"):
                rel_pub = norm[len("public/"):]
            elif norm == "index.html" or norm.startswith("img/"):
                rel_pub = norm

            if rel_pub:
                ext = Path(rel_pub).suffix.lower()
                if ext not in ALLOWED_ASSET_EXTS:
                    continue
                dest = (c_pub / rel_pub).resolve()
                if not dest.is_relative_to(c_pub):
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))
                count += 1
            elif norm.endswith("site.json") and "example" not in norm:
                c_cfg.write_bytes(zf.read(info))
                count += 1
    reload_catalog()
    return count


def build_backup_zip() -> bytes:
    """Sicherung ohne Geheimnisse (kein Passwort-Hash, kein SMTP-Passwort)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        c_pub = custom_public_dir()
        src_pub = c_pub if (c_pub / "index.html").exists() else PUBLIC_DIR
        if src_pub.is_dir():
            for f in src_pub.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    zf.write(f, f"public/{f.relative_to(src_pub)}")
        for pg in list_pages():
            zf.write(page_file(pg["slug"]), f"pages/{pg['slug']}.html")
        if bilder_file().is_file():
            zf.write(bilder_file(), "bilder.json")
        for fname in ("bestellungen.csv", "bestellungen.jsonl", "nachrichten.jsonl"):
            fpath = DATA_DIR / fname
            if fpath.is_file():
                zf.write(fpath, f"daten/{fname}")
    return buf.getvalue()


# ------------------------------------------------------------- SEO & Wartung
def esc(v) -> str:
    return htmllib.escape(str(v or ""), quote=True)


def inject_seo(html: str, path: str) -> str:
    """Ergänzt fehlende Meta-Tags im <head>; vorhandene Tags der Seite haben Vorrang."""
    s = get_effective_settings()
    base = site_base_url()
    title, desc, bild = s["seo_titel"], s["seo_beschreibung"], s["seo_bild"]

    def has(rx):
        return re.search(rx, html, re.I) is not None

    tags = []
    if title and not has(r"<title[\s>]"):
        tags.append(f"<title>{esc(title)}</title>")
    if desc and not has(r"""<meta[^>]+name=["']description["']"""):
        tags.append(f'<meta name="description" content="{esc(desc)}">')
    if title and not has(r"""property=["']og:title["']"""):
        tags.append(f'<meta property="og:title" content="{esc(title)}">')
    if desc and not has(r"""property=["']og:description["']"""):
        tags.append(f'<meta property="og:description" content="{esc(desc)}">')
    if base and bild and norm_img_path(bild) and not has(r"""property=["']og:image["']"""):
        tags.append(f'<meta property="og:image" content="{esc(base + "/" + norm_img_path(bild))}">')
    if base and not has(r"""rel=["']canonical["']"""):
        tags.append(f'<link rel="canonical" href="{esc(base + path)}">')
    if base and not has(r"""property=["']og:url["']"""):
        tags.append(f'<meta property="og:url" content="{esc(base + path)}">')
    if tags and not has(r"""property=["']og:type["']"""):
        tags.append('<meta property="og:type" content="website">')
    m = re.search(r"</head\s*>", html, re.I)
    if not tags or not m:
        return html
    return html[:m.start()] + "  " + "\n  ".join(tags) + "\n" + html[m.start():]


def robots_txt() -> bytes:
    base = site_base_url()
    out = "User-agent: *\nDisallow: /admin\nDisallow: /api/\n"
    if base:
        out += f"Sitemap: {base}/sitemap.xml\n"
    return out.encode()


def sitemap_xml() -> bytes:
    base = site_base_url()
    entries = []
    idx = active_index_file()
    if idx.is_file():
        entries.append(("/", idx.stat().st_mtime))
    for pg in list_pages():
        entries.append(("/" + pg["slug"], page_file(pg["slug"]).stat().st_mtime))
    rows = "".join(
        f"  <url><loc>{esc(base + loc)}</loc><lastmod>{dt.datetime.fromtimestamp(mt, dt.timezone.utc).strftime('%Y-%m-%d')}</lastmod></url>\n"
        for loc, mt in entries)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + rows + "</urlset>\n").encode()


def maintenance_page() -> bytes:
    s = get_effective_settings()
    text = "".join(f"<p>{esc(p)}</p>" for p in s["wartung_text"].split("\n") if p.strip())
    return f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>{esc(s['wartung_titel'])}</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.6 system-ui,sans-serif;background:#f4f7f8;color:#1d2426}}
main{{max-width:520px;padding:32px;text-align:center}}h1{{font-size:1.6rem;margin:0 0 12px}}
@media (prefers-color-scheme:dark){{body{{background:#12181a;color:#e6eef0}}}}</style></head>
<body><main><h1>{esc(s['wartung_titel'])}</h1>{text}<p><small>{esc(s['shop_name'])}</small></p></main></body></html>""".encode()


# ------------------------------------------------------------------- Server
SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}
SITE_CSP = (
    "default-src 'self'; img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "script-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
)
# Admin: kein Inline-JavaScript erlaubt -> eingeschleuste Skripte (XSS) laufen nicht.
ADMIN_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
# Login-Seite: zusätzlich nur das offizielle Google-Skript für «Sign in with Google».
LOGIN_CSP = (
    "default-src 'self'; script-src 'self' https://accounts.google.com/gsi/client; "
    "style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style; "
    "frame-src https://accounts.google.com/gsi/; connect-src 'self' https://accounts.google.com/gsi/; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
# SVGs werden ohne Skriptausführung ausgeliefert (auch beim direkten Öffnen).
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"

ADMIN_PUBLIC_FILES = {
    "/admin/login": ("login.html", "text/html; charset=utf-8"),
    "/admin/setup": ("setup.html", "text/html; charset=utf-8"),
    "/admin/auth.js": ("auth.js", "text/javascript; charset=utf-8"),
    "/admin/theme.js": ("theme.js", "text/javascript; charset=utf-8"),
    "/admin/admin.css": ("admin.css", "text/css; charset=utf-8"),
}
ADMIN_PRIVATE_FILES = {
    "/admin": ("index.html", "text/html; charset=utf-8"),
    "/admin/": ("index.html", "text/html; charset=utf-8"),
    "/admin/admin.js": ("admin.js", "text/javascript; charset=utf-8"),
}
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("text/javascript", ".js")


class Handler(BaseHTTPRequestHandler):
    server_version = "SiteEngine/2.0"
    sys_version = ""
    timeout = 30  # Schutz gegen langsame/hängende Verbindungen (Slowloris)

    def log_message(self, fmt, *args):
        log.info("%s %s", self.client_ip(), fmt % args)

    def client_ip(self):
        if TRUST_PROXY:
            for h in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
                v = self.headers.get(h)
                if v:
                    return v.split(",")[0].strip()[:64]
        return self.client_address[0]

    def send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None, head=False, csp=SITE_CSP):
        self.send_response(code)
        extra = extra or {}
        for k, v in SEC_HEADERS.items():
            if k not in extra:
                self.send_header(k, v)
        self.send_header("Content-Security-Policy", csp)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra.items():
            for item in (v if isinstance(v, list) else [v]):
                self.send_header(k, item)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def json(self, code, obj, extra=None):
        self.send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8",
                  dict({"Cache-Control": "no-store"}, **(extra or {})))

    def redirect(self, location, code=303, extra=None):
        self.send(code, b"", extra=dict({"Location": location, "Cache-Control": "no-store"}, **(extra or {})))

    def read_body(self, limit):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.json(400, {"ok": False, "error": "Ungültige Inhaltslänge", "fehler": "Ungültige Inhaltslänge"})
            return None
        if length <= 0 or length > limit:
            msg = "Anfrage zu gross" if length > 0 else "Leere Anfrage"
            self.json(413 if length > 0 else 400, {"ok": False, "error": msg, "fehler": msg})
            return None
        return self.rfile.read(length)

    # --- Sitzung & CSRF
    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def session(self):
        return get_session(self.cookie(SESSION_COOKIE))

    def session_cookie(self, tok, clear=False):
        attrs = "Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if COOKIE_SECURE else "")
        if clear:
            return f"{SESSION_COOKIE}=; Max-Age=0; {attrs}"
        return f"{SESSION_COOKIE}={tok}; {attrs}"

    def origin_ok(self) -> bool:
        """Lehnt Anfragen ab, die von fremden Webseiten ausgelöst wurden."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        hosts = {self.headers.get("Host", "").lower()}
        if TRUST_PROXY and self.headers.get("X-Forwarded-Host"):
            hosts.add(self.headers.get("X-Forwarded-Host").split(",")[0].strip().lower())
        return urlsplit(origin).netloc.lower() in hosts - {""}

    def csrf_ok(self, sess) -> bool:
        sent = self.headers.get("X-CSRF-Token", "")
        return self.origin_ok() and hmac.compare_digest(sent.encode("utf-8", "replace"), sess["csrf"].encode())

    def maintenance_active(self) -> bool:
        return feature_enabled("wartung") and not self.session()

    # --- GET
    def do_GET(self, head=False):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        if path in ("/healthz", "/readyz"):
            return self.send(200, b"ok", head=head, extra={"Cache-Control": "no-store"})
        if path == "/admin" or path.startswith("/admin/"):
            return self.serve_admin(path, head)
        if path.startswith("/api/admin/"):
            sess = self.session()
            if not sess:
                return self.json(401, {"ok": False, "error": "Nicht angemeldet", "login": True})
            return self.admin_get(path, parsed.query, head, sess)
        if self.maintenance_active():
            return self.send(503, maintenance_page(), "text/html; charset=utf-8", head=head,
                             extra={"Retry-After": "3600", "Cache-Control": "no-store"})
        if path == "/api/config":
            if not feature_enabled("shop"):
                return self.json(404, {"error": "Nicht gefunden"})
            return self.json(200, CAT)
        if path == "/api/bilder":
            return self.json(200, public_bilder())

        page_slug = path.strip("/")
        if path.endswith("/"):
            path += "index.html"
        rel = path.lstrip("/")

        # Zuerst im persistenten Kunden-Verzeichnis (/data/site/public) suchen, sonst Fallback auf PUBLIC_DIR
        target = None
        for base in (custom_public_dir(), PUBLIC_DIR):
            cand = (base / rel).resolve()
            try:
                if cand.is_relative_to(base) and cand.is_file():
                    target = cand
                    break
            except (ValueError, RuntimeError, OSError):
                continue

        if target is None and valid_slug(page_slug):
            pf = page_file(page_slug)
            if pf.is_file():
                target = pf

        if target is None and feature_enabled("seo"):
            if rel == "robots.txt":
                return self.send(200, robots_txt(), head=head, extra={"Cache-Control": "no-cache"})
            if rel == "sitemap.xml":
                return self.send(200, sitemap_xml(), "application/xml; charset=utf-8", head=head,
                                 extra={"Cache-Control": "no-cache"})

        if target is None:
            return self.send(404, b"Nicht gefunden", head=head)

        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("+xml"):
            ctype += "; charset=utf-8"
        stt = target.stat()
        # Inode ändert sich bei jedem Upload (os.replace) – auch bei gleicher Grösse und Zeit
        etag = f'"{stt.st_ino:x}-{stt.st_mtime_ns:x}-{len(data):x}"'
        if target.suffix.lower() == ".html" and feature_enabled("seo"):
            data = inject_seo(data.decode("utf-8", errors="replace"), "/" if page_slug in ("", "index.html") else "/" + page_slug).encode("utf-8")
            # Inhalt hängt auch von den SEO-Einstellungen ab -> Hash über das Ergebnis
            etag = '"' + hashlib.sha256(data).hexdigest()[:20] + '"'
        csp = SVG_CSP if target.suffix.lower() == ".svg" else SITE_CSP
        if self.headers.get("If-None-Match") == etag:
            return self.send(304, head=True, extra={"ETag": etag})
        self.send(200, data, ctype=ctype, extra={"Cache-Control": "no-cache", "ETag": etag}, head=head, csp=csp)

    def do_HEAD(self):
        self.do_GET(head=True)

    def serve_admin(self, path, head):
        admin_headers = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}
        if path in ADMIN_PUBLIC_FILES:
            fname, ctype = ADMIN_PUBLIC_FILES[path]
            if path == "/admin/login":
                # Google-Popup braucht COOP same-origin-allow-popups
                return self.send(200, (ADMIN_DIR / fname).read_bytes(), ctype, head=head, csp=LOGIN_CSP,
                                 extra=dict(admin_headers, **{"Cross-Origin-Opener-Policy": "same-origin-allow-popups"}))
            return self.send(200, (ADMIN_DIR / fname).read_bytes(), ctype, extra=admin_headers,
                             head=head, csp=ADMIN_CSP)
        if path == "/admin/login-info":
            a = load_auth()
            nonce = secrets.token_urlsafe(24)
            cookie = (f"{NONCE_COOKIE}={nonce}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict"
                      + ("; Secure" if COOKIE_SECURE else ""))
            return self.json(200, {"client_id": google_client_id(a), "erlaubt": bool(admin_emails(a)),
                                   "notfall": bool(a.get("notfall_codes")), "nonce": nonce},
                             extra={"Set-Cookie": cookie})
        if path in ADMIN_PRIVATE_FILES:
            sess = self.session()
            if not sess:
                if path.endswith(".js"):
                    return self.send(401, b"", extra=admin_headers, head=head)
                return self.redirect("/admin/login")
            fname, ctype = ADMIN_PRIVATE_FILES[path]
            body = (ADMIN_DIR / fname).read_bytes()
            if fname == "index.html":
                body = body.replace(b"__CSRF_TOKEN__", sess["csrf"].encode())
            return self.send(200, body, ctype, extra=admin_headers, head=head, csp=ADMIN_CSP)
        return self.send(404, b"Nicht gefunden", head=head, extra=admin_headers)

    def admin_get(self, path, query, head, sess):
        if path == "/api/admin/state":
            idx = active_index_file()
            html = idx.read_text(encoding="utf-8") if idx.exists() else ""
            cfg = get_effective_settings()
            shop_on = feature_enabled("shop")
            a = load_auth()
            return self.json(200, {
                "features": {name: feature_enabled(name) for name in FEATURES},
                "pages": list_pages(),
                "catalog": {
                    "versand": CAT.get("versand", {"preis": 9, "gratis_ab_betrag": 60}),
                    "motive": CAT.get("motive", []),
                    "produkte": CAT.get("produkte", []),
                },
                "settings": {
                    "shop_name": cfg["shop_name"],
                    "shop_url": cfg["shop_url"],
                    "shop_address": cfg["shop_address"],
                    "order_prefix": cfg["order_prefix"],
                    "mail_to": cfg["mail_to"],
                    "smtp_host": cfg["smtp_host"],
                    "smtp_port": cfg["smtp_port"],
                    "smtp_user": cfg["smtp_user"],
                    "smtp_pass_set": bool(cfg["smtp_pass"]),
                    "testmodus": cfg["testmodus"],
                    "seo_titel": cfg["seo_titel"],
                    "seo_beschreibung": cfg["seo_beschreibung"],
                    "seo_bild": cfg["seo_bild"],
                    "wartung_titel": cfg["wartung_titel"],
                    "wartung_text": cfg["wartung_text"],
                },
                "auth": {
                    "client_id": google_client_id(a),
                    "client_id_env": bool(ENV("GOOGLE_CLIENT_ID", "").strip()),
                    "emails": sorted({norm_email(e) for e in a.get("emails") or []}),
                    "emails_env": env_admin_emails(),
                    "ich": sess.get("email", ""),
                    "notfall_codes": len(a.get("notfall_codes") or []),
                },
                "bilder": build_bilder_state(),
                "html": html,
                "orders": read_orders()[:200] if shop_on else [],
                "nachrichten": read_jsonl(messages_file())[:500] if feature_enabled("kontakt") else [],
            })
        if path == "/api/admin/page":
            slug = (parse_qs(query).get("slug") or [""])[0]
            if not valid_slug(slug):
                return self.json(400, {"error": "Ungültiger Seitenname"})
            f = page_file(slug)
            if not f.is_file():
                return self.json(404, {"error": "Seite nicht gefunden"})
            return self.json(200, {"slug": slug, "html": f.read_text(encoding="utf-8")})
        if path == "/api/admin/orders.csv":
            if not feature_enabled("shop"):
                return self.json(404, {"error": "Feature deaktiviert"})
            csv_path = DATA_DIR / "bestellungen.csv"
            data = csv_path.read_bytes() if csv_path.is_file() else b"Noch keine Bestellungen\n"
            return self.send(200, data, "text/csv; charset=utf-8", extra={
                "Content-Disposition": 'attachment; filename="bestellungen.csv"',
                "Cache-Control": "no-store",
            }, head=head)
        if path == "/api/admin/backup.zip":
            zbytes = build_backup_zip()
            return self.send(200, zbytes, "application/zip", extra={
                "Content-Disposition": 'attachment; filename="site-backup.zip"',
                "Cache-Control": "no-store",
            }, head=head)
        return self.json(404, {"error": "Unbekannter Admin-Endpunkt"})

    # --- POST
    def do_POST(self):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)

        if path in ("/admin/google", "/admin/notfall", "/admin/setup", "/admin/logout"):
            return self.handle_auth_post(path)

        if path.startswith("/api/admin/"):
            sess = self.session()
            if not sess:
                return self.json(401, {"ok": False, "error": "Nicht angemeldet", "login": True})
            if not self.csrf_ok(sess):
                return self.json(403, {"ok": False, "error": "Ungültiges Sicherheits-Token. Bitte Seite neu laden."})
            body = self.read_body(MAX_ADMIN_BODY)
            if body is None:
                return
            try:
                return self.handle_admin_post(path, parsed.query, body, sess)
            except Fehler as e:
                return self.json(400, {"ok": False, "error": str(e)})

        if self.maintenance_active():
            return self.json(503, {"ok": False, "error": "Wartungsarbeiten", "fehler": "Wartungsarbeiten"},
                             extra={"Retry-After": "3600"})

        if path == "/api/bestellung" and feature_enabled("shop"):
            return self.handle_order()
        if path == "/api/kontakt" and feature_enabled("kontakt"):
            return self.handle_contact()
        return self.json(404, {"ok": False, "error": "Unbekannter Endpunkt", "fehler": "Unbekannter Endpunkt"})

    def handle_order(self):
        ip = self.client_ip()
        if not check_rate(ip):
            msg = "Zu viele Anfragen. Bitte warte einige Minuten."
            return self.json(429, {"ok": False, "error": msg, "fehler": msg})
        body = self.read_body(MAX_BODY)
        if body is None:
            return
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return self.json(400, {"ok": False, "error": "Ungültiges JSON", "fehler": "Ungültiges JSON"})

        try:
            order = validate(data)
        except Fehler as e:
            return self.json(400, {"ok": False, "error": str(e), "fehler": str(e)})

        try:
            nr = save_order(order)
        except Exception as e:
            log.exception("Fehler beim Speichern der Bestellung: %s", e)
            msg = "Konnte die Bestellung nicht speichern."
            return self.json(500, {"ok": False, "error": msg, "fehler": msg})

        mail_ok = notify(order)
        log.info("Bestellung %s gespeichert, %s %s (Mail: %s)", nr, CURRENCY, fmt_money(order["total"]), "ok" if mail_ok else "fehler")
        return self.json(200, {
            "ok": True,
            "bestellnummer": nr,
            "nr": nr,
            "total": order["total"],
            "currency": CURRENCY,
            "mail_gesendet": mail_ok or get_effective_settings()["testmodus"],
        })

    def handle_contact(self):
        """JSON (fetch) oder klassisches HTML-Formular (application/x-www-form-urlencoded)."""
        is_form = self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded")
        body = self.read_body(MAX_BODY)
        if body is None:
            return
        if is_form:
            fields = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
            weiter = fields.get("weiter", "/")
            if not re.fullmatch(r"/[A-Za-z0-9/_-]{0,80}", weiter):
                weiter = "/"
        else:
            try:
                fields = json.loads(body.decode("utf-8"))
            except Exception:
                return self.json(400, {"ok": False, "error": "Ungültiges JSON"})

        def done(ok, msg, code):
            if is_form:
                return self.redirect(f"{weiter}?kontakt={'ok' if ok else 'fehler'}")
            return self.json(code, {"ok": ok, **({} if ok else {"error": msg, "fehler": msg})})

        if not self.origin_ok():
            return done(False, "Ungültige Anfrage.", 403)
        if not check_rate("kontakt:" + self.client_ip()):
            return done(False, "Zu viele Anfragen. Bitte warte einige Minuten.", 429)
        try:
            msg = validate_contact(fields)
        except Fehler as e:
            return done(False, str(e), 400)
        msg = save_message(msg)
        notify_contact(msg)
        log.info("Kontaktanfrage %s gespeichert", msg["id"])
        return done(True, "", 200)

    def handle_auth_post(self, path):
        body = self.read_body(MAX_AUTH_BODY)
        if body is None:
            return
        if not self.origin_ok():
            return self.json(403, {"ok": False, "error": "Ungültige Herkunft der Anfrage."})
        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except Exception:
            return self.json(400, {"ok": False, "error": "Ungültiges JSON"})
        ip = self.client_ip()

        if path == "/admin/logout":
            sess = self.session()
            if sess and self.csrf_ok(sess):
                with SESS_LOCK:
                    SESSIONS.pop(sess["key"], None)
            return self.json(200, {"ok": True}, extra={"Set-Cookie": self.session_cookie("", clear=True)})

        if login_blocked(ip):
            return self.json(429, {"ok": False, "error": "Zu viele Fehlversuche. Bitte warte 15 Minuten."})

        clear_nonce = (f"{NONCE_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"
                       + ("; Secure" if COOKIE_SECURE else ""))
        if path == "/admin/google":
            a = load_auth()
            try:
                claims = verify_google_token(payload.get("credential"), google_client_id(a), self.cookie(NONCE_COOKIE) or "")
            except AuthFehler as e:
                login_failed(ip)
                log.warning("Google-Anmeldung abgelehnt (%s) von %s", e, ip)
                return self.json(401, {"ok": False, "error": f"Google-Anmeldung fehlgeschlagen: {e}."},
                                 extra={"Set-Cookie": clear_nonce})
            if not nonce_unused(claims["nonce"]):
                login_failed(ip)
                return self.json(401, {"ok": False, "error": "Google-Anmeldung fehlgeschlagen: Token wurde schon benutzt."},
                                 extra={"Set-Cookie": clear_nonce})
            email = claims["email"]
            if email not in admin_emails(a):
                login_failed(ip)
                log.warning("Google-Konto %s ist nicht berechtigt (%s)", email, ip)
                return self.json(403, {"ok": False, "error": f"{email} hat keinen Zugang zu dieser Administration."},
                                 extra={"Set-Cookie": clear_nonce})
            login_succeeded(ip)
            tok, _ = new_session(email)
            log.info("Admin-Anmeldung mit Google: %s (%s)", email, ip)
            return self.json(200, {"ok": True}, extra={"Set-Cookie": [self.session_cookie(tok), clear_nonce]})

        if path == "/admin/notfall":
            with AUTH_LOCK:
                left = use_notfall_code(payload.get("code"))
            if left is None:
                login_failed(ip)
                time.sleep(0.5)
                return self.json(401, {"ok": False, "error": "Der Notfall-Code ist ungültig oder wurde schon benutzt."})
            login_succeeded(ip)
            tok, _ = new_session("notfall-code")
            log.warning("Admin-Anmeldung mit Notfall-Code von %s (%d Codes übrig)", ip, left)
            return self.json(200, {"ok": True, "uebrig": left}, extra={"Set-Cookie": self.session_cookie(tok)})

        # /admin/setup – Notfall-Link aus `server.py notfall-link` bzw. dem Start-Log
        with AUTH_LOCK:
            ok = consume_setup_token(payload.get("token"))
        if not ok:
            login_failed(ip)
            return self.json(403, {"ok": False, "error": "Der Notfall-Link ist ungültig, abgelaufen oder wurde schon benutzt."})
        login_succeeded(ip)
        tok, _ = new_session("notfall-link")
        log.warning("Admin-Anmeldung über Notfall-Link von %s", ip)
        return self.json(200, {"ok": True}, extra={"Set-Cookie": self.session_cookie(tok)})

    def handle_admin_post(self, path: str, query: str, body: bytes, sess: dict):
        with STORE_LOCK:
            if path == "/api/admin/upload-zip":
                try:
                    n = import_zip_bytes(body)
                    return self.json(200, {"ok": True, "files": n})
                except (zipfile.BadZipFile, Fehler, ValueError, OSError) as e:
                    return self.json(400, {"ok": False, "error": f"Ungültiges ZIP-Archiv: {e}"})

            if path == "/api/admin/bilder-upload":
                qs = parse_qs(query)
                rel = save_uploaded_image((qs.get("ordner") or [""])[0], (qs.get("name") or [""])[0], body)
                return self.json(200, {"ok": True, "path": rel})

        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except Exception:
            return self.json(400, {"ok": False, "error": "Ungültiges JSON"})

        if path in ("/api/admin/access", "/api/admin/notfall-codes"):
            return self.handle_account_post(path, payload, sess)

        with STORE_LOCK:
            if path == "/api/admin/bilder-delete":
                rel = norm_img_path(payload.get("path"))
                c_pub = custom_public_dir()
                target = (c_pub / rel).resolve() if rel else None
                if not target or not target.is_relative_to(c_pub / "img") or not target.is_file():
                    return self.json(400, {"ok": False, "error": "Bild nicht gefunden"})
                target.unlink()
                meta = load_bilder_meta()
                if meta["bilder"].pop(rel, None) is not None:
                    save_bilder_meta(meta)
                return self.json(200, {"ok": True})

            if path == "/api/admin/bilder-save":
                folder = norm_folder(payload.get("ordner"))
                items = payload.get("bilder")
                if not isinstance(items, list) or len(items) > 2000:
                    return self.json(400, {"ok": False, "error": "Ungültige Bildliste"})
                meta = load_bilder_meta()
                for pos, it in enumerate(items):
                    rel = norm_img_path((it or {}).get("path")) if isinstance(it, dict) else None
                    if not rel or folder_of(rel) != folder:
                        continue
                    meta["bilder"][rel] = {"text": clip(it.get("text"), 300), "alt": clip(it.get("alt"), 200), "pos": pos}
                save_bilder_meta(meta)
                return self.json(200, {"ok": True})

            if path == "/api/admin/bilder-ordner":
                meta = load_bilder_meta()
                if meta["nur_bereiche"]:
                    return self.json(400, {"ok": False, "error": "Für diese Webseite sind die Bereiche fest vorgegeben."})
                folder = norm_folder(payload.get("ordner"), strict=True)
                if not folder:
                    return self.json(400, {"ok": False, "error": "Bitte einen Ordnernamen angeben."})
                c_pub = ensure_custom_public()
                d = (c_pub / "img" / folder).resolve()
                if not d.is_relative_to(c_pub / "img"):
                    return self.json(400, {"ok": False, "error": "Ungültiger Ordner"})
                d.mkdir(parents=True, exist_ok=True)
                return self.json(200, {"ok": True, "ordner": folder})

            if path == "/api/admin/bilder-ordner-delete":
                folder = norm_folder(payload.get("ordner"))
                c_pub = custom_public_dir()
                d = (c_pub / "img" / folder).resolve()
                if not folder or not d.is_relative_to(c_pub / "img") or not d.is_dir():
                    return self.json(400, {"ok": False, "error": "Ordner nicht gefunden"})
                if any(d.iterdir()):
                    return self.json(400, {"ok": False, "error": "Der Ordner ist nicht leer."})
                d.rmdir()
                return self.json(200, {"ok": True})

            if path == "/api/admin/nachricht-delete":
                if not feature_enabled("kontakt"):
                    return self.json(404, {"ok": False, "error": "Feature „Kontakt“ ist deaktiviert."})
                delete_message(str(payload.get("id") or ""))
                return self.json(200, {"ok": True})

            if path in SHOP_ADMIN_PATHS and not feature_enabled("shop"):
                return self.json(404, {"ok": False, "error": "Feature „Shop“ ist deaktiviert."})

            if path == "/api/admin/page":
                slug = str(payload.get("slug") or "").strip().lower()
                html = str(payload.get("html") or "")
                if not valid_slug(slug):
                    return self.json(400, {"ok": False, "error": "Ungültiger Seitenname (erlaubt: a-z, 0-9, Bindestrich; max. 40 Zeichen)."})
                if not html.strip():
                    return self.json(400, {"ok": False, "error": "HTML-Inhalt ist leer."})
                if len(html.encode("utf-8")) > MAX_PAGE_BYTES:
                    return self.json(400, {"ok": False, "error": "Seite ist zu gross (max. 1 MB)."})
                f = page_file(slug)
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(html, encoding="utf-8")
                return self.json(200, {"ok": True, "slug": slug, "pages": list_pages()})

            if path == "/api/admin/page-delete":
                slug = str(payload.get("slug") or "")
                if not valid_slug(slug):
                    return self.json(400, {"ok": False, "error": "Ungültiger Seitenname"})
                f = page_file(slug)
                if f.is_file():
                    f.unlink()
                return self.json(200, {"ok": True, "pages": list_pages()})

            if path == "/api/admin/catalog":
                if not isinstance(payload.get("produkte"), list) or not payload["produkte"]:
                    return self.json(400, {"ok": False, "error": "Mindestens ein Produkt erforderlich."})
                c_pub = ensure_custom_public()
                c_idx = c_pub / "index.html"
                new_cat_json = json.dumps({
                    "versand": payload.get("versand", {"preis": 9, "gratis_ab_betrag": 60}),
                    "motive": payload.get("motive", []),
                    "produkte": payload["produkte"],
                }, ensure_ascii=False, indent=2).replace("</", "<\\/")
                if c_idx.is_file():
                    html = c_idx.read_text(encoding="utf-8")
                    if re.search(r'<script id="produkte" type="application/json">.*?</script>', html, re.S):
                        html = re.sub(
                            r'(<script id="produkte" type="application/json">).*?(</script>)',
                            lambda m: f"{m.group(1)}\n{new_cat_json}\n{m.group(2)}",
                            html,
                            count=1,
                            flags=re.S,
                        )
                        c_idx.write_text(html, encoding="utf-8")
                c_cfg = custom_config_file()
                c_cfg.parent.mkdir(parents=True, exist_ok=True)
                c_cfg.write_text(new_cat_json, encoding="utf-8")
                reload_catalog()
                return self.json(200, {"ok": True})

            if path == "/api/admin/settings":
                cur = load_runtime_settings()
                for k, n in (("shop_name", 120), ("shop_url", 200), ("shop_address", 200), ("order_prefix", 20),
                             ("mail_to", 120), ("smtp_host", 120), ("smtp_user", 120), ("seo_titel", 120),
                             ("seo_beschreibung", 300), ("seo_bild", 200), ("wartung_titel", 120)):
                    if k in payload:
                        cur[k] = one_line(payload.get(k), n)
                if "wartung_text" in payload:
                    cur["wartung_text"] = clean(payload.get("wartung_text"), 2000)
                if cur.get("mail_to") and not EMAIL_RE.match(cur["mail_to"]):
                    return self.json(400, {"ok": False, "error": "Die Empfänger-E-Mail ist ungültig."})
                if cur.get("smtp_host") and not HOST_RE.match(cur["smtp_host"]):
                    return self.json(400, {"ok": False, "error": "Der SMTP-Server ist ungültig."})
                if cur.get("shop_url") and not re.match(r"^https?://[^\s/]+", cur["shop_url"]):
                    return self.json(400, {"ok": False, "error": "Die Webseiten-URL muss mit https:// beginnen."})
                if cur.get("seo_bild") and not norm_img_path(cur["seo_bild"]):
                    return self.json(400, {"ok": False, "error": "Das Vorschaubild muss ein Bild unter img/ sein."})
                if "smtp_port" in payload:
                    try:
                        port = int(payload["smtp_port"])
                        cur["smtp_port"] = port if 0 < port < 65536 else 465
                    except (ValueError, TypeError):
                        cur["smtp_port"] = 465
                if "testmodus" in payload:
                    cur["testmodus"] = bool(payload["testmodus"])
                if isinstance(payload.get("features"), dict):
                    feats = cur.get("features") if isinstance(cur.get("features"), dict) else {}
                    for name in FEATURES:
                        if name in payload["features"]:
                            feats[name] = bool(payload["features"][name])
                    cur["features"] = feats
                raw_smtp_pass = str(payload.get("smtp_pass") or "").strip()
                if raw_smtp_pass:
                    if "gmail" in str(cur.get("smtp_host", SMTP_HOST)).lower():
                        raw_smtp_pass = raw_smtp_pass.replace(" ", "")
                    cur["smtp_pass"] = raw_smtp_pass[:200]
                save_runtime_settings(cur)
                reload_catalog()
                return self.json(200, {"ok": True})

            if path == "/api/admin/test-email":
                cfg = get_effective_settings()
                try:
                    send_mail(
                        cfg["mail_to"],
                        f"Test-E-Mail von {cfg['shop_name']}",
                        f"Der E-Mail-Versand für {cfg['shop_name']} ({cfg['shop_url']}) ist erfolgreich eingerichtet!",
                        force_live=True,
                    )
                    return self.json(200, {"ok": True})
                except Exception as e:
                    return self.json(400, {"ok": False, "error": f"E-Mail-Versand fehlgeschlagen: {e}"})

            if path == "/api/admin/html":
                html = str(payload.get("html") or "")
                if len(html) < 50:
                    return self.json(400, {"ok": False, "error": "HTML-Inhalt ist leer oder zu kurz."})
                c_pub = ensure_custom_public()
                (c_pub / "index.html").write_text(html, encoding="utf-8")
                reload_catalog()
                return self.json(200, {"ok": True})

        return self.json(404, {"ok": False, "error": "Unbekannter Admin-Endpunkt"})

    def handle_account_post(self, path, payload, sess):
        """Zugang verwalten: erlaubte Google-Konten, Client ID, Notfall-Codes."""
        with AUTH_LOCK:
            a = load_auth()
            if path == "/api/admin/notfall-codes":
                codes = new_notfall_codes()
                a["notfall_codes"] = [sha256_hex(norm_notfall_code(c)) for c in codes]
                save_auth(a)
                log.info("Neue Notfall-Codes erzeugt von %s", sess.get("email") or "?")
                return self.json(200, {"ok": True, "codes": codes})
            # /api/admin/access
            emails = payload.get("emails")
            if not isinstance(emails, list) or len(emails) > 50:
                return self.json(400, {"ok": False, "error": "Ungültige Liste."})
            clean_list = []
            for e in emails:
                e = norm_email(e)
                if not e:
                    continue
                if not EMAIL_RE.match(e) or len(e) > 120:
                    return self.json(400, {"ok": False, "error": f"Ungültige E-Mail-Adresse: {e[:120]}"})
                if e not in clean_list:
                    clean_list.append(e)
            new = dict(a, emails=clean_list)
            if "client_id" in payload and not ENV("GOOGLE_CLIENT_ID", "").strip():
                cid = str(payload.get("client_id") or "").strip()
                if cid and not CLIENT_ID_RE.match(cid):
                    return self.json(400, {"ok": False, "error": "Das ist keine gültige Google Client ID "
                                                               "(…apps.googleusercontent.com)."})
                new["google_client_id"] = cid
            me = sess.get("email", "")
            if "@" in me and me not in admin_emails(new):
                return self.json(400, {"ok": False, "error": f"Damit würdest du dich selbst ({me}) aussperren."})
            if not admin_login_possible(new):
                return self.json(400, {"ok": False, "error": "Danach könnte sich niemand mehr anmelden. "
                                                           "Erzeuge zuerst Notfall-Codes oder lass ein Konto stehen."})
            save_auth(new)
            return self.json(200, {"ok": True})


# -------------------------------------------------------------------- Start
def cli_notfall_link() -> int:
    with AUTH_LOCK:
        tok = create_setup_token(NOTFALL_TTL, force=True)
    base = site_base_url()
    print(f"\nNotfall-Link für die Administration (einmalig, {NOTFALL_TTL // 60} Minuten gültig):\n")
    print(f"  {base or '<deine-domain>'}/admin/setup#{tok}\n")
    print("Er öffnet direkt eine Admin-Sitzung. Danach Google-Zugang prüfen oder neue Notfall-Codes erzeugen.\n")
    return 0


def announce_setup_if_needed():
    """Kann sich niemand anmelden (keine Client ID / keine erlaubten Konten / keine Codes),
    steht ein Notfall-Link im Log. Mit GOOGLE_CLIENT_ID + ADMIN_EMAILS passiert nichts."""
    if admin_login_possible():
        return None
    with AUTH_LOCK:
        tok = create_setup_token(NOTFALL_TTL_INITIAL, force=True)
    log.warning("Google-Anmeldung nicht eingerichtet: GOOGLE_CLIENT_ID und ADMIN_EMAILS in der ConfigMap setzen.")
    log_setup_link(tok, NOTFALL_TTL_INITIAL, "EINRICHTUNG")
    return tok


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    migrate_legacy_auth()
    if argv[:1] in (["notfall-link"], ["reset-admin"]):
        return cli_notfall_link()
    if argv:
        print("Verwendung: server.py [notfall-link]", file=sys.stderr)
        return 2

    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    log.info("%s läuft auf Port %s (Modus: %s, Währung: %s)", SHOP_NAME, PORT, "TESTMODUS" if TESTMODUS else "PRODUKTION", CURRENCY)
    announce_setup_if_needed()

    def stop(*_):
        log.info("Server wird beendet...")
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
