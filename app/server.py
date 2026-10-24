#!/usr/bin/env python3
"""Site-Engine: Schlanker, produktionshärteter Webshop- und Website-Server mit /admin-Cockpit.

Liefert die Webseite aus /data/site/public (Fallback: app/public) aus,
nimmt Bestellungen unter POST /api/bestellung an und bietet unter /admin
ein passwortgeschütztes Verwaltungs-UI für Katalog, Preise, Bilder, ZIP-Import und Bestellungen.
Nur Python-Standardbibliothek, keine externen Abhängigkeiten.
"""
import base64
import csv
import datetime as dt
import fcntl
import hashlib
import hmac
import io
import json
import logging
import mimetypes
import os
import re
import signal
import smtplib
import ssl
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
CONFIG_FILE = Path(ENV("CONFIG_FILE", Path(__file__).with_name("config") / "site.json")).resolve()
DATA_DIR = Path(ENV("DATA_DIR", "/data")).resolve()
TESTMODUS = ENV("TESTMODUS", "1") == "1"
TRUST_PROXY = ENV("TRUST_PROXY", "1") == "1"
ADMIN_USER = ENV("ADMIN_USER", "admin")
ADMIN_PASSWORD = ENV("ADMIN_PASSWORD", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("site-engine")

ALLOWED_ASSET_EXTS = {".html", ".css", ".js", ".json", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".woff2", ".txt"}
ALLOWED_IMAGE_EXTS = {".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif"}
MAX_BODY = 32 * 1024
MAX_ADMIN_BODY = 50 * 1024 * 1024  # 50 MB für ZIP-/Bild-Uploads im Admin-UI
RATE_MAX = int(ENV("RATE_MAX", "5"))
RATE_WINDOW = int(ENV("RATE_WINDOW", "900"))


def custom_public_dir() -> Path:
    return (DATA_DIR / "site" / "public").resolve()


def custom_config_file() -> Path:
    return (DATA_DIR / "site" / "config" / "site.json").resolve()


def active_index_file() -> Path:
    c_idx = custom_public_dir() / "index.html"
    if c_idx.is_file():
        return c_idx
    return PUBLIC_DIR / "index.html"


# ------------------------------------------------- Konfiguration & Katalog laden
def load_config_and_catalog():
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
        raise SystemExit("Produktliste weder in site.json noch in public/index.html gefunden")

    for p in cfg.get("produkte", []):
        if "preis" not in p and "price" in p:
            p["preis"] = p["price"]
    cfg["by_id"] = {p["id"]: p for p in cfg.get("produkte", [])}
    return cfg


CAT = load_config_and_catalog()


def reload_catalog():
    global CAT
    CAT = load_config_and_catalog()
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


class Fehler(Exception):
    pass


def clean(v, n):
    v = str(v or "").strip()
    v = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", v)
    if len(v) > n:
        raise Fehler("Eine Eingabe ist zu lang.")
    return v


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
        "name": clean(k.get("name"), 80),
        "adresse": strasse,
        "strasse": strasse,
        "plz": plz,
        "ort": ort,
        "plz_ort": plz_ort,
        "email": clean(k.get("email"), 120),
        "telefon": clean(k.get("telefon"), 40),
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
        pid = str((it or {}).get("id") or "")
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


# ---------------------------------------------------------------- Speichern
STORE_LOCK = threading.Lock()


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
    return f"{ORDER_PREFIX}-{year}-{n:03d}"


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


def send_mail(to, subject, body, reply_to=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((SHOP_NAME, MAIL_FROM))
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain=SHOP_NAME.lower().replace(" ", "") + ".internal")
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(body)

    if TESTMODUS:
        log.info("[TESTMODUS] E-Mail an %s NICHT gesendet. Betreff: %s", to, subject)
        return
    ctx = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=20) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls(context=ctx)
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)


def notify(o):
    k, nr = o["kunde"], o["bestellnummer"]
    shop_body = (f"Neue Bestellung {nr} vom {o['datum']}\n\n{summary(o)}\n\n"
                 f"E-Mail: {k['email']}\nTelefon: {k['telefon'] or '–'}\n"
                 f"Nachricht: {o['nachricht'] or '–'}\n\n"
                 f"Zahlungsart: {o.get('zahlung', 'Rechnung')}")
    kunde_body = (f"Hallo {k['name'].split()[0]}\n\n"
                  f"Danke für deine Bestellung bei {SHOP_NAME}! Wir haben sie erhalten.\n\n"
                  f"Bestellnummer: {nr}\n\n{summary(o)}\n\n"
                  f"Als Nächstes schicken wir dir die "
                  f"{'Twint-Zahlungsanfrage' if o.get('zahlung') == 'Twint' else 'Rechnung (zahlbar innert 10 Tagen)'}. "
                  f"Nach dem Zahlungseingang wird deine Bestellung bearbeitet und versendet.\n\n"
                  f"Fragen? Antworte einfach auf diese E-Mail.\n\n"
                  f"Liebe Grüsse\n{SHOP_NAME}\n{SHOP_ADDRESS}\n{SHOP_URL}".strip())
    ok = True
    for to, subj, body, rt in ((MAIL_TO, f"Neue Bestellung {nr} – {CURRENCY} {fmt_money(o['total'])}", shop_body, k["email"]),
                               (k["email"], f"Deine Bestellung {nr} bei {SHOP_NAME}", kunde_body, MAIL_TO)):
        try:
            send_mail(to, subj, body, rt)
        except Exception as e:
            ok = False
            log.error("E-Mail an %s fehlgeschlagen (%s): %s", to, nr, e)
    return ok


# --------------------------------------------------------- Admin-Hilfsfunktionen
def ensure_custom_public():
    """Stellt sicher, dass /data/site/public existiert und eine index.html besitzt."""
    c_pub = custom_public_dir()
    c_pub.mkdir(parents=True, exist_ok=True)
    c_idx = c_pub / "index.html"
    if not c_idx.exists() and (PUBLIC_DIR / "index.html").exists():
        c_idx.write_text((PUBLIC_DIR / "index.html").read_text(encoding="utf-8"), encoding="utf-8")
    return c_pub


def list_all_images():
    found = set()
    for base in (PUBLIC_DIR, custom_public_dir()):
        img_dir = base / "img"
        if img_dir.is_dir():
            for f in img_dir.rglob("*"):
                if f.is_file() and f.suffix.lower() in ALLOWED_IMAGE_EXTS:
                    found.add(str(f.relative_to(base)).replace("\\", "/"))
    return sorted(found)


def read_orders():
    jsonl = DATA_DIR / "bestellungen.jsonl"
    if not jsonl.is_file():
        return []
    out = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return list(reversed(out))


def import_zip_bytes(raw_bytes: bytes) -> int:
    """Entpackt Web-Assets (index.html, img/...) aus einem hochgeladenen ZIP nach /data/site/public."""
    c_pub = ensure_custom_public()
    c_cfg = custom_config_file()
    c_cfg.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > 20 * 1024 * 1024:
                continue
            norm = info.filename.replace("\\", "/").lstrip("/")
            if ".." in norm.split("/"):
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
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        c_pub = custom_public_dir()
        src_pub = c_pub if (c_pub / "index.html").exists() else PUBLIC_DIR
        if src_pub.is_dir():
            for f in src_pub.rglob("*"):
                if f.is_file() and f.name != "admin.html":
                    zf.write(f, f"public/{f.relative_to(src_pub)}")
        for fname in ("bestellungen.csv", "bestellungen.jsonl"):
            fpath = DATA_DIR / fname
            if fpath.is_file():
                zf.write(fpath, f"orders/{fname}")
    return buf.getvalue()


# ------------------------------------------------------------------- Server
SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ),
}
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("text/javascript", ".js")


class Handler(BaseHTTPRequestHandler):
    server_version = "SiteEngine/1.1"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.info("%s %s", self.client_ip(), fmt % args)

    def client_ip(self):
        if TRUST_PROXY:
            for h in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
                v = self.headers.get(h)
                if v:
                    return v.split(",")[0].strip()
        return self.client_address[0]

    def send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None, head=False):
        self.send_response(code)
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def json(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8",
                  {"Cache-Control": "no-store"})

    def check_admin_auth(self) -> bool:
        expected_user = ENV("ADMIN_USER", ADMIN_USER)
        expected_pw = ENV("ADMIN_PASSWORD", ADMIN_PASSWORD)
        expected_hash = ENV("ADMIN_PASSWORD_HASH", "")
        if not expected_pw and not expected_hash:
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(auth[6:].strip()).decode("utf-8")
            user, pw = raw.split(":", 1)
        except Exception:
            return False
        if not hmac.compare_digest(user, expected_user):
            return False
        if expected_hash and "$" in expected_hash:
            salt, digest = expected_hash.split("$", 1)
            calc = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
            return hmac.compare_digest(calc, digest)
        if expected_pw:
            return hmac.compare_digest(pw, expected_pw)
        return False

    def require_admin(self) -> bool:
        if self.check_admin_auth():
            return True
        self.send(401, b"Authentifizierung erforderlich",
                  extra={"WWW-Authenticate": 'Basic realm="Shop Admin", charset="UTF-8"'})
        return False

    # --- statische Dateien, Admin & Healthchecks
    def do_GET(self, head=False):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        if path in ("/healthz", "/readyz"):
            return self.send(200, b"ok", head=head, extra={"Cache-Control": "no-store"})
        if path == "/api/config":
            return self.json(200, CAT)

        # Admin-UI & Admin-GET-Endpunkte
        if path in ("/admin", "/admin/"):
            if not self.require_admin():
                return
            admin_file = PUBLIC_DIR / "admin.html"
            return self.send(200, admin_file.read_bytes(), "text/html; charset=utf-8",
                             extra={"Cache-Control": "no-store"}, head=head)

        if path.startswith("/api/admin/"):
            if not self.require_admin():
                return
            if path == "/api/admin/state":
                idx = active_index_file()
                html = idx.read_text(encoding="utf-8") if idx.exists() else ""
                community = []
                motif_images = {}
                m_com = re.search(r"var\s+COMMUNITY\s*=\s*(\[.*?\])\s*;", html, re.S)
                if m_com:
                    try:
                        community = json.loads(m_com.group(1))
                    except Exception:
                        pass
                m_img = re.search(r"var\s+IMG\s*=\s*(\{.*?\})\s*;", html, re.S)
                if m_img:
                    try:
                        motif_images = json.loads(m_img.group(1))
                    except Exception:
                        pass
                return self.json(200, {
                    "catalog": {
                        "versand": CAT.get("versand", {"preis": 9, "gratis_ab_betrag": 60}),
                        "motive": CAT.get("motive", []),
                        "produkte": CAT.get("produkte", []),
                    },
                    "community": community,
                    "motif_images": motif_images,
                    "images": list_all_images(),
                    "html": html,
                    "orders": read_orders()[:200],
                })
            if path == "/api/admin/orders.csv":
                csv_path = DATA_DIR / "bestellungen.csv"
                data = csv_path.read_bytes() if csv_path.is_file() else b"Noch keine Bestellungen\n"
                return self.send(200, data, "text/csv; charset=utf-8", extra={
                    "Content-Disposition": 'attachment; filename="bestellungen.csv"',
                    "Cache-Control": "no-store",
                }, head=head)
            if path == "/api/admin/backup.zip":
                zbytes = build_backup_zip()
                return self.send(200, zbytes, "application/zip", extra={
                    "Content-Disposition": 'attachment; filename="shop-backup.zip"',
                    "Cache-Control": "no-store",
                }, head=head)
            return self.json(404, {"error": "Unbekannter Admin-Endpunkt"})

        if path.endswith("/"):
            path += "index.html"
        rel = path.lstrip("/")
        if rel == "admin.html":
            if not self.require_admin():
                return

        # Zuerst im persistenten Kunden-Verzeichnis (/data/site/public) suchen, sonst Fallback auf PUBLIC_DIR
        target = None
        for base in (custom_public_dir(), PUBLIC_DIR):
            cand = (base / rel).resolve()
            try:
                if cand.is_relative_to(base) and cand.is_file():
                    target = cand
                    break
            except (ValueError, RuntimeError):
                continue

        if target is None:
            return self.send(404, b"Nicht gefunden", head=head)

        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("+xml"):
            ctype += "; charset=utf-8"
        cache = "no-cache"
        etag = f'"{int(target.stat().st_mtime)}-{len(data)}"'
        if self.headers.get("If-None-Match") == etag:
            return self.send(304, head=head)
        self.send(200, data, ctype=ctype, extra={"Cache-Control": cache, "ETag": etag}, head=head)

    def do_HEAD(self):
        self.do_GET(head=True)

    # --- Bestellungen & Admin-Aktionen
    def do_POST(self):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)

        if path.startswith("/api/admin/"):
            if not self.require_admin():
                return
            return self.handle_admin_post(path, parsed.query)

        if path != "/api/bestellung":
            return self.json(404, {"ok": False, "error": "Unbekannter Endpunkt", "fehler": "Unbekannter Endpunkt"})

        ip = self.client_ip()
        if not check_rate(ip):
            msg = "Zu viele Anfragen. Bitte warte einige Minuten."
            return self.json(429, {"ok": False, "error": msg, "fehler": msg})

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self.json(400, {"ok": False, "error": "Ungültige Inhaltslänge", "fehler": "Ungültige Inhaltslänge"})
        if length <= 0 or length > MAX_BODY:
            return self.json(413, {"ok": False, "error": "Anfrage zu gross", "fehler": "Anfrage zu gross"})

        body = self.rfile.read(length)
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
            "mail_gesendet": mail_ok or TESTMODUS,
        })

    def handle_admin_post(self, path: str, query: str):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self.json(400, {"ok": False, "error": "Ungültige Inhaltslänge"})
        if length <= 0 or length > MAX_ADMIN_BODY:
            return self.json(413, {"ok": False, "error": "Upload zu gross (max. 50 MB)"})

        body = self.rfile.read(length)

        with STORE_LOCK:
            if path == "/api/admin/upload-zip":
                try:
                    n = import_zip_bytes(body)
                    return self.json(200, {"ok": True, "files": n})
                except Exception as e:
                    return self.json(400, {"ok": False, "error": f"Ungültiges ZIP-Archiv: {e}"})

            if path == "/api/admin/upload-image":
                qs = parse_qs(query)
                rel = (qs.get("path") or [""])[0].replace("\\", "/").lstrip("/")
                ext = Path(rel).suffix.lower()
                if not rel.startswith("img/") or ".." in rel.split("/") or ext not in ALLOWED_IMAGE_EXTS:
                    return self.json(400, {"ok": False, "error": "Ungültiger Bildpfad"})
                c_pub = ensure_custom_public()
                dest = (c_pub / rel).resolve()
                if not dest.is_relative_to(c_pub):
                    return self.json(400, {"ok": False, "error": "Ungültiger Zielpfad"})
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(body)
                return self.json(200, {"ok": True, "path": rel})

            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                return self.json(400, {"ok": False, "error": "Ungültiges JSON"})

            if path == "/api/admin/delete-image":
                rel = str(payload.get("path") or "").replace("\\", "/").lstrip("/")
                c_pub = custom_public_dir()
                target = (c_pub / rel).resolve()
                if target.is_relative_to(c_pub) and target.is_file():
                    target.unlink()
                return self.json(200, {"ok": True})

            if path == "/api/admin/catalog":
                if not isinstance(payload.get("produkte"), list) or not payload["produkte"]:
                    return self.json(400, {"ok": False, "error": "Mindestens ein Produkt erforderlich."})
                c_pub = ensure_custom_public()
                c_idx = c_pub / "index.html"
                new_cat_json = json.dumps({
                    "versand": payload.get("versand", {"preis": 9, "gratis_ab_betrag": 60}),
                    "motive": payload.get("motive", []),
                    "produkte": payload["produkte"],
                }, ensure_ascii=False, indent=2)
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

            if path == "/api/admin/galleries":
                c_pub = ensure_custom_public()
                c_idx = c_pub / "index.html"
                if c_idx.is_file():
                    html = c_idx.read_text(encoding="utf-8")
                    if isinstance(payload.get("community"), list):
                        com_json = json.dumps(payload["community"], ensure_ascii=False, indent=2)
                        html = re.sub(
                            r"var\s+COMMUNITY\s*=\s*\[.*?\]\s*;",
                            lambda _: f"var COMMUNITY = {com_json};",
                            html,
                            count=1,
                            flags=re.S,
                        )
                    if isinstance(payload.get("motif_images"), dict):
                        img_json = json.dumps(payload["motif_images"], ensure_ascii=False, indent=2)
                        html = re.sub(
                            r"var\s+IMG\s*=\s*\{.*?\}\s*;",
                            lambda _: f"var IMG = {img_json};",
                            html,
                            count=1,
                            flags=re.S,
                        )
                    c_idx.write_text(html, encoding="utf-8")
                return self.json(200, {"ok": True})

            if path == "/api/admin/html":
                html = str(payload.get("html") or "")
                if len(html) < 50:
                    return self.json(400, {"ok": False, "error": "HTML-Inhalt ist leer oder zu kurz."})
                c_pub = ensure_custom_public()
                (c_pub / "index.html").write_text(html, encoding="utf-8")
                reload_catalog()
                return self.json(200, {"ok": True})

        return self.json(404, {"ok": False, "error": "Unbekannter Admin-Endpunkt"})


# -------------------------------------------------------------------- Start
def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("%s läuft auf Port %s (Modus: %s, Währung: %s)", SHOP_NAME, PORT, "TESTMODUS" if TESTMODUS else "PRODUKTION", CURRENCY)

    def stop(*_):
        log.info("Server wird beendet...")
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    server.serve_forever()


if __name__ == "__main__":
    main()
