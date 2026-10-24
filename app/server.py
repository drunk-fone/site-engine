#!/usr/bin/env python3
"""Site-Engine: Schlanker, produktionshärteter Webshop- und Website-Server.

Liefert die Webseite aus public/ aus und nimmt Bestellungen unter
POST /api/bestellung an. Nur Python-Standardbibliothek, keine externen Abhängigkeiten.

Einstellungen kommen aus app/config/site.json und können durch
Umgebungsvariablen im Kubernetes-Cluster überschrieben werden:
  PORT, DATA_DIR, PUBLIC_DIR, CONFIG_FILE, TESTMODUS, TRUST_PROXY,
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_TO, MAIL_FROM,
  SHOP_NAME, SHOP_URL, SHOP_ADDRESS, CURRENCY, ORDER_PREFIX
"""
import csv
import datetime as dt
import fcntl
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
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

# ---------------------------------------------------------------- Einstellungen
ENV = os.environ.get
PORT = int(ENV("PORT", "8080"))
PUBLIC_DIR = Path(ENV("PUBLIC_DIR", Path(__file__).with_name("public"))).resolve()
CONFIG_FILE = Path(ENV("CONFIG_FILE", Path(__file__).with_name("config") / "site.json")).resolve()
DATA_DIR = Path(ENV("DATA_DIR", "/data")).resolve()
TESTMODUS = ENV("TESTMODUS", "1") == "1"
TRUST_PROXY = ENV("TRUST_PROXY", "1") == "1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("site-engine")

# ------------------------------------------------- Konfiguration & Katalog laden
def load_config_and_catalog():
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            log.info("Konfiguration aus %s geladen", CONFIG_FILE)
        except Exception as e:
            log.warning("Fehler beim Lesen von %s: %s", CONFIG_FILE, e)

    # Wenn im JSON noch keine Produkte definiert sind, aus index.html auslesen
    if "produkte" not in cfg:
        index_file = PUBLIC_DIR / "index.html"
        if index_file.exists():
            text = index_file.read_text(encoding="utf-8")
            m = re.search(r'<script id="produkte" type="application/json">(.*?)</script>', text, re.S)
            if m:
                html_catalog = json.loads(m.group(1))
                cfg.update(html_catalog)

    if "produkte" not in cfg:
        raise SystemExit("Produktliste weder in site.json noch in public/index.html gefunden")

    cfg["by_id"] = {p["id"]: p for p in cfg.get("produkte", [])}
    return cfg

CAT = load_config_and_catalog()

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

MAX_BODY = 32 * 1024
RATE_MAX = int(ENV("RATE_MAX", "5"))          # Bestellungen pro IP …
RATE_WINDOW = int(ENV("RATE_WINDOW", "900"))  # … in Sekunden

def fmt_money(n):
    return f"{n:.2f}"

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
    # Honigtopf gegen Bots
    if payload.get("website"):
        raise Fehler("Ungültige Anfrage.")

    k = payload.get("kunde") or {}
    kunde = {
        "name": clean(k.get("name"), 80),
        "adresse": clean(k.get("adresse"), 120),
        "plz_ort": clean(k.get("plz_ort"), 80),
        "email": clean(k.get("email"), 120),
        "telefon": clean(k.get("telefon"), 40),
    }
    for field in ("name", "adresse", "plz_ort", "email"):
        if not kunde[field]:
            raise Fehler("Bitte fülle alle Pflichtfelder der Adresse aus.")
    if not EMAIL_RE.match(kunde["email"]):
        raise Fehler("Bitte gib eine gültige E-Mail-Adresse ein.")

    raw_pos = payload.get("positionen")
    if not isinstance(raw_pos, list) or not raw_pos or len(raw_pos) > 30:
        raise Fehler("Der Warenkorb ist leer oder zu gross.")

    motive_set = set(CAT.get("motive", []))
    positionen, subtotal = [], 0
    for it in raw_pos:
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
        if not isinstance(motive, list) or len(motive) != p.get("motive", 0):
            raise Fehler("Bitte wähle für jedes Produkt die richtige Anzahl Motive.")
        for m in motive:
            if m not in motive_set:
                raise Fehler("Ein gewähltes Motiv ist ungültig.")

        betrag = p["preis"] * qty
        subtotal += betrag
        positionen.append({
            "id": pid,
            "name": p["name"],
            "groesse": p.get("groesse", ""),
            "preis": p["preis"],
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
        "nachricht": clean(payload.get("nachricht"), 500),
        "zahlung": zahlung,
    }

# ------------------------------------------------------------- Rate-Limiter
RATES, RATES_LOCK = {}, threading.Lock()

def check_rate(ip):
    now = time.time()
    with RATES_LOCK:
        times = [t for t in RATES.get(ip, []) if now - t < RATE_WINDOW]
        if len(times) >= RATE_MAX:
            return False
        times.append(now)
        RATES[ip] = times
    return True

# ---------------------------------------------------------------- Speichern
STORE_LOCK = threading.Lock()

def next_order_number(year):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cfile = DATA_DIR / f"zaehler-{year}.txt"
    with STORE_LOCK, open(cfile, "a+", encoding="utf-8") as f:
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
    o["bestellnummer"] = next_order_number(now.year)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
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
        w.writerow({"Bestellnummer": o["bestellnummer"], "Datum": o["datum"],
                    "Name": k["name"], "Adresse": k["adresse"], "PLZ_Ort": k["plz_ort"],
                    "E-Mail": k["email"], "Telefon": k["telefon"], "Zahlung": o["zahlung"],
                    "Positionen": pos_txt,
                    "Zwischensumme": fmt_money(o["zwischensumme"]), "Versand": fmt_money(o["versand"]),
                    "Total": fmt_money(o["total"]), "Nachricht": o["nachricht"]})
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
                  f"Als Nächstes schicken wir dir die Zahlungsanfrage / Rechnung. "
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

# ------------------------------------------------------------------- Server
SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; "
                                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; "
                                "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
}
mimetypes.add_type("image/svg+xml", ".svg")

class Handler(BaseHTTPRequestHandler):
    server_version = "SiteEngine/1.0"

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

    # --- statische Dateien & Healthchecks
    def do_GET(self, head=False):
        path = unquote(urlsplit(self.path).path)
        if path in ("/healthz", "/readyz"):
            return self.send(200, b"ok", head=head, extra={"Cache-Control": "no-store"})
        if path == "/api/config":
            return self.json(200, CAT)
        if path.endswith("/"):
            path += "index.html"
        target = (PUBLIC_DIR / path.lstrip("/")).resolve()
        if PUBLIC_DIR not in target.parents or not target.is_file():
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

    # --- Bestellungen annehmen
    def do_POST(self):
        path = unquote(urlsplit(self.path).path)
        if path != "/api/bestellung":
            return self.json(404, {"error": "Unbekannter Endpunkt"})

        ip = self.client_ip()
        if not check_rate(ip):
            return self.json(429, {"error": "Zu viele Anfragen. Bitte warte einige Minuten."})

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self.json(400, {"error": "Ungültige Inhaltslänge"})
        if length <= 0 or length > MAX_BODY:
            return self.json(413, {"error": "Anfrage zu gross"})

        body = self.wfile.read(length) if hasattr(self.rfile, "read") else b""
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return self.json(400, {"error": "Ungültiges JSON"})

        try:
            order = validate(data)
        except Fehler as e:
            return self.json(400, {"error": str(e)})

        try:
            nr = save_order(order)
        except Exception as e:
            log.exception("Fehler beim Speichern der Bestellung: %s", e)
            return self.json(500, {"error": "Konnte die Bestellung nicht speichern."})

        mail_ok = notify(order)
        log.info("Bestellung %s gespeichert, %s %s (Mail: %s)", nr, CURRENCY, fmt_money(order["total"]), "ok" if mail_ok else "fehler")
        return self.json(200, {
            "ok": True,
            "bestellnummer": nr,
            "total": order["total"],
            "currency": CURRENCY,
            "mail_gesendet": mail_ok or TESTMODUS,
        })

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
