#!/usr/bin/env python3
import contextlib
import http.client
import io
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
import zipfile
import zlib
from pathlib import Path

# Add app to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "app"))

import server  # noqa: E402

PASSWORD = "korrekt-pferd-batterie"


def png(w=4, h=3):
    """Minimales gültiges PNG."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\x00\x00\x00" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def reset_globals(tmp):
    server.DATA_DIR = Path(tmp)
    server.RATES.clear()
    server.SESSIONS.clear()
    server.FAILS.clear()
    server.GLOBAL_FAILS.clear()
    server.RECOVERY_TIMES.clear()


class TestSiteEngineSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        reset_globals(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_sanitize_csv(self):
        # Prevent formula execution in Excel/LibreOffice Calc (CWE-1236)
        self.assertEqual(server.sanitize_csv("=1+1"), "'=1+1")
        self.assertEqual(server.sanitize_csv("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(server.sanitize_csv("-5+5"), "'-5+5")
        self.assertEqual(server.sanitize_csv("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(server.sanitize_csv("\tcmd"), "'\tcmd")
        self.assertEqual(server.sanitize_csv("Normal Text"), "Normal Text")
        self.assertEqual(server.sanitize_csv(""), "")

    def test_clean_input(self):
        self.assertEqual(server.clean("Hello\x00World\x1f!", 20), "HelloWorld!")
        with self.assertRaises(server.Fehler):
            server.clean("A" * 21, 20)
        # Keine Zeilenumbrüche in einzeiligen Feldern (Header-Injection)
        self.assertEqual(server.one_line("Max\r\nBcc: x@y.z", 80), "Max Bcc: x@y.z")

    def test_honeypot_blocking(self):
        payload = {"website": "http://spambot.com", "kunde": {}}
        with self.assertRaises(server.Fehler) as ctx:
            server.validate(payload)
        self.assertIn("Ungültige Anfrage", str(ctx.exception))

    def test_invalid_email(self):
        payload = {
            "kunde": {"name": "Max Muster", "adresse": "Musterstr 1", "plz_ort": "8000 Zürich",
                      "email": "invalid-email-address"},
            "positionen": [{"id": list(server.CAT["by_id"].keys())[0], "qty": 1, "motive": []}]
        }
        with self.assertRaises(server.Fehler) as ctx:
            server.validate(payload)
        self.assertIn("E-Mail", str(ctx.exception))

    def test_price_tampering_impossible(self):
        pid = list(server.CAT["by_id"].keys())[0]
        actual_price = server.CAT["by_id"][pid]["preis"]
        motives = server.CAT.get("motive", [])[:server.CAT["by_id"][pid].get("motive", 0)]
        payload = {
            "kunde": {"name": "Hacker", "adresse": "Str 1", "plz_ort": "1234 City", "email": "hacker@example.com"},
            "positionen": [{"id": pid, "qty": 2, "preis": 0.01, "betrag": 0.02, "motive": motives}]
        }
        order = server.validate(payload)
        self.assertEqual(order["zwischensumme"], actual_price * 2)
        self.assertEqual(order["positionen"][0]["preis"], actual_price)

    def test_non_dict_position_rejected(self):
        payload = {"kunde": {"name": "A", "adresse": "B", "plz_ort": "1234 C", "email": "a@b.ch"},
                   "positionen": ["x"]}
        with self.assertRaises(server.Fehler):
            server.validate(payload)

    def test_concurrent_order_number_generation(self):
        order_numbers = []
        lock = threading.Lock()

        def make_order():
            pid = list(server.CAT["by_id"].keys())[0]
            motives = server.CAT.get("motive", [])[:server.CAT["by_id"][pid].get("motive", 0)]
            payload = {
                "kunde": {"name": "Concurrency Tester", "adresse": "Testweg 1", "plz_ort": "8000 Zürich",
                          "email": "test@example.com"},
                "positionen": [{"id": pid, "qty": 1, "motive": motives}]
            }
            nr = server.save_order(server.validate(payload))
            with lock:
                order_numbers.append(nr)

        threads = [threading.Thread(target=make_order) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(order_numbers)), 20, "All order numbers must be strictly unique!")

    def test_rate_limiting_and_memory_cleanup(self):
        ip = "192.168.1.50"
        for _ in range(server.RATE_MAX):
            self.assertTrue(server.check_rate(ip))
        self.assertFalse(server.check_rate(ip))
        server.RATES.clear()
        for i in range(1200):
            server.check_rate(f"10.0.0.{i}")
        self.assertLessEqual(len(server.RATES), 1200)

    def test_custom_checkout_format_and_zip_import(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("shop-template/app/public/index.html", '''<!doctype html><html><head>
<script id="produkte" type="application/json">
{"versand":{"preis":9,"gratis_ab_betrag":60},"motive":["Motiv A"],"produkte":[{"id":"set-klein","name":"Set klein","groesse":"6 cm","preis":24,"motive":1,"set":true}]}
</script></head><body>Testshop</body></html>''')
            zf.writestr("shop-template/app/public/img/item-1.png", png())
            zf.writestr("shop-template/app/public/evil.php", b"<?php system($_GET['c']); ?>")
            zf.writestr("shop-template/app/public/../../escape.html", b"bad")

        count = server.import_zip_bytes(buf.getvalue())
        self.assertEqual(count, 2)
        self.assertTrue((server.custom_public_dir() / "index.html").is_file())
        self.assertTrue((server.custom_public_dir() / "img" / "item-1.png").is_file())
        self.assertFalse((server.custom_public_dir() / "evil.php").exists())

        payload = {
            "items": [{"id": "set-klein", "motive": ["Motiv A"], "qty": 1}],
            "kunde": {"name": "Max Muster", "email": "max@example.com", "telefon": "",
                      "strasse": "Musterstrasse 1", "plz": "8000", "ort": "Zürich"},
            "zahlung": "Twint", "nachricht": "Test", "agb": True, "website": "",
        }
        order = server.validate(payload)
        self.assertEqual((order["zwischensumme"], order["versand"], order["total"]), (24, 9, 33))
        self.assertEqual(order["kunde"]["plz_ort"], "8000 Zürich")

        server.save_runtime_settings({"mail_to": "orders@example.com", "testmodus": False})
        eff = server.get_effective_settings()
        self.assertEqual(eff["mail_to"], "orders@example.com")
        self.assertFalse(eff["testmodus"])
        self.assertNotIn("admin_user", eff)
        self.assertEqual(os.stat(server.custom_settings_file()).st_mode & 0o777, 0o600)
        server.reload_catalog()

    def test_zip_limits(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(server.MAX_ZIP_ENTRIES + 1):
                zf.writestr(f"img/{i}.txt", b"")
        with self.assertRaises(server.Fehler):
            server.import_zip_bytes(buf.getvalue())


class TestAuthPrimitives(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        reset_globals(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_password_hash_roundtrip(self):
        h = server.hash_password(PASSWORD)
        self.assertTrue(h.startswith("pbkdf2_sha256$600000$"))
        self.assertNotIn(PASSWORD, h)
        self.assertEqual(server.verify_password(PASSWORD, h), (True, False))
        self.assertEqual(server.verify_password("falsch", h), (False, False))
        self.assertEqual(server.verify_password(PASSWORD, "kaputt"), (False, False))
        self.assertEqual(server.verify_password(PASSWORD, ""), (False, False))
        self.assertNotEqual(server.hash_password(PASSWORD), h, "Salt muss zufällig sein")

    def test_new_password_rules(self):
        with self.assertRaises(server.Fehler):
            server.check_new_password("kurz")
        with self.assertRaises(server.Fehler):
            server.check_new_password(None)
        self.assertEqual(server.check_new_password(PASSWORD), PASSWORD)

    def test_totp_rfc6238_vector(self):
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        # RFC 6238 Anhang B, T=59 -> 94287082 (8 Stellen) -> 287082 (6 Stellen)
        self.assertEqual(server.totp_at(secret, 1, digits=8), "94287082")
        self.assertEqual(server.totp_at(secret, 1), "287082")
        self.assertEqual(server.totp_check(secret, "287 082", now=59), 1)
        self.assertIsNone(server.totp_check(secret, "287082", last_counter=1, now=59), "Replay muss scheitern")
        self.assertIsNone(server.totp_check(secret, "000000", now=59))
        self.assertIsNone(server.totp_check(secret, "abc", now=59))

    def test_setup_token_single_use_and_expiry(self):
        tok = server.create_setup_token()
        self.assertNotIn(tok, server.setup_token_file().read_text())
        self.assertFalse(server.consume_setup_token("falsch"))
        self.assertTrue(server.consume_setup_token(tok))
        self.assertFalse(server.consume_setup_token(tok), "Token darf nur einmal funktionieren")
        tok = server.create_setup_token()
        d = json.loads(server.setup_token_file().read_text())
        d["tokens"][0]["expires"] = time.time() - 1
        server.setup_token_file().write_text(json.dumps(d))
        self.assertFalse(server.consume_setup_token(tok))

    def test_tokens_cannot_be_evicted(self):
        first = server.create_setup_token("log")
        for _ in range(server.MAX_SETUP_TOKENS - 1):
            self.assertIsNotNone(server.create_setup_token("log"))
        self.assertIsNone(server.create_setup_token("log"), "voll: kein neuer Link ohne force")
        self.assertEqual(server.check_setup_token(first), "log", "bestehender Link bleibt gültig")
        self.assertIsNotNone(server.create_setup_token("log", force=True))
        self.assertEqual(len(server._load_setup_tokens()), server.MAX_SETUP_TOKENS)

    def test_startup_announces_setup_link(self):
        with self.assertLogs("site-engine", "WARNING") as cm:
            tok = server.announce_setup_if_needed()
        self.assertTrue(any(f"/admin/setup#{tok}" in line for line in cm.output))
        self.assertEqual(server.check_setup_token(tok), "log")
        exp = server._load_setup_tokens()[0]["expires"]
        self.assertGreater(exp - time.time(), 23 * 3600, "Erst-Link ist 24 h gültig")
        server.save_auth({"pw": server.hash_password(PASSWORD)})
        self.assertIsNone(server.announce_setup_if_needed(), "mit Passwort: kein Link")

    def test_legacy_migration(self):
        import hashlib
        salt = "c7ecf8c6d1ac14280a6b91bfad9cf6f6"
        digest = hashlib.pbkdf2_hmac("sha256", b"altes-passwort", salt.encode(), 100_000).hex()
        server.save_runtime_settings({"admin_user": "admin", "admin_password_hash": f"{salt}${digest}", "mail_to": "a@b.ch"})
        server.migrate_legacy_auth()
        s = server.load_runtime_settings()
        self.assertNotIn("admin_user", s)
        self.assertNotIn("admin_password_hash", s)
        self.assertEqual(s["mail_to"], "a@b.ch")
        ok, rehash = server.verify_password("altes-passwort", server.load_auth()["pw"])
        self.assertTrue(ok)
        self.assertTrue(rehash)

    def test_cli_reset_admin(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(server.main(["reset-admin"]), 0)
        link = [line for line in out.getvalue().splitlines() if "/admin/setup#" in line][0]
        self.assertTrue(server.consume_setup_token(link.split("#", 1)[1].strip()))
        self.assertEqual(server.main(["unbekannt"]), 2)


class TestImageHelpers(unittest.TestCase):
    def test_image_size_and_sniff(self):
        self.assertEqual(server.image_size(png(7, 5)), (7, 5))
        gif = b"GIF89a" + struct.pack("<HH", 12, 9) + b"\x00" * 10
        self.assertEqual(server.image_size(gif), (12, 9))
        jpg = (b"\xff\xd8\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + b"\x00" * 9 +
               b"\xff\xc0" + struct.pack(">HBHH", 17, 8, 300, 400) + b"\x00" * 12)
        self.assertEqual(server.image_size(jpg), (400, 300))
        webp = b"RIFF" + b"\x00" * 4 + b"WEBPVP8X" + b"\x00" * 8 + (99).to_bytes(3, "little") + (49).to_bytes(3, "little")
        self.assertEqual(server.image_size(webp), (100, 50))
        self.assertTrue(server.sniff_image(png(), ".png"))
        self.assertFalse(server.sniff_image(b"<html><script>", ".png"))
        self.assertTrue(server.sniff_image(b'<?xml version="1.0"?>\n<svg xmlns="..."/>', ".svg"))
        self.assertFalse(server.sniff_image(b"<html>", ".svg"))

    def test_names_and_paths(self):
        self.assertEqual(server.safe_image_name("../../Mein Foto (1).JPEG"), "mein-foto-1.jpg")
        with self.assertRaises(server.Fehler):
            server.safe_image_name("shell.php")
        self.assertEqual(server.norm_img_path("/img/galerie/a.png?v=2"), "img/galerie/a.png")
        for bad in ("img/../index.html", "index.html", "img/a.html", "../img/a.png", "img/x/../../a.png"):
            self.assertIsNone(server.norm_img_path(bad), bad)
        with self.assertRaises(server.Fehler):
            server.norm_folder("../x")
        with self.assertRaises(server.Fehler):
            server.norm_folder("Mit Leerzeichen", strict=True)
        self.assertEqual(server.norm_folder("img/galerie"), "galerie")

    def test_extract_refs(self):
        html = '''<img src="img/a.png"><img srcset="img/b.webp 1x, /img/c.jpg 2x">
        <div style="background:url('img/d.gif')"></div><img src="https://cdn.x/e.png">
        <img src="${p.bild}.png"><img src="data:image/png;base64,xx"><a href="kontakt.html">'''
        self.assertEqual(server.extract_image_refs(html),
                         ["img/a.png", "img/b.webp", "/img/c.jpg", "img/d.gif", "https://cdn.x/e.png"])

    def test_manifest_validation(self):
        m = server.parse_manifest({
            "nur_bereiche": True,
            "bereiche": [
                {"ordner": "galerie", "titel": "Galerie", "max": 3, "format": "4:3"},
                {"ordner": "../evil"},
                {"ordner": "team", "max": True, "format": "rm -rf"},
                {"ordner": "galerie", "titel": "Duplikat"},
            ],
            "bilder": {"img/galerie/a.png": {"text": "Hallo", "alt": "A"}, "../x.png": {"text": "nein"}},
        })
        self.assertTrue(m["nur_bereiche"])
        self.assertEqual([b["ordner"] for b in m["bereiche"]], ["galerie", "team"])
        self.assertEqual(m["bereiche"][1]["max"], None)
        self.assertEqual(m["bereiche"][1]["format"], "")
        self.assertEqual(list(m["bilder"]), ["img/galerie/a.png"])


class HTTPBase(unittest.TestCase):
    """Echter Server auf einem freien Port, Login über Einrichtungs-Link."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        reset_globals(self.tmp_dir.name)
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp_dir.cleanup()
        server.reload_catalog()

    def req(self, method, path, body=None, auth=True, headers=None, raw=None, csrf=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if auth and self.cookie:
            h["Cookie"] = self.cookie
            if csrf and self.csrf and method == "POST":
                h.setdefault("X-CSRF-Token", self.csrf)
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        c.request(method, path, data, h)
        r = c.getresponse()
        out = r.status, r.read()
        self.last_headers = r.headers
        c.close()
        return out

    def setup_admin(self):
        tok = server.create_setup_token()
        st, body = self.req("POST", "/admin/setup", {"token": tok, "passwort": PASSWORD}, auth=False)
        self.assertEqual(st, 200, body)
        self.cookie = self.last_headers["Set-Cookie"].split(";")[0]
        self.load_csrf()

    def load_csrf(self):
        st, body = self.req("GET", "/admin")
        self.assertEqual(st, 200)
        import re
        self.csrf = re.search(rb'name="csrf-token" content="([^"]+)"', body).group(1).decode()


class TestAuthHTTP(HTTPBase):
    def test_fresh_instance_requires_setup(self):
        st, body = self.req("GET", "/admin/login-info", auth=False)
        self.assertEqual(json.loads(body), {"setup": True, "totp": False})
        st, body = self.req("POST", "/admin/login", {"passwort": "irgendwas"}, auth=False)
        self.assertEqual(st, 409)
        self.assertEqual(self.req("GET", "/admin", auth=False)[0], 303)
        self.assertEqual(self.last_headers["Location"], "/admin/login")
        self.assertEqual(self.req("GET", "/api/admin/state", auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/admin/admin.js", auth=False)[0], 401)
        # Login-Seite ist öffentlich und erlaubt kein Inline-JS
        self.assertEqual(self.req("GET", "/admin/login", auth=False)[0], 200)
        csp = self.last_headers["Content-Security-Policy"]
        self.assertIn("script-src 'self';", csp)
        self.assertNotIn("unsafe-inline' https", csp.split("script-src")[1].split(";")[0])
        # Altes Basic-Auth geht nicht mehr
        self.assertEqual(self.req("GET", "/api/admin/state", auth=False,
                                  headers={"Authorization": "Basic YWRtaW46cHc="})[0], 401)

    def test_setup_login_logout(self):
        self.assertEqual(self.req("POST", "/admin/setup", {"token": "falsch", "passwort": PASSWORD}, auth=False)[0], 403)
        tok = server.create_setup_token()
        self.assertEqual(self.req("POST", "/admin/setup", {"token": tok, "passwort": "kurz"}, auth=False)[0], 400)
        self.setup_admin()
        cookie_hdr = self.last_headers.get("Set-Cookie")
        self.assertIsNone(cookie_hdr)  # nur beim Setup gesetzt; jetzt GET /admin
        st, body = self.req("GET", "/api/admin/state")
        self.assertEqual(st, 200)
        self.assertNotIn(b"pbkdf2", body)
        self.assertNotIn(b"smtp_pass\"", body)
        # Logout beendet die Sitzung
        self.assertEqual(self.req("POST", "/admin/logout", {})[0], 200)
        self.assertEqual(self.req("GET", "/api/admin/state")[0], 401)
        # Neu anmelden mit Passwort
        st, _ = self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False)
        self.assertEqual(st, 200)
        sc = self.last_headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Secure", "Path=/"):
            self.assertIn(flag, sc)
        self.assertTrue(sc.startswith("__Host-se_session="))
        self.cookie = sc.split(";")[0]
        self.assertEqual(self.req("GET", "/api/admin/state")[0], 200)

    def test_csrf_and_origin(self):
        self.setup_admin()
        page = {"slug": "x", "html": "<p>x</p>"}
        self.assertEqual(self.req("POST", "/api/admin/page", page, csrf=False)[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/page", page, headers={"X-CSRF-Token": "falsch"})[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/page", page, headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/page", page,
                                  headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)
        # Login von fremder Seite
        self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False,
                                  headers={"Origin": "https://evil.example"})[0], 403)

    def test_lockout(self):
        self.setup_admin()
        orig = server.time.sleep
        server.time.sleep = lambda s: None
        try:
            for _ in range(server.LOGIN_MAX_FAILS):
                self.assertEqual(self.req("POST", "/admin/login", {"passwort": "falsch"}, auth=False)[0], 401)
            # Auch das richtige Passwort wird jetzt abgewiesen
            self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False)[0], 429)
            # Andere IP (hinter Proxy) ist nicht betroffen ...
            self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False,
                                      headers={"X-Real-IP": "203.0.113.9"})[0], 200)
            # ... aber eine globale Obergrenze stoppt IP-Rotation
            for i in range(server.LOGIN_GLOBAL_MAX):
                self.req("POST", "/admin/login", {"passwort": "falsch"}, auth=False, headers={"X-Real-IP": f"198.51.100.{i}"})
            self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False,
                                      headers={"X-Real-IP": "192.0.2.77"})[0], 429)
        finally:
            server.time.sleep = orig

    def test_password_change_drops_other_sessions(self):
        self.setup_admin()
        st, _ = self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False)
        other = self.last_headers["Set-Cookie"].split(";")[0]
        self.assertEqual(self.req("POST", "/api/admin/password", {"aktuell": "falsch", "neu": "x" * 12})[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/password", {"aktuell": PASSWORD, "neu": "kurz"})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/password", {"aktuell": PASSWORD, "neu": "ein-neues-langes-pw"})[0], 200)
        self.assertEqual(self.req("GET", "/api/admin/state")[0], 200, "eigene Sitzung bleibt")
        self.assertEqual(self.req("GET", "/api/admin/state", headers={"Cookie": other}, auth=False)[0], 401)

    def test_totp_flow(self):
        self.setup_admin()
        self.assertEqual(self.req("POST", "/api/admin/totp-begin", {"aktuell": "falsch"})[0], 403)
        st, body = self.req("POST", "/api/admin/totp-begin", {"aktuell": PASSWORD})
        secret = json.loads(body)["secret"]
        self.assertTrue(json.loads(body)["uri"].startswith("otpauth://totp/"))
        self.assertEqual(self.req("POST", "/api/admin/totp-enable", {"code": "000000"})[0], 400)
        code = server.totp_at(secret, int(time.time() // 30))
        self.assertEqual(self.req("POST", "/api/admin/totp-enable", {"code": code})[0], 200)
        self.assertEqual(json.loads(self.req("GET", "/admin/login-info", auth=False)[1])["totp"], True)
        # Login ohne/mit falschem Code scheitert, Code-Replay ebenfalls
        self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD}, auth=False)[0], 401)
        self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD, "code": code}, auth=False)[0], 401)
        server.FAILS.clear()
        server.GLOBAL_FAILS.clear()
        next_code = server.totp_at(secret, int(time.time() // 30) + 1)
        self.assertEqual(self.req("POST", "/admin/login", {"passwort": PASSWORD, "code": next_code}, auth=False)[0], 200)
        # Reset über Einrichtungs-Link schaltet 2FA ab
        self.setup_admin()
        self.assertEqual(json.loads(self.req("GET", "/admin/login-info", auth=False)[1])["totp"], False)


class TestRecoveryHTTP(HTTPBase):
    def setUp(self):
        super().setUp()
        self.sent = []
        self._orig_send = server.send_mail
        server.send_mail = lambda to, subj, body, reply_to=None, force_live=False: self.sent.append((to, subj, body, force_live))

    def tearDown(self):
        server.send_mail = self._orig_send
        super().tearDown()

    def wait_mail(self, n=1):
        for _ in range(50):
            if len(self.sent) >= n:
                return
            time.sleep(0.05)
        self.fail("keine E-Mail verschickt")

    def log_token(self, output):
        return [l for l in output if "/admin/setup#" in l][0].split("#", 1)[1].strip()

    def test_new_site_link_via_button_and_log(self):
        with self.assertLogs("site-engine", "WARNING") as cm:
            st, _ = self.req("POST", "/admin/recover", {}, auth=False)
        self.assertEqual(st, 200)
        tok = self.log_token(cm.output)
        self.assertEqual(self.req("POST", "/admin/setup", {"token": tok, "passwort": PASSWORD}, auth=False)[0], 200)
        self.assertEqual(self.sent, [], "ohne E-Mail/SMTP nur Log")
        server.RECOVERY_TIMES.clear()
        for _ in range(server.RECOVERY_MAX):
            self.assertEqual(self.req("POST", "/admin/recover", {}, auth=False)[0], 200)
        self.assertEqual(self.req("POST", "/admin/recover", {}, auth=False)[0], 429)
        self.assertEqual(self.req("POST", "/admin/recover", {}, auth=False,
                                  headers={"Origin": "https://evil.example"})[0], 403)

    def configure_mail(self):
        self.setup_admin()
        self.req("POST", "/api/admin/settings", {"shop_url": "https://www.beispiel.ch", "smtp_user": "a@b.ch", "smtp_pass": "x"})
        self.assertEqual(self.req("POST", "/api/admin/recovery-email", {"aktuell": "falsch", "email": "ich@beispiel.ch"})[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/recovery-email", {"aktuell": PASSWORD, "email": "kaputt"})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/recovery-email", {"aktuell": PASSWORD, "email": "ich@beispiel.ch"})[0], 200)
        auth = json.loads(self.req("GET", "/api/admin/state")[1])["auth"]
        self.assertEqual((auth["email"], auth["smtp_ok"], auth["url_ok"]), ("ich@beispiel.ch", True, True))

    def mail_token(self):
        self.wait_mail()
        to, subj, body, live = self.sent[-1]
        self.assertEqual(to, "ich@beispiel.ch")
        self.assertTrue(live, "Wiederherstellung auch im Testmodus")
        link = [l for l in body.splitlines() if "/admin/setup#" in l][0]
        self.assertTrue(link.startswith("https://www.beispiel.ch/admin/setup#"), "Domain nur aus Konfiguration")
        return link.split("#", 1)[1]

    def test_forgot_password_by_email(self):
        self.configure_mail()
        # Host-Header-Poisoning: der Link darf nie auf die Domain des Angreifers zeigen
        self.assertEqual(self.req("POST", "/admin/recover", {}, auth=False, headers={"Host": "evil.example"})[0], 200)
        tok = self.mail_token()
        self.assertEqual(server.check_setup_token(tok), "email")
        self.assertEqual(self.req("POST", "/admin/setup", {"token": tok, "passwort": "ganz-neues-passwort"}, auth=False)[0], 200)
        self.assertEqual(self.req("POST", "/admin/login", {"passwort": "ganz-neues-passwort"}, auth=False)[0], 200)
        self.assertEqual(server.load_auth().get("email"), "ich@beispiel.ch", "E-Mail bleibt erhalten")
        self.assertIsNone(server.check_setup_token(tok), "Links sind danach verbraucht")

    def test_email_link_needs_2fa_log_link_resets_it(self):
        self.configure_mail()
        secret = json.loads(self.req("POST", "/api/admin/totp-begin", {"aktuell": PASSWORD})[1])["secret"]
        self.req("POST", "/api/admin/totp-enable", {"code": server.totp_at(secret, int(time.time() // 30))})
        with self.assertLogs("site-engine", "WARNING") as cm:
            self.req("POST", "/admin/recover", {}, auth=False)
        tok, log_tok = self.mail_token(), self.log_token(cm.output)
        st, body = self.req("POST", "/admin/setup", {"token": tok, "passwort": "ganz-neues-passwort"}, auth=False)
        self.assertEqual(st, 401)
        self.assertTrue(json.loads(body)["need_code"])
        code = server.totp_at(secret, int(time.time() // 30) + 1)
        st, _ = self.req("POST", "/admin/setup", {"token": tok, "passwort": "ganz-neues-passwort", "code": code}, auth=False)
        self.assertEqual(st, 200)
        self.assertTrue(server.load_auth()["totp"]["enabled"], "E-Mail-Link lässt 2FA bestehen")
        self.assertIsNone(server.check_setup_token(log_tok))
        # Link aus dem Log (Cluster-/Argo-CD-Zugriff) setzt 2FA zurück
        server.RECOVERY_TIMES.clear()
        with self.assertLogs("site-engine", "WARNING") as cm:
            self.req("POST", "/admin/recover", {}, auth=False)
        st, _ = self.req("POST", "/admin/setup", {"token": self.log_token(cm.output), "passwort": "drittes-passwort-xx"}, auth=False)
        self.assertEqual(st, 200)
        self.assertNotIn("totp", server.load_auth())


class TestFeaturesAndPages(HTTPBase):
    def setUp(self):
        super().setUp()
        self.setup_admin()

    def test_slug_validation(self):
        for ok in ("impressum", "ueber-uns", "a1"):
            self.assertTrue(server.valid_slug(ok), ok)
        for bad in ("", "../etc/passwd", "a/b", "A", "-x", "x" * 41, "admin", "api", "img", "a.b", "a%2fb", None, "sitemap"):
            self.assertFalse(server.valid_slug(bad), bad)

    def test_page_lifecycle_and_auth(self):
        html = "<!doctype html><html><body>Impressum</body></html>"
        self.assertEqual(self.req("POST", "/api/admin/page", {"slug": "impressum", "html": html}, auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/impressum")[0], 404)
        self.assertEqual(self.req("POST", "/api/admin/page", {"slug": "impressum", "html": html})[0], 200)
        st, body = self.req("GET", "/impressum", auth=False)
        self.assertEqual((st, body.decode()), (200, html))
        self.assertEqual(self.req("GET", "/impressum/", auth=False)[0], 200)
        self.assertEqual(self.req("GET", "/pages/impressum.html", auth=False)[0], 404)
        st, body = self.req("GET", "/api/admin/state")
        self.assertEqual([p["slug"] for p in json.loads(body)["pages"]], ["impressum"])
        self.assertEqual(self.req("POST", "/api/admin/page-delete", {"slug": "impressum"})[0], 200)
        self.assertEqual(self.req("GET", "/impressum", auth=False)[0], 404)

    def test_page_rejects_bad_slugs(self):
        for bad in ("../x", "admin", "A B", "x/y", ""):
            st, _ = self.req("POST", "/api/admin/page", {"slug": bad, "html": "<p>x</p>"})
            self.assertEqual(st, 400, bad)
        self.assertEqual(self.req("GET", "/api/admin/page?slug=..%2F..%2Fetc%2Fpasswd")[0], 400)

    def test_shop_feature_off_returns_404(self):
        pid = list(server.CAT["by_id"].keys())[0]
        order = {"positionen": [{"id": pid, "qty": 1}]}
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 200)
        self.assertEqual(self.req("POST", "/api/admin/settings", {"features": {"shop": False}})[0], 200)
        self.assertFalse(server.feature_enabled("shop"))
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 404)
        self.assertEqual(self.req("POST", "/api/bestellung", order, auth=False)[0], 404)
        self.assertEqual(self.req("GET", "/api/admin/orders.csv")[0], 404)
        self.assertEqual(self.req("POST", "/api/admin/catalog", {"produkte": [{}]})[0], 404)
        st, body = self.req("GET", "/api/admin/state")
        self.assertEqual(json.loads(body)["features"], {"shop": False, "kontakt": False, "seo": False, "wartung": False})
        self.req("POST", "/api/admin/settings", {"features": {"shop": True}})
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 200)

    def test_settings_validation(self):
        self.assertEqual(self.req("POST", "/api/admin/settings", {"mail_to": "keine-mail"})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/settings", {"shop_url": "javascript:alert(1)"})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/settings", {"smtp_host": "evil host;"})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/settings", {"shop_name": "x" * 500})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/settings", {"shop_name": "Ok\r\nBcc: a@b.c"})[0], 200)
        self.assertEqual(server.get_effective_settings()["shop_name"], "Ok Bcc: a@b.c")

    def test_env_default_and_missing_catalog(self):
        old = os.environ.get("FEATURE_SHOP")
        os.environ["FEATURE_SHOP"] = "0"
        try:
            self.assertFalse(server.feature_enabled("shop"))
            orig = server.CONFIG_FILE, server.active_index_file
            server.CONFIG_FILE = Path(self.tmp_dir.name) / "none.json"
            server.active_index_file = lambda: Path(self.tmp_dir.name) / "none.html"
            try:
                self.assertEqual(server.load_config_and_catalog()["produkte"], [])
                os.environ["FEATURE_SHOP"] = "1"
                with self.assertRaises(SystemExit):
                    server.load_config_and_catalog()
            finally:
                server.CONFIG_FILE, server.active_index_file = orig
        finally:
            if old is None:
                os.environ.pop("FEATURE_SHOP", None)
            else:
                os.environ["FEATURE_SHOP"] = old

    def test_backup_has_no_secrets(self):
        self.req("POST", "/api/admin/settings", {"smtp_pass": "geheim-smtp-pw"})
        st, body = self.req("GET", "/api/admin/backup.zip")
        self.assertEqual(st, 200)
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = zf.namelist()
            blob = b"".join(zf.read(n) for n in names)
        self.assertNotIn(b"geheim-smtp-pw", blob)
        self.assertNotIn(b"pbkdf2", blob)
        self.assertFalse(any("admin" in n for n in names))


class TestBilder(HTTPBase):
    def setUp(self):
        super().setUp()
        self.setup_admin()

    def upload(self, folder, name, data):
        from urllib.parse import quote
        return self.req("POST", f"/api/admin/bilder-upload?ordner={quote(folder)}&name={quote(name)}", raw=data,
                        headers={"Content-Type": "application/octet-stream"})

    def state(self):
        return json.loads(self.req("GET", "/api/admin/state")[1])["bilder"]

    def test_placeholders_hidden(self):
        st = self.state()
        self.assertEqual(st["bereiche"], [])
        self.assertEqual(st["seiten"], [])

    def test_upload_validation(self):
        st, body = self.upload("galerie", "Mein Bild.PNG", png())
        self.assertEqual(st, 200, body)
        self.assertEqual(json.loads(body)["path"], "img/galerie/mein-bild.png")
        self.assertEqual(self.upload("galerie", "fake.png", b"<html><script>alert(1)</script>")[0], 400)
        self.assertEqual(self.upload("galerie", "x.html", b"<html>")[0], 400)
        self.assertEqual(self.upload("../../etc", "x.png", png())[0], 400)
        self.assertEqual(self.upload("Neu Ordner", "x.png", png())[0], 400)
        self.assertFalse((Path(self.tmp_dir.name) / "etc").exists())
        sec = self.state()["bereiche"]
        self.assertEqual([(s["ordner"], [i["path"] for i in s["bilder"]]) for s in sec],
                         [("galerie", ["img/galerie/mein-bild.png"])])
        self.assertEqual((sec[0]["bilder"][0]["w"], sec[0]["bilder"][0]["h"]), (4, 3))

    def test_delete_only_images(self):
        self.upload("", "logo.png", png())
        server.ensure_custom_public()
        for bad in ("index.html", "img/../index.html", "../site/config/settings.json"):
            self.assertEqual(self.req("POST", "/api/admin/bilder-delete", {"path": bad})[0], 400, bad)
        self.assertTrue((server.custom_public_dir() / "index.html").is_file())
        self.assertEqual(self.req("POST", "/api/admin/bilder-delete", {"path": "img/logo.png"})[0], 200)
        self.assertFalse((server.custom_public_dir() / "img" / "logo.png").exists())

    def test_manifest_zip_sections_order_and_public_api(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("site/public/index.html", '<html><head></head><body><img src="img/team/anna.png">'
                                                  '<img src="img/logo.svg"><img src="img/fehlt.png"></body></html>')
            zf.writestr("site/public/img/team/anna.png", png())
            zf.writestr("site/public/img/team/ben.png", png(8, 8))
            zf.writestr("site/public/img/sonstiges/x.png", png())
            zf.writestr("bilder.json", json.dumps({
                "bereiche": [{"ordner": "hero", "titel": "Titelbild", "max": 1, "format": "16:9"},
                             {"ordner": "team", "titel": "Team", "beschriftung": True}],
                "bilder": {"img/team/anna.png": {"text": "Anna, Gründerin", "alt": "Porträt Anna"}},
            }))
        st, body = self.req("POST", "/api/admin/upload-zip", raw=buf.getvalue(),
                            headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(st, 200, body)
        self.assertFalse((server.custom_public_dir() / "bilder.json").exists())

        # Subseite mit Bild
        self.req("POST", "/api/admin/page", {"slug": "ueber-uns", "html": '<img src="/img/team/ben.png">'})

        sec = self.state()
        self.assertEqual([s["ordner"] for s in sec["bereiche"]], ["hero", "team", "sonstiges"])
        team = sec["bereiche"][1]
        self.assertEqual(team["bilder"][0]["text"], "Anna, Gründerin")
        self.assertEqual(team["bilder"][0]["verwendet"], ["/"])
        self.assertEqual(team["bilder"][1]["verwendet"], ["/ueber-uns"])
        seiten = {p["seite"]: p["bilder"] for p in sec["seiten"]}
        self.assertEqual([(b["path"], b["status"]) for b in seiten["/"]],
                         [("img/team/anna.png", "ok"), ("img/fehlt.png", "fehlt")])  # Vorlagen-Logo ausgeblendet
        self.assertEqual(seiten["/ueber-uns"][0]["path"], "img/team/ben.png")

        # Maximalanzahl
        self.assertEqual(self.upload("hero", "a.png", png(16, 9))[0], 200)
        self.assertEqual(self.upload("hero", "b.png", png())[0], 400)
        self.assertEqual(self.upload("hero", "a.png", png(32, 18))[0], 200, "Ersetzen bleibt erlaubt")

        # Reihenfolge & Beschriftung speichern
        st, _ = self.req("POST", "/api/admin/bilder-save", {"ordner": "team", "bilder": [
            {"path": "img/team/ben.png", "text": "Ben", "alt": "Ben"},
            {"path": "img/team/anna.png", "text": "Anna", "alt": "Anna"},
            {"path": "img/sonstiges/x.png", "text": "falscher Bereich"},
        ]})
        self.assertEqual(st, 200)
        pub = json.loads(self.req("GET", "/api/bilder", auth=False)[1])
        team = [b for b in pub["bereiche"] if b["ordner"] == "team"][0]
        self.assertEqual([(i["src"], i["text"]) for i in team["bilder"]],
                         [("/img/team/ben.png", "Ben"), ("/img/team/anna.png", "Anna")])
        self.assertNotIn("falscher Bereich", json.dumps(pub))

    def test_nur_bereiche_and_folders(self):
        self.assertEqual(self.req("POST", "/api/admin/bilder-ordner", {"ordner": "projekte"})[0], 200)
        self.assertEqual(self.req("POST", "/api/admin/bilder-ordner", {"ordner": "../x"})[0], 400)
        self.assertIn("projekte", [s["ordner"] for s in self.state()["bereiche"]])
        self.assertEqual(self.req("POST", "/api/admin/bilder-ordner-delete", {"ordner": "projekte"})[0], 200)
        meta = server.load_bilder_meta()
        meta["nur_bereiche"] = True
        meta["bereiche"] = [{"ordner": "galerie", "titel": "G", "beschreibung": "", "max": None, "format": "", "beschriftung": True}]
        server.save_bilder_meta(meta)
        self.assertEqual(self.req("POST", "/api/admin/bilder-ordner", {"ordner": "neu"})[0], 400)
        self.assertEqual(self.upload("neu", "a.png", png())[0], 400)
        self.assertEqual(self.upload("galerie", "a.png", png())[0], 200)

    def test_etag_and_conditional_get(self):
        self.upload("", "e.png", png())
        st, _ = self.req("GET", "/img/e.png", auth=False)
        etag = self.last_headers["ETag"]
        self.assertEqual(self.req("GET", "/img/e.png", auth=False, headers={"If-None-Match": etag})[0], 304)
        self.upload("", "e.png", png(9, 9))
        self.assertEqual(self.req("GET", "/img/e.png", auth=False, headers={"If-None-Match": etag})[0], 200)

    def test_svg_served_sandboxed(self):
        self.upload("", "icon.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
        st, _ = self.req("GET", "/img/icon.svg", auth=False)
        self.assertEqual(st, 200)
        self.assertIn("sandbox", self.last_headers["Content-Security-Policy"])


class TestKontaktWartungSeo(HTTPBase):
    def setUp(self):
        super().setUp()
        self.setup_admin()

    def test_kontakt(self):
        msg = {"name": "Max", "email": "max@example.com", "betreff": "Frage\r\nBcc: x@y.z", "nachricht": "Hallo\nWelt"}
        self.assertEqual(self.req("POST", "/api/kontakt", msg, auth=False)[0], 404, "standardmässig aus")
        self.req("POST", "/api/admin/settings", {"features": {"kontakt": True}})
        self.assertEqual(self.req("POST", "/api/kontakt", dict(msg, website="spam"), auth=False)[0], 400)
        self.assertEqual(self.req("POST", "/api/kontakt", dict(msg, email="x"), auth=False)[0], 400)
        self.assertEqual(self.req("POST", "/api/kontakt", msg, auth=False, headers={"Origin": "https://evil.example"})[0], 403)
        st, body = self.req("POST", "/api/kontakt", msg, auth=False)
        self.assertEqual(st, 200, body)
        # Formular ohne JavaScript
        st, _ = self.req("POST", "/api/kontakt", auth=False, raw=b"name=Eva&email=eva%40example.com&nachricht=Hi&weiter=/kontakt",
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual((st, self.last_headers["Location"]), (303, "/kontakt?kontakt=ok"))
        st, _ = self.req("POST", "/api/kontakt", auth=False, raw=b"name=Eva&email=eva%40example.com&nachricht=Hi&weiter=https://evil.example",
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(self.last_headers["Location"], "/?kontakt=ok", "kein Open Redirect")
        nachrichten = json.loads(self.req("GET", "/api/admin/state")[1])["nachrichten"]
        self.assertEqual(len(nachrichten), 3)
        first = [n for n in nachrichten if n["name"] == "Max"][0]
        self.assertEqual(first["betreff"], "Frage Bcc: x@y.z")
        self.assertEqual(first["nachricht"], "Hallo\nWelt")
        self.assertEqual(self.req("POST", "/api/admin/nachricht-delete", {"id": first["id"]})[0], 200)
        self.assertEqual(len(json.loads(self.req("GET", "/api/admin/state")[1])["nachrichten"]), 2)
        # Rate-Limit
        for _ in range(server.RATE_MAX):
            self.req("POST", "/api/kontakt", msg, auth=False, headers={"X-Real-IP": "203.0.113.5"})
        self.assertEqual(self.req("POST", "/api/kontakt", msg, auth=False, headers={"X-Real-IP": "203.0.113.5"})[0], 429)

    def test_wartung(self):
        self.req("POST", "/api/admin/settings", {"features": {"wartung": True}, "wartung_titel": "<b>Bald</b> zurück"})
        st, body = self.req("GET", "/", auth=False)
        self.assertEqual(st, 503)
        self.assertIn(b"&lt;b&gt;Bald&lt;/b&gt;", body)
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 503)
        self.assertEqual(self.req("GET", "/healthz", auth=False)[0], 200)
        self.assertEqual(self.req("GET", "/admin/login", auth=False)[0], 200)
        self.assertEqual(self.req("GET", "/")[0], 200, "Admin sieht die Webseite")
        self.req("POST", "/api/admin/settings", {"features": {"wartung": False}})
        self.assertEqual(self.req("GET", "/", auth=False)[0], 200)

    def test_seo(self):
        self.assertEqual(self.req("GET", "/sitemap.xml", auth=False)[0], 404)
        self.req("POST", "/api/admin/settings", {"features": {"seo": True}, "shop_url": "https://www.beispiel.ch",
                                                  "seo_titel": "Beispiel & Co", "seo_beschreibung": 'Wir "machen" Dinge'})
        self.req("POST", "/api/admin/page", {"slug": "kontakt", "html": "<html><head><title>Eigener</title></head><body></body></html>"})
        st, body = self.req("GET", "/sitemap.xml", auth=False)
        self.assertEqual(st, 200)
        self.assertIn(b"<loc>https://www.beispiel.ch/</loc>", body)
        self.assertIn(b"<loc>https://www.beispiel.ch/kontakt</loc>", body)
        st, body = self.req("GET", "/robots.txt", auth=False)
        self.assertIn(b"Sitemap: https://www.beispiel.ch/sitemap.xml", body)
        st, body = self.req("GET", "/kontakt", auth=False)
        self.assertIn(b"<title>Eigener</title>", body)
        self.assertEqual(body.count(b"<title>"), 1, "vorhandener Titel bleibt")
        self.assertIn(b'content="Wir &quot;machen&quot; Dinge"', body)
        self.assertIn(b'<link rel="canonical" href="https://www.beispiel.ch/kontakt">', body)


if __name__ == "__main__":
    unittest.main()
