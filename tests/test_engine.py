#!/usr/bin/env python3
import base64
import contextlib
import hashlib
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

CLIENT_ID = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"
ADMIN = "admin@beispiel.ch"

# Fester 2048-Bit-RSA-Testschlüssel (nur für Tests) – damit werden echte RS256-Tokens signiert.
TEST_N = int("c42603300b22d47ad06f1a116ed3a210d56f240b1f4eb877fc7634eaa5c80498b4c83626c775385c55ac311d5f7b45c9956e2510d964ce6660d52f6a1b8fe8cd517c071c74530d42a91a8aab1ac8a3e25a6901f5763769c077096b21137c500b67193a5a5ee1ae2d369ee81f869567502cc62c13f8699a59af6ed4348ab141a683159bae00d6e59e891037064da5cc57592f0197d6cbb3f0db0c89bf7fc839dc8a9c537e5ccdccd9a37f61d815de6b4b1cf7108ef82d94f354aae7f7832c01b7f550c9b64c0c5431afe4dab3441d3bd20da4b945b564832bfa41fd39c3b40b7f5915b873b8bb2a3b272df88291ed4b0ac52017e3c12ffbace647d9772b10a131", 16)
TEST_D = int("663708e2386b661eba0fab9dfa0aff219697dc488f800e513896c0eca6879d1d96d7dea046c0a72636df0c9929f0ab65692184df4aea6544a4a1739befd10698382651ee5a100d90f75e8574b4f869aec33e856eccb403bff0485033645c1bba5577a818ffe8cb43747b4aab630ee84fb7856de2da48edce5ec57a8006e66836da4844e95c84ac9056edf344d516fd90d8a044448aeb1560f2fcd0e706db2975b1e29814b66098bacfec5716159d6bf3a3a3573dca8e657596155627f92fdeece3dbeb4ab75cf1cb376131f6ff7877fa5ff2e06573104c9c9ecb75aa30b3b5cf07ae68a4149043072ee4edd9424602b62ebb8dd9ad229f07ac8e740b26b60f3", 16)
TEST_KID = "test-kid-1"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign_rs256(msg: bytes, n=None, d=None) -> bytes:
    n, d = n or TEST_N, d or TEST_D
    k = (n.bit_length() + 7) // 8
    t = server.SHA256_DIGEST_INFO + hashlib.sha256(msg).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def google_token(nonce, email=ADMIN, aud=CLIENT_ID, iss="https://accounts.google.com", exp_in=3600,
                 verified=True, kid=TEST_KID, alg="RS256", **extra):
    now = int(time.time())
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    claims = dict({"iss": iss, "aud": aud, "sub": "1234", "email": email, "email_verified": verified,
                   "iat": now, "exp": now + exp_in, "nonce": nonce}, **extra)
    h = b64u(json.dumps(header).encode()); p = b64u(json.dumps(claims).encode())
    return f"{h}.{p}.{b64u(sign_rs256(f'{h}.{p}'.encode()))}"


class FakeGoogle:
    """Liefert den Testschlüssel als JWKS aus (wie https://www.googleapis.com/oauth2/v3/certs)."""
    requests = 0

    def __init__(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.requests += 1
                body = json.dumps({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": TEST_KID,
                                             "n": b64u(TEST_N.to_bytes(256, "big")), "e": "AQAB"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "public, max-age=3600")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/certs"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


FAKE_GOOGLE = FakeGoogle()
server.GOOGLE_CERTS_URL = FAKE_GOOGLE.url


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
    server.USED_NONCES.clear()
    server.JWKS.update({"keys": {}, "expires": 0.0, "fetched": 0.0})


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

    def test_rsa_signature(self):
        msg = b"hallo"
        sig = sign_rs256(msg)
        self.assertTrue(server.rsa_sha256_verify(TEST_N, 65537, msg, sig))
        self.assertFalse(server.rsa_sha256_verify(TEST_N, 65537, b"hallo!", sig))
        bad = bytearray(sig); bad[-1] ^= 1
        self.assertFalse(server.rsa_sha256_verify(TEST_N, 65537, msg, bytes(bad)))
        self.assertFalse(server.rsa_sha256_verify(TEST_N, 3, msg, sig), "nur e=65537")
        self.assertFalse(server.rsa_sha256_verify(TEST_N, 65537, msg, sig[1:]), "falsche Länge")
        self.assertFalse(server.rsa_sha256_verify(TEST_N, 65537, msg, TEST_N.to_bytes(256, "big")), "s >= n")
        small = 0xC2E9  # zu kurzer Schlüssel
        self.assertFalse(server.rsa_sha256_verify(small, 65537, msg, b"\x01" * 2))

    def check(self, token, nonce="n1", cid=CLIENT_ID):
        return server.verify_google_token(token, cid, nonce)

    def test_google_token_validation(self):
        claims = self.check(google_token("n1", email="Admin@Beispiel.CH"))
        self.assertEqual(claims["email"], "admin@beispiel.ch")
        self.check(google_token("n1", iss="accounts.google.com"))
        cases = {
            "fremde Client ID": google_token("n1", aud="999-x.apps.googleusercontent.com"),
            "abgelaufen": google_token("n1", exp_in=-120),
            "falscher Aussteller": google_token("n1", iss="https://evil.example"),
            "falsche Nonce": google_token("anders"),
            "unbestätigte E-Mail": google_token("n1", verified=False),
            "alg none": google_token("n1", alg="none"),
            "unbekannter Schlüssel": google_token("n1", kid="gibts-nicht"),
            "kaputt": "a.b.c",
            "kein JWT": "hallo",
        }
        for name, tok in cases.items():
            with self.assertRaises(server.AuthFehler, msg=name):
                self.check(tok)
        # Signatur manipuliert: andere E-Mail in den Claims, alte Signatur
        h, p, sg = google_token("n1").split(".")
        p2 = b64u(json.dumps(dict(json.loads(base64.urlsafe_b64decode(p + "==")), email="evil@x.ch")).encode())
        with self.assertRaises(server.AuthFehler):
            self.check(f"{h}.{p2}.{sg}")
        with self.assertRaises(server.AuthFehler):
            self.check(google_token("n1"), cid="")
        with self.assertRaises(server.AuthFehler):
            self.check(google_token(""), nonce="")

    def test_google_keys_cached(self):
        FAKE_GOOGLE.requests = 0
        for _ in range(3):
            self.check(google_token("n1"))
        self.assertEqual(FAKE_GOOGLE.requests, 1, "Schlüssel werden gecacht")
        for _ in range(3):
            with self.assertRaises(server.AuthFehler):
                self.check(google_token("n1", kid="neu"))
        self.assertEqual(FAKE_GOOGLE.requests, 1, "unbekannte kid: höchstens alle 30 s neu laden")

    def test_notfall_codes(self):
        codes = server.new_notfall_codes()
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        self.assertRegex(codes[0], r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$")
        server.save_auth({"notfall_codes": [server.sha256_hex(server.norm_notfall_code(c)) for c in codes]})
        self.assertNotIn(codes[0], server.auth_file().read_text())
        self.assertEqual(server.use_notfall_code(codes[0].lower().replace("-", " ")), 9)
        self.assertIsNone(server.use_notfall_code(codes[0]), "nur einmal gültig")
        self.assertIsNone(server.use_notfall_code("AAAA-AAAA-AAAA-AAAA"))
        self.assertIsNone(server.use_notfall_code(""))

    def test_setup_token_single_use_and_expiry(self):
        tok = server.create_setup_token()
        self.assertNotIn(tok, server.setup_token_file().read_text())
        self.assertFalse(server.consume_setup_token("falsch"))
        self.assertTrue(server.consume_setup_token(tok))
        self.assertFalse(server.consume_setup_token(tok))
        tok = server.create_setup_token()
        d = json.loads(server.setup_token_file().read_text())
        d["tokens"][0]["expires"] = time.time() - 1
        server.setup_token_file().write_text(json.dumps(d))
        self.assertFalse(server.consume_setup_token(tok))

    def test_tokens_cannot_be_evicted(self):
        first = server.create_setup_token()
        for _ in range(server.MAX_SETUP_TOKENS - 1):
            self.assertIsNotNone(server.create_setup_token())
        self.assertIsNone(server.create_setup_token())
        self.assertTrue(server.check_setup_token(first))
        self.assertIsNotNone(server.create_setup_token(force=True))
        self.assertEqual(len(server._load_setup_tokens()), server.MAX_SETUP_TOKENS)

    def test_startup_announce_only_when_nobody_can_log_in(self):
        with env(GOOGLE_CLIENT_ID=None, ADMIN_EMAILS=None):
            with self.assertLogs("site-engine", "WARNING") as cm:
                tok = server.announce_setup_if_needed()
            self.assertTrue(any(f"/admin/setup#{tok}" in line for line in cm.output))
        with env(GOOGLE_CLIENT_ID=CLIENT_ID, ADMIN_EMAILS=ADMIN):
            self.assertIsNone(server.announce_setup_if_needed(), "mit ConfigMap: kein Link nötig")

    def test_admin_emails_and_client_id(self):
        with env(ADMIN_EMAILS=" Admin@Beispiel.ch, kunde@gmail.com;kaputt ", GOOGLE_CLIENT_ID=None):
            server.save_auth({"emails": ["Zweiter@x.ch"], "google_client_id": CLIENT_ID})
            self.assertEqual(server.admin_emails(), ["admin@beispiel.ch", "kunde@gmail.com", "zweiter@x.ch"])
            self.assertEqual(server.google_client_id(), CLIENT_ID)
        with env(GOOGLE_CLIENT_ID="999-envwins.apps.googleusercontent.com"):
            self.assertEqual(server.google_client_id(), "999-envwins.apps.googleusercontent.com")

    def test_legacy_cleanup(self):
        server.save_runtime_settings({"admin_user": "admin", "admin_password_hash": "a$b", "mail_to": "a@b.ch"})
        server.save_auth({"pw": "pbkdf2_sha256$1$aa$bb", "totp": {"enabled": True}, "email": "x@y.z", "emails": [ADMIN]})
        server.migrate_legacy_auth()
        self.assertEqual(server.load_runtime_settings(), {"mail_to": "a@b.ch"})
        self.assertEqual(server.load_auth(), {"emails": [ADMIN]})

    def test_cli_notfall_link(self):
        for cmd in ("notfall-link", "reset-admin"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(server.main([cmd]), 0)
            link = [line for line in out.getvalue().splitlines() if "/admin/setup#" in line][0]
            self.assertTrue(server.consume_setup_token(link.split("#", 1)[1].strip()))
        self.assertEqual(server.main(["unbekannt"]), 2)


@contextlib.contextmanager
def env(**kw):
    old = {k: os.environ.get(k) for k in kw}
    for k, v in kw.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


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
    """Echter Server auf einem freien Port; Anmeldung über (simuliertes) Google."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        reset_globals(self.tmp_dir.name)
        self._env = env(GOOGLE_CLIENT_ID=CLIENT_ID, ADMIN_EMAILS=ADMIN)
        self._env.__enter__()
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._env.__exit__(None, None, None)
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

    def nonce(self):
        st, body = self.req("GET", "/admin/login-info", auth=False)
        cookie = [v for k, v in self.last_headers.items() if k.lower() == "set-cookie"][0].split(";")[0]
        return json.loads(body)["nonce"], cookie

    def google_login(self, email=ADMIN, **kw):
        nonce, ncookie = self.nonce()
        tok = google_token(nonce, email=email, **kw)
        st, body = self.req("POST", "/admin/google", {"credential": tok}, auth=False, headers={"Cookie": ncookie})
        return st, body, tok, ncookie

    def setup_admin(self, email=ADMIN):
        st, body, _, _ = self.google_login(email)
        self.assertEqual(st, 200, body)
        cookies = [v for k, v in self.last_headers.items() if k.lower() == "set-cookie"]
        self.cookie = [c for c in cookies if "session" in c][0].split(";")[0]
        self.load_csrf()

    def load_csrf(self):
        st, body = self.req("GET", "/admin")
        self.assertEqual(st, 200)
        import re
        self.csrf = re.search(rb'name="csrf-token" content="([^"]+)"', body).group(1).decode()


class TestAuthHTTP(HTTPBase):
    def test_login_page_and_unauthenticated(self):
        st, body = self.req("GET", "/admin/login-info", auth=False)
        info = json.loads(body)
        self.assertEqual((info["client_id"], info["erlaubt"], info["notfall"]), (CLIENT_ID, True, False))
        self.assertIn("HttpOnly", self.last_headers["Set-Cookie"])
        self.assertEqual(self.req("GET", "/admin", auth=False)[0], 303)
        self.assertEqual(self.last_headers["Location"], "/admin/login")
        self.assertEqual(self.req("GET", "/api/admin/state", auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/admin/admin.js", auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/admin/login", auth=False)[0], 200)
        csp = self.last_headers["Content-Security-Policy"]
        self.assertIn("script-src 'self' https://accounts.google.com/gsi/client;", csp)
        self.assertNotIn("unsafe-inline", csp.split("script-src")[1].split(";")[0])
        self.assertEqual(self.last_headers["Cross-Origin-Opener-Policy"], "same-origin-allow-popups")
        # Andere Admin-Seiten bleiben streng
        self.req("GET", "/admin/setup", auth=False)
        self.assertNotIn("google", self.last_headers["Content-Security-Policy"])
        self.assertEqual(self.last_headers["Cross-Origin-Opener-Policy"], "same-origin")
        # Passwort- und Basic-Auth-Wege gibt es nicht mehr
        self.assertEqual(self.req("POST", "/admin/login", {"passwort": "x"}, auth=False)[0], 404)
        self.assertEqual(self.req("GET", "/api/admin/state", auth=False,
                                  headers={"Authorization": "Basic YWRtaW46cHc="})[0], 401)

    def test_google_login_and_logout(self):
        self.setup_admin()
        sc = [v for k, v in self.last_headers.items()]  # nach load_csrf
        st, body = self.req("GET", "/api/admin/state")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["auth"]["ich"], ADMIN)
        self.assertEqual(self.req("POST", "/admin/logout", {})[0], 200)
        self.assertEqual(self.req("GET", "/api/admin/state")[0], 401)
        st, _, _, _ = self.google_login()
        cookies = [v for k, v in self.last_headers.items() if k.lower() == "set-cookie"]
        session = [c for c in cookies if "session" in c][0]
        for flag in ("HttpOnly", "SameSite=Strict", "Secure", "Path=/"):
            self.assertIn(flag, session)
        self.assertTrue(session.startswith("__Host-se_session="))
        self.assertTrue(any(c.startswith("__Host-se_nonce=;") and "Max-Age=0" in c for c in cookies), "Nonce wird gelöscht")

    def test_google_login_rejections(self):
        st, body, _, _ = self.google_login(email="fremder@gmail.com")
        self.assertEqual(st, 403)
        self.assertIn("keinen Zugang", json.loads(body)["error"])
        self.assertEqual(self.google_login(aud="999-x.apps.googleusercontent.com")[0], 401)
        self.assertEqual(self.google_login(verified=False)[0], 401)
        # Token ohne passendes Nonce-Cookie (z. B. abgefangen und in anderem Browser benutzt)
        nonce, _ = self.nonce()
        tok = google_token(nonce)
        self.assertEqual(self.req("POST", "/admin/google", {"credential": tok}, auth=False)[0], 401)
        self.assertEqual(self.req("POST", "/admin/google", {"credential": tok}, auth=False,
                                  headers={"Cookie": "__Host-se_nonce=anders"})[0], 401)
        # Login von fremder Seite
        server.FAILS.clear(); server.GLOBAL_FAILS.clear()
        nonce, ncookie = self.nonce()
        self.assertEqual(self.req("POST", "/admin/google", {"credential": google_token(nonce)}, auth=False,
                                  headers={"Cookie": ncookie, "Origin": "https://evil.example"})[0], 403)

    def test_token_replay(self):
        st, _, tok, ncookie = self.google_login()
        self.assertEqual(st, 200)
        st, body = self.req("POST", "/admin/google", {"credential": tok}, auth=False, headers={"Cookie": ncookie})
        self.assertEqual(st, 401)
        self.assertIn("schon benutzt", json.loads(body)["error"])

    def test_lockout(self):
        orig = server.time.sleep
        server.time.sleep = lambda s: None
        try:
            for _ in range(server.LOGIN_MAX_FAILS):
                self.assertEqual(self.google_login(email="fremder@gmail.com")[0], 403)
            self.assertEqual(self.google_login()[0], 429, "auch das richtige Konto ist jetzt gesperrt")
            for i in range(server.LOGIN_GLOBAL_MAX):
                self.req("POST", "/admin/notfall", {"code": "AAAA-AAAA-AAAA-AAAA"}, auth=False,
                         headers={"X-Real-IP": f"198.51.100.{i}"})
            self.assertEqual(self.req("POST", "/admin/notfall", {"code": "x"}, auth=False,
                                      headers={"X-Real-IP": "192.0.2.77"})[0], 429, "globale Obergrenze")
        finally:
            server.time.sleep = orig

    def test_csrf_and_origin(self):
        self.setup_admin()
        page = {"slug": "x", "html": "<p>x</p>"}
        self.assertEqual(self.req("POST", "/api/admin/page", page, csrf=False)[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/page", page, headers={"X-CSRF-Token": "falsch"})[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/page", page, headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/admin/page", page,
                                  headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_access_management(self):
        self.setup_admin()
        self.assertEqual(self.req("POST", "/api/admin/access", {"emails": ["kaputt"]})[0], 400)
        self.assertEqual(self.req("POST", "/api/admin/access", {"emails": ["Kunde@Gmail.com", "kunde@gmail.com"]})[0], 200)
        self.assertEqual(server.load_auth()["emails"], ["kunde@gmail.com"])
        # Kunde kann sich jetzt anmelden
        self.assertEqual(self.google_login(email="kunde@gmail.com")[0], 200)
        # Client ID aus der ConfigMap kann im Admin nicht überschrieben werden
        self.req("POST", "/api/admin/access", {"emails": [], "client_id": "999-x.apps.googleusercontent.com"})
        self.assertEqual(server.google_client_id(), CLIENT_ID)

    def test_access_without_env(self):
        """Client ID und Konten nur über das Admin-UI (ohne ConfigMap), inkl. Selbstaussperr-Schutz."""
        with env(GOOGLE_CLIENT_ID=None, ADMIN_EMAILS=None):
            tok = server.create_setup_token()
            self.assertEqual(self.req("POST", "/admin/setup", {"token": tok}, auth=False)[0], 200)
            self.cookie = self.last_headers["Set-Cookie"].split(";")[0]
            self.load_csrf()
            self.assertEqual(self.req("POST", "/api/admin/access", {"emails": [ADMIN], "client_id": "kein-client"})[0], 400)
            self.assertEqual(self.req("POST", "/api/admin/access", {"emails": [], "client_id": CLIENT_ID})[0], 400,
                             "ohne Konto und ohne Notfall-Codes käme niemand mehr rein")
            self.assertEqual(self.req("POST", "/api/admin/access", {"emails": [ADMIN], "client_id": CLIENT_ID})[0], 200)
            self.cookie = None
            self.setup_admin()
            self.assertEqual(self.req("POST", "/api/admin/access", {"emails": ["anderer@x.ch"]})[0], 400, "Selbstaussperrung")

    def test_notfall_codes_flow(self):
        self.setup_admin()
        st, body = self.req("POST", "/api/admin/notfall-codes", {})
        codes = json.loads(body)["codes"]
        self.assertEqual(json.loads(self.req("GET", "/api/admin/state")[1])["auth"]["notfall_codes"], 10)
        self.assertNotIn(codes[0].encode(), self.req("GET", "/api/admin/state")[1], "Codes nur einmal sichtbar")
        self.req("POST", "/admin/logout", {})
        st, body = self.req("POST", "/admin/notfall", {"code": codes[3]}, auth=False)
        self.assertEqual((st, json.loads(body)["uebrig"]), (200, 9))
        self.assertEqual(self.req("POST", "/admin/notfall", {"code": codes[3]}, auth=False)[0], 401)
        self.assertTrue(json.loads(self.req("GET", "/admin/login-info", auth=False)[1])["notfall"])

    def test_notfall_link(self):
        tok = server.create_setup_token()
        self.assertEqual(self.req("POST", "/admin/setup", {"token": "falsch"}, auth=False)[0], 403)
        self.assertEqual(self.req("POST", "/admin/setup", {"token": tok}, auth=False)[0], 200)
        self.cookie = self.last_headers["Set-Cookie"].split(";")[0]
        self.assertEqual(self.req("GET", "/api/admin/state")[0], 200)
        self.assertEqual(self.req("POST", "/admin/setup", {"token": tok}, auth=False)[0], 403, "nur einmal")


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
