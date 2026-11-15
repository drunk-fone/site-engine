#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

# Add app to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "app"))

import server

class TestSiteEngineSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        server.DATA_DIR = Path(self.tmp_dir.name)
        server.RATES.clear()

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
        # Strips control characters
        self.assertEqual(server.clean("Hello\x00World\x1f!", 20), "HelloWorld!")
        # Enforces length
        with self.assertRaises(server.Fehler):
            server.clean("A" * 21, 20)

    def test_honeypot_blocking(self):
        # Honeypot filled by bots should be rejected
        payload = {"website": "http://spambot.com", "kunde": {}}
        with self.assertRaises(server.Fehler) as ctx:
            server.validate(payload)
        self.assertIn("Ungültige Anfrage", str(ctx.exception))

    def test_invalid_email(self):
        payload = {
            "kunde": {
                "name": "Max Muster",
                "adresse": "Musterstr 1",
                "plz_ort": "8000 Zürich",
                "email": "invalid-email-address",
            },
            "positionen": [{"id": list(server.CAT["by_id"].keys())[0], "qty": 1, "motive": []}]
        }
        with self.assertRaises(server.Fehler) as ctx:
            server.validate(payload)
        self.assertIn("E-Mail", str(ctx.exception))

    def test_price_tampering_impossible(self):
        # Client sends a fake price of 0.01
        pid = list(server.CAT["by_id"].keys())[0]
        actual_price = server.CAT["by_id"][pid]["preis"]
        expected_motive_count = server.CAT["by_id"][pid].get("motive", 0)
        motives = server.CAT.get("motive", [])[:expected_motive_count]

        payload = {
            "kunde": {
                "name": "Hacker",
                "adresse": "Str 1",
                "plz_ort": "1234 City",
                "email": "hacker@example.com",
            },
            "positionen": [{"id": pid, "qty": 2, "preis": 0.01, "betrag": 0.02, "motive": motives}]
        }
        order = server.validate(payload)
        # Server must strictly compute subtotal using server catalog price, ignoring payload price
        expected_subtotal = actual_price * 2
        self.assertEqual(order["zwischensumme"], expected_subtotal)
        self.assertEqual(order["positionen"][0]["preis"], actual_price)

    def test_concurrent_order_number_generation(self):
        # Concurrency test with 20 threads simulating simultaneous orders
        order_numbers = []
        lock = threading.Lock()

        def make_order():
            pid = list(server.CAT["by_id"].keys())[0]
            motives = server.CAT.get("motive", [])[:server.CAT["by_id"][pid].get("motive", 0)]
            payload = {
                "kunde": {
                    "name": "Concurrency Tester",
                    "adresse": "Testweg 1",
                    "plz_ort": "8000 Zürich",
                    "email": "test@example.com",
                },
                "positionen": [{"id": pid, "qty": 1, "motive": motives}]
            }
            order = server.validate(payload)
            nr = server.save_order(order)
            with lock:
                order_numbers.append(nr)

        threads = [threading.Thread(target=make_order) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(order_numbers), 20)
        self.assertEqual(len(set(order_numbers)), 20, "All order numbers must be strictly unique!")

    def test_rate_limiting_and_memory_cleanup(self):
        # 1. Verify rate limit blocks after RATE_MAX
        ip = "192.168.1.50"
        for _ in range(server.RATE_MAX):
            self.assertTrue(server.check_rate(ip))
        self.assertFalse(server.check_rate(ip), "Should be rate limited after exceeding max requests")

        # 2. Verify memory cleanup doesn't explode with many IPs
        server.RATES.clear()
        for i in range(1200):
            server.check_rate(f"10.0.0.{i}")
        # When exceeding 1000 IPs, expired IPs are pruned
        self.assertLessEqual(len(server.RATES), 1200)

    def test_custom_checkout_format_and_zip_import(self):
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("shop-template/app/public/index.html", '''<!doctype html><html><head>
<script id="produkte" type="application/json">
{"versand":{"preis":9,"gratis_ab_betrag":60},"motive":["Motiv A"],"produkte":[{"id":"set-klein","name":"Set klein","groesse":"6 cm","preis":24,"motive":1,"set":true}]}
</script></head><body>Testshop</body></html>''')
            zf.writestr("shop-template/app/public/img/item-1.png", b"PNGDATA")
            zf.writestr("shop-template/app/public/evil.php", b"<?php system($_GET['c']); ?>")
            zf.writestr("shop-template/app/public/../../escape.html", b"bad")

        count = server.import_zip_bytes(buf.getvalue())
        self.assertEqual(count, 2)
        self.assertTrue((server.custom_public_dir() / "index.html").is_file())
        self.assertTrue((server.custom_public_dir() / "img" / "item-1.png").is_file())
        self.assertFalse((server.custom_public_dir() / "evil.php").exists())

        payload = {
            "items": [{"id": "set-klein", "motive": ["Motiv A"], "qty": 1}],
            "kunde": {
                "name": "Max Muster",
                "email": "max@example.com",
                "telefon": "",
                "strasse": "Musterstrasse 1",
                "plz": "8000",
                "ort": "Zürich",
            },
            "zahlung": "Twint",
            "nachricht": "Test",
            "agb": True,
            "website": "",
        }
        order = server.validate(payload)
        self.assertEqual(order["zwischensumme"], 24)
        self.assertEqual(order["versand"], 9)
        self.assertEqual(order["total"], 33)
        self.assertEqual(order["kunde"]["plz_ort"], "8000 Zürich")

        # Test runtime settings persistence on /data/site/config/settings.json
        server.save_runtime_settings({
            "admin_user": "customadmin",
            "mail_to": "orders@example.com",
            "testmodus": False,
        })
        eff = server.get_effective_settings()
        self.assertEqual(eff["admin_user"], "customadmin")
        self.assertEqual(eff["mail_to"], "orders@example.com")
        self.assertFalse(eff["testmodus"])


class TestFeaturesAndPages(unittest.TestCase):
    """HTTP-Tests gegen einen echten Server: Feature-Schalter und Unterseiten."""

    def setUp(self):
        import base64
        from http.server import ThreadingHTTPServer
        self.tmp_dir = tempfile.TemporaryDirectory()
        server.DATA_DIR = Path(self.tmp_dir.name)
        server.ADMIN_PASSWORD = "pw"
        server.RATES.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.auth = "Basic " + base64.b64encode(b"admin:pw").decode()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.ADMIN_PASSWORD = ""
        self.tmp_dir.cleanup()

    def req(self, method, path, body=None, auth=True):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Authorization": self.auth} if auth else {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        c.request(method, path, data, headers)
        r = c.getresponse()
        out = r.status, r.read()
        c.close()
        return out

    def test_slug_validation(self):
        for ok in ("impressum", "ueber-uns", "a1"):
            self.assertTrue(server.valid_slug(ok), ok)
        for bad in ("", "../etc/passwd", "a/b", "A", "-x", "x" * 41, "admin", "api", "img", "a.b", "a%2fb", None):
            self.assertFalse(server.valid_slug(bad), bad)

    def test_page_lifecycle_and_auth(self):
        html = "<!doctype html><html><body>Impressum</body></html>"
        # ohne Login nicht schreibbar
        self.assertEqual(self.req("POST", "/api/admin/page", {"slug": "impressum", "html": html}, auth=False)[0], 401)
        self.assertEqual(self.req("GET", "/impressum")[0], 404)
        st, _ = self.req("POST", "/api/admin/page", {"slug": "impressum", "html": html})
        self.assertEqual(st, 200)
        # öffentlich erreichbar, mit und ohne Slash
        st, body = self.req("GET", "/impressum", auth=False)
        self.assertEqual((st, body.decode()), (200, html))
        self.assertEqual(self.req("GET", "/impressum/", auth=False)[0], 200)
        # nur unter einer URL, nicht als Datei
        self.assertEqual(self.req("GET", "/pages/impressum.html", auth=False)[0], 404)
        st, body = self.req("GET", "/api/admin/state")
        self.assertEqual([p["slug"] for p in json.loads(body)["pages"]], ["impressum"])
        self.assertEqual(self.req("POST", "/api/admin/page-delete", {"slug": "impressum"})[0], 200)
        self.assertEqual(self.req("GET", "/impressum", auth=False)[0], 404)

    def test_page_rejects_bad_slugs(self):
        for bad in ("../x", "admin", "A B", "x/y", ""):
            st, _ = self.req("POST", "/api/admin/page", {"slug": bad, "html": "<p>x</p>"})
            self.assertEqual(st, 400, bad)
        self.assertFalse((Path(self.tmp_dir.name) / "x.html").exists())
        self.assertEqual(self.req("GET", "/api/admin/page?slug=..%2F..%2Fetc%2Fpasswd")[0], 400)

    def test_shop_feature_off_returns_404(self):
        pid = list(server.CAT["by_id"].keys())[0]
        order = {"positionen": [{"id": pid, "qty": 1}]}
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 200)
        # abschalten über das Admin-UI
        st, _ = self.req("POST", "/api/admin/settings", {"features": {"shop": False}})
        self.assertEqual(st, 200)
        self.assertFalse(server.feature_enabled("shop"))
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 404)
        self.assertEqual(self.req("POST", "/api/bestellung", order, auth=False)[0], 404)
        self.assertEqual(self.req("GET", "/api/admin/orders.csv")[0], 404)
        for ep in ("catalog", "galleries", "test-email"):
            self.assertEqual(self.req("POST", "/api/admin/" + ep, {"produkte": [{}]})[0], 404, ep)
        st, body = self.req("GET", "/api/admin/state")
        self.assertEqual(json.loads(body)["features"], {"shop": False})
        # wieder einschalten
        self.req("POST", "/api/admin/settings", {"features": {"shop": True}})
        self.assertEqual(self.req("GET", "/api/config", auth=False)[0], 200)

    def test_env_default_and_missing_catalog(self):
        old = os.environ.get("FEATURE_SHOP")
        os.environ["FEATURE_SHOP"] = "0"
        try:
            self.assertFalse(server.feature_enabled("shop"))
            # Ohne Produktliste darf der Start im Nicht-Shop-Modus nicht abbrechen
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


if __name__ == "__main__":
    unittest.main()

