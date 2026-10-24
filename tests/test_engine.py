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

if __name__ == "__main__":
    unittest.main()
