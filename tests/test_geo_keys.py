"""GET /api/geo collapses duplicate spellings to one compressed address.

2001:DB8::1 and 2001:db8::1 are one key. A repeated address counts once
toward the 200 cap. An invalid address stays 400. An unknown address stays
null. The synthetic table is unchanged: 192.0.2.1 is Northhaven and
203.0.113.1 is Ironvale.
"""

from pathlib import Path

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
INVALID = "ips must be a comma-separated list of IP addresses"
CAP = "at most 200 ips per request"
V6 = (
    "2001:DB8::1",
    "2001:db8::1",
    "2001:0db8:0000:0000:0000:0000:0000:0001",
)


class GeoKeyTests(ServerTestCase):
    def test_duplicate_spellings_are_one_compressed_key(self):
        status, data, _ = self.client("analyst").get("/api/geo?ips=" + ",".join(V6))
        self.assertEqual(status, 200)
        self.assertEqual(data["label"], "synthetic geo")
        self.assertEqual(list(data["ips"]), ["2001:db8::1"])
        self.assertIsNone(data["ips"]["2001:db8::1"])
        self.assertIn("2001:db8::1", API.read_text())
        self.assertIn("count once", API.read_text())

    def test_known_addresses_keep_the_synthetic_cities(self):
        status, data, _ = self.client("analyst").get(
            "/api/geo?ips=192.0.2.1,203.0.113.1,8.8.8.8")
        self.assertEqual(status, 200)
        self.assertEqual(data["ips"]["192.0.2.1"]["city"], "Northhaven")
        self.assertTrue(data["ips"]["192.0.2.1"]["synthetic"])
        self.assertFalse(data["ips"]["192.0.2.1"]["internal"])
        self.assertEqual(data["ips"]["203.0.113.1"]["city"], "Ironvale")
        self.assertIsNone(data["ips"]["8.8.8.8"])

    def test_a_repeated_address_counts_once_toward_the_cap(self):
        client = self.client("analyst")
        repeated = ",".join(["10.0.0.5"] * 201)
        status, data, _ = client.get("/api/geo?ips=" + repeated)
        self.assertEqual(status, 200)
        self.assertEqual(list(data["ips"]), ["10.0.0.5"])
        self.assertEqual(data["ips"]["10.0.0.5"]["city"], "Riverton HQ")
        self.assertTrue(data["ips"]["10.0.0.5"]["internal"])

        # 199 other addresses plus three spellings of one unknown address: 200 keys.
        others = [f"10.0.{i // 250}.{i % 250}" for i in range(1, 200)]
        mixed = ",".join(others + list(V6))
        status, data, _ = client.get("/api/geo?ips=" + mixed)
        self.assertEqual(status, 200)
        self.assertEqual(len(data["ips"]), 200)
        self.assertIsNone(data["ips"]["2001:db8::1"])
        self.assertNotIn("2001:DB8::1", data["ips"])

        extra = ",".join(f"10.1.{i // 250}.{i % 250}" for i in range(201))
        status, body, headers = client.get("/api/geo?ips=" + extra)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], CAP)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_an_invalid_address_stays_400(self):
        client = self.client("analyst")
        for ips in ("1.2.3.4,<script>", "not-an-ip", "192.0.2.01"):
            with self.subTest(ips=ips):
                status, body, headers = client.get("/api/geo?ips=" + ips)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], INVALID)
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(client.get("/api/geo?ips=")[1]["ips"], {})
