"""Synthetic geo: IPv4-mapped addresses, range edges, and great-circle distance."""

import ipaddress
import math
import unittest

from watchpost import geo


class GeoBlitzTests(unittest.TestCase):
    def test_ipv4_mapped_addresses_follow_the_embedded_ipv4(self):
        pairs = (
            ("::ffff:192.0.2.1", "192.0.2.1"),
            ("::ffff:c000:201", "192.0.2.1"),
            ("::FFFF:C000:201", "192.0.2.1"),
            ("0:0:0:0:0:ffff:a00:1", "10.0.0.1"),
            ("::ffff:10.0.0.1%eth0", "10.0.0.1"),
            ("::ffff:172.31.255.255", "172.31.255.255"),
            ("::ffff:192.168.255.255", "192.168.255.255"),
            ("::ffff:203.0.113.200", "203.0.113.200"),
        )
        for mapped, plain in pairs:
            with self.subTest(mapped=mapped):
                self.assertEqual(geo.locate(mapped), geo.locate(plain))
                self.assertEqual(geo.is_internal(mapped), geo.is_internal(plain))
        packed = ipaddress.ip_address("::ffff:10.0.0.1").packed
        self.assertEqual(geo.locate(packed), geo.locate("10.0.0.1"))
        self.assertTrue(geo.is_internal(packed))
        # Similar spellings are different addresses and stay unknown.
        for other in ("::ffff:0:10.0.0.1", "64:ff9b::10.0.0.1", "2002:a00:1::", "::ffff:8.8.8.8"):
            with self.subTest(other=other):
                self.assertIsNone(geo.locate(other))
                self.assertFalse(geo.is_internal(other))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(geo.locate("  192.0.2.1\n"), geo.locate("192.0.2.1"))
        self.assertTrue(geo.is_internal("\t10.0.0.1  "))
        self.assertEqual(geo.locate(" ::ffff:172.16.0.1\n"), geo.locate("172.16.0.1"))
        self.assertIsNone(geo.locate("   "))
        self.assertFalse(geo.is_internal("   "))

    def test_unknown_input_is_not_a_location(self):
        # 0 is the address 0.0.0.0, which is outside the table. Leading zeros are rejected
        # by ipaddress, same as the rest of ingest, so they are not guessed.
        for ip in ("8.8.8.8", "2001:db8::1", "::1", "127.0.0.1", "169.254.1.1", "fc00::1",
                   "192.0.2.01", "192.0.2.1/32", "192.0.2.1:80", None, "", "not-an-ip",
                   True, False, 0, -1, 1.5, ["10.0.0.1"], b""):
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))
                self.assertFalse(geo.is_internal(ip))

    def test_integer_and_packed_bytes_match_the_same_city(self):
        self.assertEqual(geo.locate(3221225985)["city"], "Northhaven")  # 192.0.2.1
        self.assertEqual(geo.locate(b"\xc0\x00\x02\x01")["city"], "Northhaven")
        self.assertFalse(geo.is_internal(b"\xc0\x00\x02\x01"))
        self.assertTrue(geo.is_internal(167772161))  # 10.0.0.1
        self.assertEqual(geo.locate("192.0.2.1"), geo.locate(ipaddress.ip_address("192.0.2.1")))

    def test_range_edges(self):
        edges = (
            ("192.0.2.0", "Northhaven", False),
            ("192.0.2.127", "Northhaven", False),
            ("192.0.2.128", "Saltmere", False),
            ("192.0.2.255", "Saltmere", False),
            ("198.51.100.0", "Kestrel Bay", False),
            ("198.51.100.127", "Kestrel Bay", False),
            ("198.51.100.128", "Duskport", False),
            ("198.51.100.255", "Duskport", False),
            ("203.0.113.0", "Ironvale", False),
            ("203.0.113.127", "Ironvale", False),
            ("203.0.113.128", "Emberfield", False),
            ("203.0.113.255", "Emberfield", False),
            ("10.0.0.0", "Riverton HQ", True),
            ("10.255.255.255", "Riverton HQ", True),
            ("172.16.0.0", "Lakeside branch", True),
            ("172.31.255.255", "Lakeside branch", True),
            ("192.168.0.0", "Hillcrest remote site", True),
            ("192.168.255.255", "Hillcrest remote site", True),
        )
        for ip, city, internal in edges:
            with self.subTest(ip=ip):
                loc = geo.locate(ip)
                self.assertEqual(loc["city"], city)
                self.assertTrue(loc["synthetic"])
                self.assertEqual(set(loc), {"city", "lat", "lon", "synthetic"})
                self.assertTrue(-90 <= loc["lat"] <= 90 and -180 <= loc["lon"] <= 180)
                self.assertEqual(loc, geo.locate(ip))
                self.assertEqual(geo.is_internal(ip), internal)
        for ip in ("192.0.1.255", "192.0.3.0", "198.51.99.255", "198.51.101.0",
                   "203.0.112.255", "203.0.114.0", "9.255.255.255", "11.0.0.0",
                   "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0"):
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))
                self.assertFalse(geo.is_internal(ip))
                self.assertIsNone(geo.locate("::ffff:" + ip))
                self.assertFalse(geo.is_internal("::ffff:" + ip))

    def test_distance(self):
        hq = geo.locate("10.0.0.1")
        far = geo.locate("203.0.113.150")
        lakeside = geo.locate("172.16.4.1")
        self.assertEqual(geo.distance_km(hq, hq), 0)
        self.assertEqual(geo.distance_km(hq, geo.locate("10.255.255.255")), 0)
        self.assertEqual(geo.distance_km(geo.locate("::ffff:10.0.0.1"), geo.locate("::ffff:10.9.9.9")), 0)
        chi_lagos = geo.distance_km(hq, far)
        self.assertGreater(chi_lagos, 8000)
        self.assertEqual(chi_lagos, geo.distance_km(far, hq))
        self.assertEqual(chi_lagos, geo.distance_km(geo.locate("::ffff:10.0.0.1"), geo.locate("::ffff:203.0.113.150")))
        sea_chi = geo.distance_km(lakeside, hq)
        self.assertGreater(sea_chi, 2700)
        self.assertLess(sea_chi, 2900)
        cap = math.pi * 6371.0
        cities = []
        seen = set()
        for ip in ("192.0.2.1", "192.0.2.200", "198.51.100.1", "198.51.100.200",
                   "203.0.113.1", "203.0.113.200", "10.0.0.1", "172.16.0.1", "192.168.0.1"):
            loc = geo.locate(ip)
            key = (loc["city"], loc["lat"], loc["lon"])
            if key not in seen:
                seen.add(key)
                cities.append(loc)
        self.assertEqual(len(cities), 9)
        for i, a in enumerate(cities):
            for b in cities[i:]:
                km = geo.distance_km(a, b)
                self.assertGreaterEqual(km, 0)
                self.assertLessEqual(km, cap + 1e-6)
                self.assertEqual(km, geo.distance_km(b, a))
                if a["city"] != b["city"]:
                    self.assertGreater(km, 500)
        # 180 and -180 are the same meridian. Opposite longitudes are half a sphere, not an error.
        self.assertLess(geo.distance_km({"lat": 10, "lon": 180}, {"lat": 10, "lon": -180}), 0.001)
        self.assertAlmostEqual(
            geo.distance_km({"lat": 0, "lon": 0}, {"lat": 0, "lon": 180}), cap, places=6)
