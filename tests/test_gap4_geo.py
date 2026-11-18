"""Edges of watchpost.geo that the other suites leave open.

locate: both ends of every mapped prefix, and the address just outside it.
is_internal: RFC 1918 ends, the next address out, and lookalikes that are not RFC 1918.
distance_km: argument order, two hosts in one city, and the short arc across ±180.
"""

import ipaddress
import unittest

from watchpost import geo


# Inclusive ends. The /25 cut is .127 | .128. RFC 1918 includes network and broadcast.
_PREFIX_ENDS = {
    "192.0.2.0": "Northhaven",
    "192.0.2.127": "Northhaven",
    "192.0.2.128": "Saltmere",
    "192.0.2.255": "Saltmere",
    "198.51.100.0": "Kestrel Bay",
    "198.51.100.127": "Kestrel Bay",
    "198.51.100.128": "Duskport",
    "198.51.100.255": "Duskport",
    "203.0.113.0": "Ironvale",
    "203.0.113.127": "Ironvale",
    "203.0.113.128": "Emberfield",
    "203.0.113.255": "Emberfield",
    "10.0.0.0": "Riverton HQ",
    "10.255.255.255": "Riverton HQ",
    "172.16.0.0": "Lakeside branch",
    "172.31.255.255": "Lakeside branch",
    "192.168.0.0": "Hillcrest remote site",
    "192.168.255.255": "Hillcrest remote site",
}

# One address outside each block. 192.0.2.0/24 is fully split into two /25s, so the
# neighbors are the addresses on either side of that /24 (and the same for the other docs).
_JUST_OUTSIDE = (
    "192.0.1.255",
    "192.0.3.0",
    "198.51.99.255",
    "198.51.101.0",
    "203.0.112.255",
    "203.0.114.0",
    "9.255.255.255",
    "11.0.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.167.255.255",
    "192.169.0.0",
)

_MALFORMED = (
    " 192.0.2.1",
    "192.0.2.1 ",
    "192.0.2.1\n",
    "   ",
    "192.0.2.01",
    "192.0.2.1/32",
    "192.0.2",
    "192.0.2.256",
    "::ffff:192.0.2.1",
    "::ffff:10.0.0.1",
)

# Not RFC 1918, even when they feel "local".
_NOT_INTERNAL = _JUST_OUTSIDE + (
    "127.0.0.1",
    "169.254.1.1",
    "0.0.0.0",
    "255.255.255.255",
    "::1",
    "fc00::1",
    "fd12:3456::1",
    "",
    None,
    "not-an-ip",
) + _MALFORMED


class LocateTests(unittest.TestCase):
    def test_prefix_ends_keep_their_city(self):
        for ip, city in _PREFIX_ENDS.items():
            with self.subTest(ip=ip):
                loc = geo.locate(ip)
                self.assertEqual(loc["city"], city)
                self.assertTrue(loc["synthetic"])
                self.assertEqual(set(loc), {"city", "lat", "lon", "synthetic"})

    def test_address_just_outside_a_prefix_is_unknown(self):
        for ip in _JUST_OUTSIDE:
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))

    def test_malformed_and_mapped_v6_are_unknown(self):
        for ip in _MALFORMED:
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))

    def test_integer_form_matches_the_same_address(self):
        inside = int(ipaddress.ip_address("10.255.255.255"))
        outside = int(ipaddress.ip_address("11.0.0.0"))
        self.assertEqual(geo.locate(inside)["city"], "Riverton HQ")
        self.assertIsNone(geo.locate(outside))
        self.assertIsNone(geo.locate(0))


class IsInternalTests(unittest.TestCase):
    def test_rfc1918_ends_are_internal(self):
        for ip in ("10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
                   "192.168.0.0", "192.168.255.255"):
            with self.subTest(ip=ip):
                self.assertTrue(geo.is_internal(ip))

    def test_documentation_ends_are_not_internal(self):
        for ip in ("192.0.2.0", "192.0.2.255", "198.51.100.0", "198.51.100.255",
                   "203.0.113.0", "203.0.113.255"):
            with self.subTest(ip=ip):
                self.assertFalse(geo.is_internal(ip))
                self.assertIsNotNone(geo.locate(ip))

    def test_neighbors_lookalikes_and_malformed_are_not_internal(self):
        for ip in _NOT_INTERNAL:
            with self.subTest(ip=ip):
                self.assertFalse(geo.is_internal(ip))

    def test_integer_form_follows_rfc1918(self):
        self.assertTrue(geo.is_internal(int(ipaddress.ip_address("172.31.255.255"))))
        self.assertFalse(geo.is_internal(int(ipaddress.ip_address("172.32.0.0"))))
        self.assertFalse(geo.is_internal(0))


class DistanceTests(unittest.TestCase):
    def test_argument_order_does_not_change_the_result(self):
        north = geo.locate("192.0.2.0")
        south = geo.locate("192.0.2.255")
        self.assertEqual(geo.distance_km(north, south), geo.distance_km(south, north))
        self.assertGreater(geo.distance_km(north, south), 15000)

    def test_two_hosts_in_one_city_are_zero_apart(self):
        self.assertEqual(
            geo.distance_km(geo.locate("10.0.0.0"), geo.locate("10.255.255.255")), 0)
        self.assertEqual(
            geo.distance_km(geo.locate("172.16.0.0"), geo.locate("172.31.255.255")), 0)
        self.assertEqual(
            geo.distance_km(geo.locate("203.0.113.128"), geo.locate("203.0.113.255")), 0)

    def test_closer_pair_is_shorter(self):
        hq = geo.locate("10.0.0.0")
        hill = geo.locate("192.168.255.255")
        lake = geo.locate("172.31.255.255")
        far = geo.distance_km(geo.locate("192.0.2.127"), geo.locate("192.0.2.128"))
        self.assertLess(geo.distance_km(hq, hill), geo.distance_km(hq, lake))
        self.assertLess(geo.distance_km(hq, lake), far)

    def test_date_line_uses_the_short_arc(self):
        km = geo.distance_km({"lat": 0.0, "lon": 179.0}, {"lat": 0.0, "lon": -179.0})
        self.assertGreater(km, 200)
        self.assertLess(km, 300)
        same = geo.distance_km({"lat": 0.0, "lon": 180.0}, {"lat": 0.0, "lon": -180.0})
        self.assertLess(abs(same), 1e-6)

    def test_antipodes_stay_on_the_half_circumference(self):
        km = geo.distance_km({"lat": 0.0, "lon": 0.0}, {"lat": 0.0, "lon": 180.0})
        self.assertGreater(km, 20000)
        self.assertLess(km, 20020)

    def test_empty_point_is_rejected(self):
        with self.assertRaises(KeyError):
            geo.distance_km({}, {"lat": 0.0, "lon": 0.0})
        with self.assertRaises(TypeError):
            geo.distance_km(None, {"lat": 0.0, "lon": 0.0})


if __name__ == "__main__":
    unittest.main()
