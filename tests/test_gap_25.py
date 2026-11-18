"""parse_allow turns a comma-separated allow list into IP networks.

Empty and None mean any peer. A bad token raises ValueError so the listener
can fail closed. Networks are parsed with strict=False, so host bits are masked.
"""

import ipaddress
import unittest

from watchpost.syslog_listener import parse_allow


class ParseAllowTests(unittest.TestCase):
    def test_empty_and_none_yield_no_networks(self):
        self.assertEqual(parse_allow(""), [])
        self.assertEqual(parse_allow(None), [])

    def test_cidr_and_host_yield_two_networks(self):
        nets = parse_allow("192.0.2.0/24, 127.0.0.1")
        self.assertEqual(
            nets,
            [
                ipaddress.ip_network("192.0.2.0/24", strict=False),
                ipaddress.ip_network("127.0.0.1", strict=False),
            ],
        )
        # Host bits are accepted and masked. strict=True would raise.
        self.assertEqual(
            parse_allow("192.0.2.1/24"),
            [ipaddress.ip_network("192.0.2.0/24", strict=False)],
        )

    def test_not_an_ip_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_allow("not-an-ip")


if __name__ == "__main__":
    unittest.main()
