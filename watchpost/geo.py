"""Synthetic geo table for the attacker map. Not a geo lookup.

Only the RFC 5737 documentation ranges (which the synthetic data uses for
"external" attackers) and the RFC 1918 private ranges have entries. They map to
fictional place names pinned at fixed coordinates so the map has somewhere to
draw them. Every result is labeled synthetic. Any other address returns None and
the UI lists it as "unknown": real IPs are never guessed.
"""

import ipaddress

# (name, lat, lon). Names are invented; coordinates are spread across continents
# so no real country is singled out as a source.
_EXTERNAL = [
    ("Kestrel Bay", 47.6, -122.3), ("Brightwell", 40.7, -74.0), ("Highmere", 19.4, -99.1),
    ("Sable Ridge", -23.5, -46.6), ("Oskar Fjell", 64.1, -21.9), ("Mirelle", 48.9, 2.3),
    ("Nordhaven", 59.9, 10.7), ("Graywater", 55.7, 37.6), ("Duneholt", 30.0, 31.2),
    ("Port Ashvale", -33.9, 18.6), ("Solenne", -1.3, 36.8), ("Qadira", 25.2, 55.3),
    ("Lanterna", 28.6, 77.2), ("Tamsin Reach", 1.3, 103.8), ("Vesper Point", 35.7, 139.7),
    ("Coralind", -33.9, 151.2),
]

# Each documentation /24 gets its own slice of the list, so the three ranges look
# different on the map but any single address always lands in the same place.
_TABLE = [
    (ipaddress.ip_network("192.0.2.0/24"), [_EXTERNAL[i] for i in (0, 3, 6, 9, 12, 15)], False),
    (ipaddress.ip_network("198.51.100.0/24"), [_EXTERNAL[i] for i in (1, 4, 7, 10, 13)], False),
    (ipaddress.ip_network("203.0.113.0/24"), [_EXTERNAL[i] for i in (2, 5, 8, 11, 14)], False),
    (ipaddress.ip_network("10.0.0.0/8"), [("Watchpost HQ (internal)", 39.1, -94.6)], True),
    (ipaddress.ip_network("172.16.0.0/12"), [("Branch office (internal)", 41.9, -87.6)], True),
    (ipaddress.ip_network("192.168.0.0/16"), [("Remote site (internal)", 33.7, -84.4)], True),
]

LABEL = "synthetic geo"


def locate(ip):
    """Return {"city", "lat", "lon", "synthetic", "internal"} for table ranges, else None."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    for network, places, internal in _TABLE:
        if addr.version == network.version and addr in network:
            city, lat, lon = places[int(addr) % len(places)]
            return {"city": city, "lat": lat, "lon": lon, "synthetic": True, "internal": internal}
    return None
