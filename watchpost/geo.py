"""Synthetic geolocation for demo IP ranges. Not a real geo lookup.

Only the RFC 5737 documentation ranges and RFC 1918 private ranges are mapped, each to a
fictional city at a fixed position. Anything else returns None ("unknown"): real addresses
are never guessed.
"""

import ipaddress
import math

# (network, fictional city, lat, lon)
_TABLE = [
    ("192.0.2.0/25", "Northhaven", 59.33, 18.07),
    ("192.0.2.128/25", "Saltmere", -33.87, 151.21),
    ("198.51.100.0/25", "Kestrel Bay", 35.68, 139.69),
    ("198.51.100.128/25", "Duskport", -23.55, -46.63),
    ("203.0.113.0/25", "Ironvale", 55.75, 37.62),
    ("203.0.113.128/25", "Emberfield", 6.52, 3.38),
    ("10.0.0.0/8", "Riverton HQ", 41.88, -87.63),
    ("172.16.0.0/12", "Lakeside branch", 47.61, -122.33),
    ("192.168.0.0/16", "Hillcrest remote site", 40.71, -74.01),
]
TABLE = [(ipaddress.ip_network(net), city, lat, lon) for net, city, lat, lon in _TABLE]
LABEL = "synthetic geo"
# RFC 1918 only. ipaddress's is_private also covers the RFC 5737 ranges, so it cannot be used here.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def locate(ip):
    """Return {"city", "lat", "lon", "synthetic": True} for a mapped address, else None."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for network, city, lat, lon in TABLE:
        if addr.version == network.version and addr in network:
            return {"city": city, "lat": lat, "lon": lon, "synthetic": True}
    return None


def is_internal(ip):
    """True for RFC 1918 addresses; the dashboard map draws those sites as the HQ target."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _INTERNAL)


def distance_km(a, b):
    """Great-circle distance between two locate() results."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(min(1.0, h)))
