"""The README heroes are the shots taken after the ATT&CK evidence legend.

A 1440x900 dashboard crop ends above that legend. The dashboard file is taller
so validated, mapped, disabled, and gap sit inside the JPEG.
"""

import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

DASHBOARD = "docs/screenshots/01-dashboard-1117.jpg"
INCIDENTS = "docs/screenshots/02-incidents-1117.jpg"
ALERTS = "docs/screenshots/03-alerts-1117.jpg"


def jpeg_size(data):
    """Return (width, height) from the first SOF marker, or (None, None)."""
    if not data.startswith(b"\xff\xd8"):
        return None, None
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xC0, 0xC1, 0xC2):
            height, width = struct.unpack(">HH", data[i + 5 : i + 9])
            return width, height
        if marker in (0xD8, 0xD9):
            i += 2
            continue
        if i + 4 > len(data):
            break
        i += 2 + struct.unpack(">H", data[i + 2 : i + 4])[0]
    return None, None


class ReadmeShotTests(unittest.TestCase):
    def test_heroes_name_the_legend_and_include_it(self):
        readme = (ROOT / "README.md").read_text()
        reference = (ROOT / "docs" / "REFERENCE.md").read_text()
        self.assertIn(
            "ATT&CK legend: validated, mapped, disabled, and gap",
            readme,
        )
        self.assertIn(DASHBOARD, readme)
        self.assertIn(INCIDENTS, readme)
        self.assertIn(ALERTS, readme)
        self.assertIn("screenshots/01-dashboard-1117.jpg", reference)
        self.assertIn("screenshots/02-incidents-1117.jpg", reference)
        self.assertIn("screenshots/03-alerts-1117.jpg", reference)
        self.assertNotIn("screenshots/01-dashboard.png", reference)

        shots = {
            DASHBOARD: "dashboard",
            INCIDENTS: "incidents",
            ALERTS: "alerts",
        }
        for rel, name in shots.items():
            data = (ROOT / rel).read_bytes()
            self.assertTrue(data.startswith(b"\xff\xd8\xff"), name)
            self.assertGreater(len(data), 50_000, name)
            width, height = jpeg_size(data)
            self.assertEqual(width, 1440, name)
            if name == "dashboard":
                # 900px clips the legend (it starts near y=892 and is 13px tall).
                self.assertGreaterEqual(height, 920, name)
            else:
                self.assertEqual(height, 900, name)
