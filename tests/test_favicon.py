import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit

STATIC = Path(__file__).resolve().parent.parent / "static"


class FaviconTests(unittest.TestCase):
    def test_every_icon_the_page_links_exists(self):
        html = (STATIC / "index.html").read_text()
        icons = re.findall(r'<link rel="(?:icon|apple-touch-icon)" href="/([^"]+)"', html)
        paths = [urlsplit(icon).path for icon in icons]
        self.assertIn("favicon.ico", paths)
        for name in paths:
            self.assertTrue((STATIC / name).is_file(), name)

    def test_favicon_ico_is_a_real_icon_file(self):
        data = (STATIC / "favicon.ico").read_bytes()
        self.assertEqual(data[:4], b"\x00\x00\x01\x00")  # ICO header, type 1 = icon


if __name__ == "__main__":
    unittest.main()
