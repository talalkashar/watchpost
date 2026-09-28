import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")  # fast hashing for tests only

from watchpost.config import Config  # noqa: E402
from watchpost.server import make_server  # noqa: E402

ADMIN_PW = "admin-test-password-1"
ANALYST_PW = "analyst-test-password-1"
VIEWER_PW = "viewer-test-password-1"


class Client:
    def __init__(self, base):
        self.base = base
        self.csrf = None
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def request(self, method, path, body=None, headers=None, raw=None, csrf=True):
        headers = dict(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        if method == "POST" and csrf and self.csrf:
            headers.setdefault("X-CSRF-Token", self.csrf)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read() or b"null"), resp.headers
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"null"), exc.headers

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body if body is not None or "raw" in kw else {}, **kw)

    def login(self, username, password):
        status, data, _ = self.post("/api/auth/login", {"username": username, "password": password})
        if status == 200:
            self.csrf = data["csrf_token"]
        return status, data


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.config = Config.from_env(db_path=self.db_path, host="127.0.0.1", port=0,
                                      admin_password=ADMIN_PW, analyst_password=ANALYST_PW,
                                      viewer_password=VIEWER_PW, **self.config_overrides())
        self.server, self.app = make_server(self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def config_overrides(self):
        """Subclasses may change Config fields (e.g. rate limits) before the server starts."""
        return {}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def client(self, user=None):
        client = Client(self.base)
        if user == "admin":
            self.assertEqual(client.login("admin", ADMIN_PW)[0], 200)
        elif user == "analyst":
            self.assertEqual(client.login("analyst", ANALYST_PW)[0], 200)
        elif user == "viewer":
            self.assertEqual(client.login("viewer", VIEWER_PW)[0], 200)
        return client
