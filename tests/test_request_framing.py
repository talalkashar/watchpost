"""A POST with Transfer-Encoding, or with no Content-Length, is 400 and the connection closes.

The body is not an empty payload, and the leftover bytes are not the next request.
"""

import json
import socket
from pathlib import Path

from tests.helpers import ADMIN_PW, ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def exchange(port, payload):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    try:
        sock.sendall(payload)
        chunks = []
        while True:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def status_lines(raw):
    return [line for line in raw.split(b"\r\n") if line.startswith(b"HTTP/")]


def header_map(raw):
    head = raw.split(b"\r\n\r\n", 1)[0].decode()
    headers = {}
    for line in head.split("\r\n")[1:]:
        key, _, value = line.partition(":")
        headers[key.lower()] = value.strip()
    return headers


class RequestFramingTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.port = self.server.server_address[1]
        self.login = json.dumps({"username": "admin", "password": ADMIN_PW}).encode()

    def test_missing_content_length_is_400_and_drops_the_next_request(self):
        raw = exchange(self.port, (
            b"POST /api/auth/login HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n" + self.login +
            b"GET /api/health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        ))
        self.assertEqual(status_lines(raw), [b"HTTP/1.0 400 Bad Request"])
        self.assertEqual(json.loads(raw.split(b"\r\n\r\n", 1)[1]),
                         {"error": "Content-Length is required"})
        headers = header_map(raw)
        self.assertEqual(headers["connection"], "close")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn(b"csrf_token", raw)
        self.assertNotIn(b"200 OK", raw)

    def test_transfer_encoding_is_400_even_with_content_length(self):
        raw = exchange(self.port, (
            b"POST /api/auth/login HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(self.login)).encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n" + self.login +
            b"GET /api/health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"\r\n"
        ))
        self.assertEqual(status_lines(raw), [b"HTTP/1.0 400 Bad Request"])
        self.assertEqual(json.loads(raw.split(b"\r\n\r\n", 1)[1]),
                         {"error": "Transfer-Encoding is not supported"})
        self.assertEqual(header_map(raw)["connection"], "close")
        self.assertNotIn(b"csrf_token", raw)
        self.assertNotIn(b"200 OK", raw)

    def test_transfer_encoding_without_content_length_names_transfer_encoding(self):
        raw = exchange(self.port, (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"transfer-encoding: identity\r\n"
            b"\r\n"
            b"GET /api/health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"\r\n"
        ))
        self.assertEqual(status_lines(raw), [b"HTTP/1.0 400 Bad Request"])
        self.assertIn(b"Transfer-Encoding is not supported", raw)
        self.assertNotIn(b"method not allowed", raw)

    def test_content_length_still_frames_the_body(self):
        raw = exchange(self.port, (
            b"POST /api/auth/login HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(self.login)).encode() + b"\r\n"
            b"\r\n" + self.login
        ))
        self.assertEqual(status_lines(raw), [b"HTTP/1.0 200 OK"])
        self.assertIn(b"csrf_token", raw)

        empty = exchange(self.port, (
            b"POST /api/auth/login HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        ))
        self.assertEqual(status_lines(empty), [b"HTTP/1.0 401 Unauthorized"])
        body = json.loads(empty.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(body["error"], "invalid username or password")

    def test_api_docs_name_the_refusal(self):
        text = API.read_text()
        self.assertIn("Transfer-Encoding is not supported", text)
        self.assertIn("Content-Length is required", text)
        self.assertIn("the connection closes", text)
