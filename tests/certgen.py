"""Throwaway X.509 certificates for the TLS syslog tests, standard library only.

The standard library can verify certificates but cannot create them, and this project keeps
both its dependencies and its repository free of key files. So the tests build what they need
here: RSA keys from a small prime search, DER written by hand, PKCS#1 v1.5 SHA-256 signatures.

TEST USE ONLY. Every key is generated for one test run and never leaves it. Certificates for a
real listener are made with openssl; see docs/LIVE_INGEST.md.
"""

import base64
import hashlib
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")  # RFC 8017 section 9.2
_RSA_ENCRYPTION, _SHA256_WITH_RSA, _COMMON_NAME = "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11", "2.5.4.3"
_SUBJECT_KEY_ID, _KEY_USAGE, _ALT_NAME = "2.5.29.14", "2.5.29.15", "2.5.29.17"
_BASIC_CONSTRAINTS, _AUTHORITY_KEY_ID = "2.5.29.19", "2.5.29.35"


# --- DER -----------------------------------------------------------------------------

def _der(tag, *parts):
    body = b"".join(parts)
    if len(body) < 128:
        length = bytes([len(body)])
    else:
        size = (len(body).bit_length() + 7) // 8
        length = bytes([0x80 | size]) + len(body).to_bytes(size, "big")
    return bytes([tag]) + length + body


def _seq(*parts):
    return _der(0x30, *parts)


def _int(value):
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))  # the extra bit keeps it positive


def _oid(dotted):
    first, second, *rest = (int(part) for part in dotted.split("."))
    body = bytes([first * 40 + second])
    for arc in rest:
        chunk = [arc & 0x7F]
        while arc := arc >> 7:
            chunk.append(0x80 | (arc & 0x7F))
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _bits(data):
    return _der(0x03, b"\x00" + data)


def _name(common_name):
    return _seq(_der(0x31, _seq(_oid(_COMMON_NAME), _der(0x0C, common_name.encode()))))


def _time(moment):
    return _der(0x17, moment.astimezone(timezone.utc).strftime("%y%m%d%H%M%SZ").encode())  # UTCTime: until 2049


def _extension(oid, value, critical=False):
    return _seq(_oid(oid), *([_der(0x01, b"\xff")] if critical else []), _der(0x04, value))


def _alt_name(name):
    try:
        return _der(0x87, ipaddress.ip_address(name).packed)  # iPAddress
    except ValueError:
        return _der(0x82, name.encode())                      # dNSName


def _pem(label, der):
    text = base64.b64encode(der).decode()
    lines = "\n".join(text[i:i + 64] for i in range(0, len(text), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


# --- RSA -----------------------------------------------------------------------------

def _is_prime(n):
    if any(n % p == 0 for p in _SMALL_PRIMES):
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(8):  # Miller-Rabin rounds
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1  # top two bits set: p * q is full size
        if _is_prime(candidate):
            return candidate


class Key:
    """An RSA key pair. 2048 bits is the smallest size OpenSSL accepts at its default security level."""

    def __init__(self, bits=2048):
        self.e = 65537
        while True:
            self.p, self.q = _prime(bits // 2), _prime(bits // 2)
            if self.p != self.q and (self.p - 1) % self.e and (self.q - 1) % self.e:
                break
        self.n = self.p * self.q
        self.d = pow(self.e, -1, (self.p - 1) * (self.q - 1))
        public = _seq(_int(self.n), _int(self.e))
        self.public_info = _seq(_seq(_oid(_RSA_ENCRYPTION), _der(0x05)), _bits(public))
        self.key_id = hashlib.sha256(public).digest()[:20]

    def pem(self):
        """The private key as an unencrypted PKCS#1 `RSA PRIVATE KEY` block."""
        numbers = (0, self.n, self.e, self.d, self.p, self.q,
                   self.d % (self.p - 1), self.d % (self.q - 1), pow(self.q, -1, self.p))
        return _pem("RSA PRIVATE KEY", _seq(*map(_int, numbers)))

    def sign(self, data):
        size = (self.n.bit_length() + 7) // 8
        digest = _SHA256_DIGEST_INFO + hashlib.sha256(data).digest()
        padded = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
        return pow(int.from_bytes(padded, "big"), self.d, self.n).to_bytes(size, "big")


# --- certificates --------------------------------------------------------------------

def certificate(subject, key, issuer=None, issuer_key=None, ca=False, names=(), not_before=None, not_after=None):
    """A PEM certificate for `key`, signed by `issuer_key`; self-signed when no issuer is given.

    `names` are DNS names or IP addresses for subjectAltName. The default validity is one hour back
    to one day ahead, so nothing here outlives a test run by much.
    """
    signer = issuer_key or key
    now = datetime.now(timezone.utc)
    extensions = [_extension(_BASIC_CONSTRAINTS, _seq(_der(0x01, b"\xff")) if ca else _seq(), critical=True),
                  _extension(_SUBJECT_KEY_ID, _der(0x04, key.key_id)),
                  _extension(_AUTHORITY_KEY_ID, _seq(_der(0x80, signer.key_id)))]
    if ca:
        extensions.append(_extension(_KEY_USAGE, _der(0x03, b"\x01\x06"), critical=True))  # keyCertSign, cRLSign
    if names:
        extensions.append(_extension(_ALT_NAME, _seq(*map(_alt_name, names))))
    algorithm = _seq(_oid(_SHA256_WITH_RSA), _der(0x05))
    body = _seq(_der(0xA0, _int(2)),                 # version 3
                _int(secrets.randbits(63) + 1),      # serial number
                algorithm,
                _name(issuer or subject),
                _seq(_time(not_before or now - timedelta(hours=1)), _time(not_after or now + timedelta(days=1))),
                _name(subject),
                key.public_info,
                _der(0xA3, _seq(*extensions)))
    return _pem("CERTIFICATE", _seq(body, algorithm, _bits(signer.sign(body))))


def write(directory, name, *pems):
    """Write PEM blocks to `directory/name` (mode 0600) and return the path as a string."""
    path = Path(directory) / name
    path.touch(mode=0o600)
    path.write_text("".join(pems))
    return str(path)
