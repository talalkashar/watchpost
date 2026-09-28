"""A tiny PDF reader for tests: follows the xref table and pulls text out of page content streams.

Only understands what watchpost.pdfwriter emits (uncompressed streams, literal strings with Tj).
"""

import re


class ParsedPDF:
    def __init__(self, data):
        self.data = data
        if not data.startswith(b"%PDF-1.4"):
            raise ValueError("not a PDF 1.4 file")
        if not data.rstrip().endswith(b"%%EOF"):
            raise ValueError("missing %%EOF")
        start = int(re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", data).group(1))
        if not data[start:].startswith(b"xref"):
            raise ValueError("startxref does not point at the xref table")
        head = re.match(rb"xref\n0 (\d+)\n", data[start:])
        count = int(head.group(1))
        table = data[start + head.end():start + head.end() + 20 * count]
        self.offsets = {}
        for number in range(count):
            entry = table[number * 20:(number + 1) * 20]
            if len(entry) != 20 or entry[-2:] not in (b" \n", b"\r\n"):
                raise ValueError(f"xref entry {number} is not 20 bytes")
            if entry[17:18] == b"n":
                self.offsets[number] = int(entry[:10])
        self.trailer = data[start + head.end() + 20 * count:]

    def obj(self, number):
        offset = self.offsets[number]
        match = re.match(rb"(\d+) 0 obj\n", self.data[offset:])
        if not match or int(match.group(1)) != number:
            raise ValueError(f"xref offset for object {number} is wrong")
        end = self.data.index(b"\nendobj", offset)
        return self.data[offset + match.end():end]

    def ref(self, body, key):
        return int(re.search(rb"/" + key + rb" (\d+) 0 R", body).group(1))

    def pages(self):
        root = self.ref(self.trailer, b"Root")
        pages = self.obj(self.ref(self.obj(root), b"Pages"))
        kids = [int(k) for k in re.findall(rb"(\d+) 0 R", re.search(rb"/Kids \[(.*?)\]", pages).group(1))]
        count = int(re.search(rb"/Count (\d+)", pages).group(1))
        if count != len(kids):
            raise ValueError("/Count does not match /Kids")
        return kids

    def page_text(self, page):
        body = self.obj(self.ref(self.obj(page), b"Contents"))
        length = int(re.search(rb"/Length (\d+)", body).group(1))
        stream = body[body.index(b"stream\n") + 7:]
        if not stream[length:].startswith(b"\nendstream"):
            raise ValueError("stream /Length is wrong")
        return [_unescape(s) for s in re.findall(rb"\(((?:\\.|[^\\)])*)\) Tj", stream[:length])]

    def text(self):
        return "\n".join(line for page in self.pages() for line in self.page_text(page))


def _unescape(raw):
    out, i = [], 0
    while i < len(raw):
        c = raw[i:i + 1]
        if c == b"\\":
            nxt = raw[i + 1:i + 4]
            if nxt[:1].isdigit():
                out.append(int(nxt, 8))
                i += 4
                continue
            out.append(raw[i + 1])
            i += 2
            continue
        out.append(raw[i])
        i += 1
    return bytes(out).decode("latin-1")
