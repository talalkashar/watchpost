"""Minimal PDF 1.4 writer: Helvetica text, word wrap, rules, simple tables, page breaks.

Standard library only. Content streams are left uncompressed so the output stays easy to inspect.
Text uses WinAnsiEncoding; characters outside Latin-1 are replaced with close ASCII equivalents or '?'.
"""

PAGE_W, PAGE_H = 612, 792  # US Letter, points
MARGIN = 54
FOOTER_Y = 30

# Helvetica advance widths (1/1000 em) for ASCII 32..126, from the standard AFM metrics.
_WIDTHS = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]
_REPLACE = {"—": "-", "–": "-", "…": "...", "→": "->", "←": "<-", "‘": "'",
            "’": "'", "“": '"', "”": '"', "•": "\xb7", "≥": ">=", "≤": "<="}


def clean(text):
    """Map text onto the characters Helvetica/WinAnsi can show."""
    out = []
    for ch in str(text):
        ch = _REPLACE.get(ch, ch)
        if len(ch) > 1:
            out.append(ch)
        elif ch in "\t\r\n" or ord(ch) < 32:
            out.append(" ")
        elif ord(ch) < 127 or 160 <= ord(ch) < 256:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def text_width(text, size, bold=False):
    units = sum(_WIDTHS[ord(c) - 32] if 32 <= ord(c) < 127 else 556 for c in clean(text))
    return units * size / 1000 * (1.07 if bold else 1.0)


def _pdf_string(text):
    out = []
    for ch in clean(text):
        if ch in "\\()":
            out.append("\\" + ch)
        elif ord(ch) > 126:
            out.append("\\%03o" % ord(ch))
        else:
            out.append(ch)
    return "(" + "".join(out) + ")"


def wrap(text, width, size, bold=False):
    """Greedy word wrap; words longer than the line are split by character."""
    lines = []
    for paragraph in str(text).split("\n"):
        paragraph = clean(paragraph)
        line = ""
        for word in paragraph.split(" "):
            candidate = f"{line} {word}" if line else word
            if text_width(candidate, size, bold) <= width:
                line = candidate
                continue
            if line:
                lines.append(line)
            while text_width(word, size, bold) > width:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
    return lines


def truncate(text, width, size, bold=False):
    text = clean(text)
    if text_width(text, size, bold) <= width:
        return text
    while text and text_width(text + "...", size, bold) > width:
        text = text[:-1]
    return text + "..."


class Document:
    """Build pages top to bottom; call to_bytes() at the end."""

    def __init__(self, title="", author="Watchpost", footer=""):
        self.title, self.author, self.footer = title, author, footer
        self.pages = []
        self.y = 0
        self.new_page()

    # --- layout primitives ------------------------------------------------------------

    @property
    def width(self):
        return PAGE_W - 2 * MARGIN

    def new_page(self):
        self.pages.append([])
        self.y = PAGE_H - MARGIN

    def ensure(self, height):
        """Start a new page unless `height` points still fit above the bottom margin."""
        if self.y - height < MARGIN:
            self.new_page()

    def _op(self, op):
        self.pages[-1].append(op)

    def _text_at(self, x, y, text, size, bold=False, color=None):
        font = "F2" if bold else "F1"
        rgb, reset = ("%.3f %.3f %.3f rg " % color, " 0 0 0 rg") if color else ("", "")
        self._op(f"BT {rgb}/{font} {size} Tf {x:.2f} {y:.2f} Td {_pdf_string(text)} Tj ET{reset}")

    def _rect(self, x, y, w, h, color):
        self._op("%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f 0 0 0 rg" % (*color, x, y, w, h))

    def space(self, points):
        self.y -= points
        if self.y < MARGIN:
            self.new_page()

    def text(self, text, size=10, bold=False, color=None, indent=0, leading=None):
        """Wrapped paragraph."""
        leading = leading or size * 1.3
        for line in wrap(text, self.width - indent, size, bold):
            self.ensure(leading)
            self.y -= leading
            self._text_at(MARGIN + indent, self.y + (leading - size) / 2, line, size, bold, color)

    def heading(self, text, size=14):
        self.ensure(size * 2.4)  # keep a heading with at least one line after it
        self.space(size * 0.5)
        self.text(text, size=size, bold=True)
        self.space(2)

    def rule(self, gray=0.7, thickness=0.75):
        self.ensure(6)
        self.y -= 3
        self._op(f"{gray:.2f} G {thickness} w {MARGIN} {self.y:.2f} m {PAGE_W - MARGIN} {self.y:.2f} l S 0 G")
        self.y -= 3

    def banner(self, text, fill=(0.98, 0.9, 0.6), size=10):
        lines = wrap(text, self.width - 12, size, True)
        height = len(lines) * size * 1.3 + 8
        self.ensure(height)
        self.y -= height
        self._rect(MARGIN, self.y, self.width, height, fill)
        for i, line in enumerate(lines):
            self._text_at(MARGIN + 6, self.y + height - 4 - (i + 1) * size * 1.3 + size * 0.3, line, size, True)

    def table(self, headers, rows, widths=None, size=8):
        """Rows are lists of cell strings; each cell is truncated to its column. Header repeats per page."""
        widths = widths or [1] * len(headers)
        scale = self.width / sum(widths)
        cols = [w * scale for w in widths]
        row_h = size * 1.6

        def draw_row(cells, bold, shade):
            self.ensure(row_h)
            self.y -= row_h
            if shade:
                self._rect(MARGIN, self.y, self.width, row_h, shade)
            x = MARGIN
            for cell, w in zip(cells, cols):
                self._text_at(x + 3, self.y + size * 0.45, truncate("" if cell is None else cell, w - 6, size, bold),
                              size, bold)
                x += w

        self.ensure(row_h * 2)
        draw_row(headers, True, (0.88, 0.9, 0.94))
        for i, row in enumerate(rows):
            if self.y - row_h < MARGIN:
                self.new_page()
                draw_row(headers, True, (0.88, 0.9, 0.94))
            draw_row(row, False, (0.97, 0.97, 0.97) if i % 2 else None)
        self.space(4)

    # --- serialization ----------------------------------------------------------------

    def to_bytes(self):
        total = len(self.pages)
        streams = []
        for number, ops in enumerate(self.pages, 1):
            ops = list(ops)
            label = f"Page {number} of {total}"
            ops.append(f"0.4 0.4 0.4 rg BT /F1 8 Tf {MARGIN} {FOOTER_Y} Td {_pdf_string(self.footer)} Tj ET")
            ops.append(f"BT /F1 8 Tf {PAGE_W - MARGIN - text_width(label, 8):.2f} {FOOTER_Y} Td "
                       f"{_pdf_string(label)} Tj ET 0 0 0 rg")
            streams.append("\n".join(ops).encode("latin-1"))

        # Object numbers: 1 catalog, 2 pages, 3-4 fonts, 5 info, then (page, content) pairs.
        objects = {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
            5: ("<< /Title %s /Author %s /Producer (Watchpost pdfwriter) >>"
                % (_pdf_string(self.title), _pdf_string(self.author))).encode("latin-1"),
        }
        kids = []
        for i, stream in enumerate(streams):
            page_id, content_id = 6 + 2 * i, 7 + 2 * i
            kids.append(f"{page_id} 0 R")
            objects[page_id] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                                f"/Contents {content_id} 0 R >>").encode()
            objects[content_id] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {total} >>".encode()

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = {}
        for obj_id in sorted(objects):
            offsets[obj_id] = len(out)
            out += b"%d 0 obj\n" % obj_id + objects[obj_id] + b"\nendobj\n"
        xref_at = len(out)
        size = max(objects) + 1
        out += b"xref\n0 %d\n0000000000 65535 f \n" % size
        for obj_id in range(1, size):
            out += b"%010d 00000 n \n" % offsets[obj_id]
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, xref_at)
        return bytes(out)
