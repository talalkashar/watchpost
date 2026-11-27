"""Edge cases in watchpost.pdfwriter that the original suite did not hit."""

import re
import unittest

from tests.pdfparse import ParsedPDF
from watchpost.pdfwriter import (
    MARGIN, PAGE_W, Document, clean, text_width, truncate, wrap,
)


def _baselines(doc):
    found = []
    for page in doc.pages:
        for op in page:
            found += [float(y) for _x, y in re.findall(r"(-?[\d.]+) (-?[\d.]+) Td", op)]
            found += [float(y) for _x, y, _w, _h in re.findall(
                r"(-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) re", op)]
    return found


class PdfWriterBlitzTests(unittest.TestCase):
    def test_basic_document_round_trip(self):
        doc = Document(title="Test (1)", author="Analyst", footer="footer")
        doc.heading("Incident")
        doc.text("paren ( ) and café")
        doc.rule()
        doc.banner("SYNTHETIC")
        doc.table(["A", "B"], [["1", "ok"], [None, "two"]], widths=[1, 2])
        data = doc.to_bytes()
        pdf = ParsedPDF(data)
        self.assertEqual(len(pdf.pages()), 1)
        text = pdf.text()
        self.assertIn("Incident", text)
        self.assertIn("paren ( ) and café", text)
        self.assertIn("SYNTHETIC", text)
        self.assertIn("footer", text)
        self.assertIn("Page 1 of 1", text)
        self.assertIn("two", text)
        self.assertIn(b"/Title (Test \\(1\\))", data)
        for number in pdf.offsets:
            pdf.obj(number)
        self.assertTrue(all(y >= MARGIN for y in _baselines(doc)))

    def test_heading_stays_on_the_page_when_there_is_room(self):
        doc = Document()
        doc.text("intro")
        doc.heading("Section")
        doc.text("body")
        pdf = ParsedPDF(doc.to_bytes())
        self.assertEqual(len(pdf.pages()), 1)
        self.assertIn("Section", pdf.text())

    def test_heading_keeps_the_following_line(self):
        doc = Document()
        while doc.y - MARGIN > 36:
            doc.text("filler", size=10)
        doc.heading("Section title")
        doc.text("BODYLINE")
        pdf = ParsedPDF(doc.to_bytes())
        homes = {}
        for index, page in enumerate(pdf.pages()):
            text = "\n".join(pdf.page_text(page))
            if "Section title" in text:
                homes["heading"] = index
            if "BODYLINE" in text:
                homes["body"] = index
        self.assertEqual(homes["heading"], homes["body"])
        self.assertTrue(all(y >= MARGIN for y in _baselines(doc)))

    def test_trailing_space_does_not_open_a_blank_page(self):
        doc = Document()
        doc.text("Hello")
        doc.space(5000)
        self.assertEqual(len(doc.pages), 1)
        doc.text("Next")
        pdf = ParsedPDF(doc.to_bytes())
        pages = pdf.pages()
        self.assertEqual(len(pages), 2)
        self.assertIn("Hello", pdf.page_text(pages[0]))
        self.assertNotIn("Next", pdf.page_text(pages[0]))
        self.assertIn("Next", pdf.page_text(pages[1]))

    def test_table_spacer_does_not_add_a_blank_page(self):
        # size 7 and 60 data rows end 4 points above the margin. space(4)
        # used to cross it and emit a page with nothing but a footer.
        doc = Document(footer="footer")
        rows = [[str(i), "x"] for i in range(60)]
        doc.table(["A", "B"], rows, size=7)
        self.assertTrue(all(doc.pages))
        pdf = ParsedPDF(doc.to_bytes())
        self.assertEqual(len(pdf.pages()), 1)
        text = pdf.text()
        self.assertIn("0", text)
        self.assertIn("59", text)
        self.assertIn("Page 1 of 1", text)
        self.assertTrue(all(y >= MARGIN for y in _baselines(doc)))

    def test_banner_splits_instead_of_crossing_the_footer(self):
        doc = Document()
        doc.banner("word " * 2000, size=10)
        self.assertTrue(all(doc.pages))
        self.assertGreater(len(doc.pages), 1)
        pdf = ParsedPDF(doc.to_bytes())
        self.assertGreaterEqual(pdf.text().count("word"), 2000)
        for number in pdf.offsets:
            pdf.obj(number)
        self.assertTrue(all(y >= MARGIN for y in _baselines(doc)))

    def test_short_banner_stays_on_one_page(self):
        doc = Document()
        doc.banner("SYNTHETIC DATA")
        pdf = ParsedPDF(doc.to_bytes())
        self.assertEqual(len(pdf.pages()), 1)
        self.assertIn("SYNTHETIC DATA", pdf.text())

    def test_long_footer_leaves_room_for_the_page_number(self):
        footer = "Watchpost " + "W" * 300
        doc = Document(footer=footer)
        doc.text("Hello")
        pdf = ParsedPDF(doc.to_bytes())
        lines = pdf.page_text(pdf.pages()[0])
        shown, label = lines[-2], lines[-1]
        self.assertEqual(label, "Page 1 of 1")
        self.assertTrue(shown.endswith("..."))
        self.assertLess(len(shown), len(footer))
        limit = PAGE_W - 2 * MARGIN
        self.assertLessEqual(text_width(shown, 8) + text_width(label, 8) + 12, limit)
        self.assertIn("Hello", lines)

    def test_table_survives_empty_and_zero_widths(self):
        doc = Document()
        doc.table([], [])
        doc.table(["A"], [["x"]], widths=[0])
        doc.table(["A", "B"], [["left", "right"]], widths=[0, 0])
        text = ParsedPDF(doc.to_bytes()).text()
        self.assertIn("x", text)
        self.assertIn("left", text)
        self.assertIn("right", text)

    def test_table_keeps_cells_past_the_header(self):
        doc = Document()
        doc.table(["A", "B"], [["only", "two", "THREE"]])
        self.assertIn("THREE", ParsedPDF(doc.to_bytes()).text())

    def test_truncate_stays_inside_the_width(self):
        sample = "Hello world this is long"
        for width in (0, 1, 5, 10, 18, 40, -3):
            out = truncate(sample, width, 8)
            if width <= 0:
                self.assertEqual(out, "")
            else:
                self.assertLessEqual(text_width(out, 8), width)

    def test_wrap_negative_width_finishes(self):
        lines = wrap("ab cd", -5, 10)
        self.assertEqual("".join(lines), "abcd")
        self.assertTrue(lines)
        self.assertTrue(all(len(line) == 1 for line in lines))

    def test_text_indent_past_the_margin_finishes(self):
        doc = Document()
        doc.text("abcdef", indent=10000)
        text = ParsedPDF(doc.to_bytes()).text()
        for char in "abcdef":
            self.assertIn(char, text)

    def test_wrap_treats_crlf_as_a_break(self):
        self.assertEqual(wrap("hello\r\nworld", 500, 10), ["hello", "world"])
        self.assertEqual(wrap("hello\rworld", 500, 10), ["hello", "world"])
        tight = wrap("hello\r\nworld", text_width("hello", 10) + 1, 10)
        self.assertNotIn("", tight)
        self.assertEqual(wrap("one\ntwo", 500, 10), ["one", "two"])
        self.assertEqual(clean("a\tb\x00c"), "a b c")

    def test_overlong_word_splits_without_a_blank_line(self):
        token = "a" * 4000
        lines = wrap(token, 80, 10)
        self.assertNotIn("", lines)
        self.assertEqual("".join(lines), token)
        for line in lines:
            self.assertLessEqual(text_width(line, 10), 80)

    def test_wrap_preserves_a_blank_paragraph(self):
        self.assertEqual(wrap("one\n\ntwo", 500, 10), ["one", "", "two"])


if __name__ == "__main__":
    unittest.main()
