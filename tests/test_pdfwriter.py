import unittest

from tests.pdfparse import ParsedPDF
from watchpost.pdfwriter import Document, clean, text_width, wrap


class PdfWriterTests(unittest.TestCase):
    def test_single_page_structure(self):
        doc = Document(title="Test (1)", footer="footer")
        doc.heading("Incident report: brute force")
        doc.text("Hello world")
        data = doc.to_bytes()
        self.assertTrue(data.startswith(b"%PDF-1.4\n"))
        self.assertTrue(data.endswith(b"%%EOF\n"))
        pdf = ParsedPDF(data)
        self.assertEqual(len(pdf.pages()), 1)
        text = pdf.text()
        self.assertIn("Incident report: brute force", text)
        self.assertIn("Page 1 of 1", text)
        self.assertIn(b"/Title (Test \\(1\\))", data)

    def test_xref_offsets_point_at_every_object(self):
        doc = Document()
        for i in range(200):
            doc.text(f"line {i}")
        pdf = ParsedPDF(doc.to_bytes())
        for number in pdf.offsets:
            pdf.obj(number)  # raises when an offset is wrong
        self.assertEqual(sorted(pdf.offsets), list(range(1, max(pdf.offsets) + 1)))

    def test_page_breaks(self):
        doc = Document()
        for i in range(150):
            doc.text(f"line {i}", size=10)
        pdf = ParsedPDF(doc.to_bytes())
        pages = pdf.pages()
        self.assertEqual(len(pages), len(doc.pages))
        self.assertGreaterEqual(len(pages), 3)
        self.assertIn("line 0", pdf.page_text(pages[0]))
        self.assertIn("line 149", pdf.page_text(pages[-1]))
        self.assertIn(f"Page {len(pages)} of {len(pages)}", pdf.page_text(pages[-1]))

    def test_table_repeats_header_and_truncates_cells(self):
        doc = Document()
        rows = [[str(i), "x" * 300] for i in range(120)]
        doc.table(["Number", "Payload"], rows, widths=[1, 3])
        pdf = ParsedPDF(doc.to_bytes())
        pages = pdf.pages()
        self.assertGreater(len(pages), 1)
        for page in pages:
            self.assertIn("Number", pdf.page_text(page))
        text = pdf.text()
        self.assertIn("119", text)
        self.assertIn("...", text)
        self.assertNotIn("x" * 300, text)

    def test_escaping_and_unicode(self):
        doc = Document()
        doc.text("paren ( ) and backslash \\ and café — 中文")
        doc.banner("SYNTHETIC DATA")
        text = ParsedPDF(doc.to_bytes()).text()
        self.assertIn("paren ( ) and backslash \\ and café - ??", text)
        self.assertIn("SYNTHETIC DATA", text)

    def test_wrap_respects_width(self):
        long = "word " * 200 + "a" * 500
        for line in wrap(long, 200, 10):
            self.assertLessEqual(text_width(line, 10), 200)
        self.assertEqual(wrap("one\ntwo", 500, 10), ["one", "two"])
        self.assertEqual(clean("a\tb\x00c"), "a b c")


if __name__ == "__main__":
    unittest.main()
