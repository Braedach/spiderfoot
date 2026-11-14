"""sfp_filemeta must read real files: every file used to fail because it was fetched as text."""
from __future__ import annotations

import io
from unittest.mock import MagicMock

import docx
import pptx
import pypdf
from PIL import Image

from modules.sfp_filemeta import sfp_filemeta
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


def _pdf() -> bytes:
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_metadata({"/Producer": "Acme PDF 4.2", "/Creator": "Acme Writer", "/Author": "J Smith"})
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue() + b"\n" * 600


def _docx() -> bytes:
    document = docx.Document()
    document.core_properties.author = "J Smith"
    document.core_properties.comments = "internal draft"
    document.add_paragraph("x" * 2000)
    out = io.BytesIO()
    document.save(out)
    return out.getvalue()


def _pptx() -> bytes:
    deck = pptx.Presentation()
    deck.core_properties.author = "A Jones"
    out = io.BytesIO()
    deck.save(out)
    return out.getvalue()


def _jpeg(with_exif: bool = True) -> bytes:
    img = Image.effect_noise((96, 96), 60).convert("RGB")
    out = io.BytesIO()
    if with_exif:
        exif = Image.Exif()
        exif[0x0131] = "Acme Photo 9"      # Software
        exif[0x010F] = "AcmeCam"           # Make
        img.save(out, format="JPEG", exif=exif)
    else:
        img.save(out, format="JPEG")
    return out.getvalue()


class TestFilemetaParsing(TestModuleBase):

    def _run(self, url: str, content: bytes | None):
        sf = SpiderFoot(self.default_options)
        sf.fetchBytes = MagicMock(return_value=content)
        module = sfp_filemeta()
        module.__name__ = "sfp_filemeta"
        module.setup(sf, dict())
        module.sf = sf
        events, errors = [], []
        module.notifyListeners = events.append
        module.error = errors.append
        module.checkForStop = lambda: False
        module.handleEvent(SpiderFootEvent("LINKED_URL_INTERNAL", url, "sfp_spider", None))
        return events, errors, sf.fetchBytes

    def _by_type(self, events, etype):
        return [e.data for e in events if e.eventType == etype]

    def test_pdf(self):
        events, errors, _ = self._run("http://e.com/docs/report.pdf", _pdf())
        self.assertEqual(errors, [])
        meta = self._by_type(events, "RAW_FILE_META_DATA")
        self.assertEqual(len(meta), 1)
        self.assertIn("Author: J Smith", meta[0])
        self.assertEqual(sorted(self._by_type(events, "SOFTWARE_USED")), ["Acme PDF 4.2", "Acme Writer"])

    def test_docx(self):
        events, errors, _ = self._run("http://e.com/a/letter.docx", _docx())
        self.assertEqual(errors, [])
        meta = self._by_type(events, "RAW_FILE_META_DATA")[0]
        self.assertIn("Author: J Smith", meta)
        self.assertIn("Comments: internal draft", meta)

    def test_pptx(self):
        events, errors, _ = self._run("http://e.com/a/deck.pptx", _pptx())
        self.assertEqual(errors, [])
        self.assertIn("Author: A Jones", self._by_type(events, "RAW_FILE_META_DATA")[0])

    def test_jpeg_with_exif(self):
        """The live failure: 121 of these, each 'a bytes-like object is required, not str'."""
        events, errors, _ = self._run("http://e.com/images/home1.jpg", _jpeg())
        self.assertEqual(errors, [])
        self.assertIn("Image Make: AcmeCam", self._by_type(events, "RAW_FILE_META_DATA")[0])
        self.assertEqual(self._by_type(events, "SOFTWARE_USED"), ["Acme Photo 9"])

    def test_jpeg_without_exif_is_silent(self):
        events, errors, _ = self._run("http://e.com/images/plain.jpeg", _jpeg(with_exif=False))
        self.assertEqual((events, errors), ([], []))

    def test_tif_extension_is_handled(self):
        img = Image.effect_noise((64, 64), 60)
        out = io.BytesIO()
        img.save(out, format="TIFF", software="Acme Scan")
        events, errors, _ = self._run("http://e.com/scan.tif", out.getvalue())
        self.assertEqual(errors, [])
        self.assertEqual(self._by_type(events, "SOFTWARE_USED"), ["Acme Scan"])

    def test_a_damaged_file_is_not_a_module_error(self):
        events, errors, _ = self._run("http://e.com/broken.pdf", b"%PDF-1.4 not really a pdf" + b"\x00" * 800)
        self.assertEqual((events, errors), ([], []))

    def test_download_failure_and_tiny_files_are_not_errors(self):
        self.assertEqual(self._run("http://e.com/gone.pdf", None)[:2], ([], []))
        self.assertEqual(self._run("http://e.com/tiny.jpg", b"abc")[:2], ([], []))

    def test_only_listed_extensions_are_downloaded(self):
        for url in ("http://e.com/page.jsp", "http://e.com/index.jsp?file=report.pdf", "http://e.com/a.pdf.html",
                    "http://e.com/dir.jpg/"):
            _, _, fetch = self._run(url, _pdf())
            self.assertFalse(fetch.called, url)
        _, _, fetch = self._run("http://e.com/Report.PDF?download=1", _pdf())
        self.assertTrue(fetch.called)

    def test_the_same_url_is_fetched_once(self):
        sf = SpiderFoot(self.default_options)
        sf.fetchBytes = MagicMock(return_value=_jpeg())
        module = sfp_filemeta()
        module.__name__ = "sfp_filemeta"
        module.setup(sf, dict())
        module.sf = sf
        module.notifyListeners = lambda e: None
        module.checkForStop = lambda: False
        for _ in range(3):
            module.handleEvent(SpiderFootEvent("LINKED_URL_INTERNAL", "http://e.com/i.jpg", "sfp_spider", None))
        self.assertEqual(sf.fetchBytes.call_count, 1)
