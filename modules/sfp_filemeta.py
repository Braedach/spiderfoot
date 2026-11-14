from __future__ import annotations

"""SpiderFoot plug-in module: filemeta."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_filemeta
# Purpose:      From Spidering and from searching search engines, extracts file
#               meta data from files matching certain file extensions.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     MIT
# -------------------------------------------------------------------------------

import io
import urllib.parse

import pypdf

import docx

import exifread

import pptx

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_filemeta(SpiderFootAsyncPlugin):
    """SpiderFoot plugin for extracting file metadata."""
    meta = {
        'name': "File Metadata Extractor",
        'summary': "Extracts meta data from documents and images.",
        'flags': [],
        'useCases': ["Footprint"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
        'fileexts': ["docx", "pptx", 'pdf', 'jpg', 'jpeg', 'tiff', 'tif'],
        'timeout': 300
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions to analyse the meta data of. Supported: pdf, docx, pptx, jpg, jpeg, tiff, tif.",
        'timeout': "Download timeout for files, in seconds."
    }

    results = None

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"
    # What events is this module interested in for input
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["LINKED_URL_INTERNAL", "INTERESTING_FILE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["RAW_FILE_META_DATA", "SOFTWARE_USED"]

    @staticmethod
    def _extension(url: str) -> str:
        """Lower-case file extension of the URL's path ("" when there is none)."""
        try:
            path = urllib.parse.urlsplit(url).path
        except ValueError:
            return ""
        name = path.rsplit("/", 1)[-1]
        return name.rsplit(".", 1)[-1].lower() if "." in name else ""

    @staticmethod
    def _pdf_meta(content: bytes) -> tuple[dict, list[str]]:
        """(metadata, software names) of a PDF."""
        info = pypdf.PdfReader(io.BytesIO(content), strict=False).metadata or {}
        fields = {str(k).lstrip("/"): str(v) for k, v in info.items() if v is not None and str(v).strip()}
        return fields, [fields[k] for k in ("Producer", "Creator") if k in fields]

    @staticmethod
    def _office_meta(content: bytes, ext: str) -> tuple[dict, list[str]]:
        """(metadata, software names) of a .docx or .pptx file."""
        opened = docx.Document(io.BytesIO(content)) if ext == "docx" else pptx.Presentation(io.BytesIO(content))
        props = opened.core_properties
        fields = {}
        for label, attr in (("Author", "author"), ("Last modified by", "last_modified_by"), ("Title", "title"),
                            ("Subject", "subject"), ("Comments", "comments"), ("Keywords", "keywords"),
                            ("Category", "category"), ("Created", "created"), ("Modified", "modified")):
            value = getattr(props, attr, None)
            if value is not None and str(value).strip():
                fields[label] = str(value).strip()
        return fields, []

    @staticmethod
    def _image_meta(content: bytes) -> tuple[dict, list[str]]:
        """(metadata, software names) of a JPEG or TIFF image (EXIF)."""
        tags = exifread.process_file(io.BytesIO(content), details=False) or {}
        fields = {str(k): str(v).strip() for k, v in tags.items() if str(v).strip()}
        return fields, [fields[k] for k in ("Image Software",) if k in fields]

    # Handle events sent to this module
    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Download a document or image the target links to and report its embedded meta data."""
        if self.errorState:
            return

        eventData = event.data
        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if eventData in self.results:
            return
        self.results[eventData] = True

        ext = self._extension(eventData)
        wanted = {str(e).lower().lstrip(".") for e in self.opts['fileexts']}
        if not ext or ext not in wanted:
            return
        if self.checkForStop():
            return

        # The file must arrive as the bytes the server sent. fetch_url() returns text (decoded as
        # UTF-8 with bad bytes replaced), which no document or image parser can read: every file
        # failed with "a bytes-like object is required, not 'str'".
        content = self.sf.fetchBytes(eventData, timeout=self.opts['timeout'],
                                     useragent=self.opts.get('_useragent', 'SpiderFoot'), sizeLimit=10000000,
                                     verify=False)
        if content is None:
            self.info(f"Could not download file for meta analysis: {eventData}")
            return
        if len(content) < 512:
            self.debug(f"Skipping {eventData}: {len(content)} bytes is too small to hold meta data")
            return

        try:
            if ext == "pdf":
                fields, software = self._pdf_meta(content)
            elif ext in ("docx", "pptx"):
                fields, software = self._office_meta(content, ext)
            elif ext in ("jpg", "jpeg", "tiff", "tif"):
                fields, software = self._image_meta(content)
            else:
                self.debug(f"No meta data reader for .{ext} files: {eventData}")
                return
        except Exception as e:
            # A damaged or mislabelled file is a property of the file, not a module failure.
            self.info(f"No readable meta data in {eventData} ({type(e).__name__}: {e})")
            return

        if not fields:
            self.debug(f"No meta data in {eventData}")
            return

        meta = "\n".join(f"{k}: {v}" for k, v in sorted(fields.items()))
        rawevt = SpiderFootEvent("RAW_FILE_META_DATA", meta, self.__name__, event)
        self.notifyListeners(rawevt)

        for name in dict.fromkeys(software):
            # Strip non-ASCII
            name = ''.join(c if ord(c) < 128 else ' ' for c in name).strip()
            if name:
                self.notifyListeners(SpiderFootEvent("SOFTWARE_USED", name, self.__name__, rawevt))
