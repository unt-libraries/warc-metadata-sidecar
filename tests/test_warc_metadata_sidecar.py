import os
from logging import ERROR, INFO
from unittest.mock import Mock, patch, mock_open

import chardet
import pycld2 as cld2
from fido.fido import Fido
from warcio.archiveiterator import ArchiveIterator
from warcio.recordloader import ArcWarcRecord
from warcio.warcwriter import WARCWriter

import warc-metadata-sidecar as sidecar

class Test_Warc_Metadata_Sidecar:
    def test_metadata_sidecar(self):
        pass

    def test_find_mime_and_puid(self):
        pass

    def test_find_character_set(self):
        pass