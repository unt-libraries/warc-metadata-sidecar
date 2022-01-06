import io
import os
from logging import INFO
from unittest.mock import patch

from warcio.archiveiterator import ArchiveIterator
from warcio.recordloader import ArcWarcRecord

import warc_metadata_sidecar as sidecar


class Test_Warc_Metadata_Sidecar:
    def get_record(self):
        test_file = os.path.join(os.path.dirname(__file__), 'warc.warc')
        with open(test_file, 'rb') as stream:
            for record in ArchiveIterator(stream):
                url = record.rec_headers.get_header('WARC-Target-URI')
                rawPayload = io.BytesIO(record.raw_stream.read())
                if record.http_headers:
                    recordCopy = ArcWarcRecord(
                        record.format, record.rec_type,
                        record.rec_headers, rawPayload,
                        record.http_headers, record.content_type,
                        record.length
                        )
                    decodedPayload = recordCopy.content_stream().read()
                    rawPayload.seek(0)
                else:
                    decodedPayload = rawPayload
            return(url, rawPayload, decodedPayload)

    @patch('warc_metadata_sidecar.WARCWriter')
    def test_metadata_sidecar(self, mock_warcwriter, caplog, tmpdir):
        caplog.set_level(INFO)
        sidecar.metadata_sidecar(str(tmpdir), 'tests/test_warc.warc')
        assert 'Logging WARC metadata record information for tests/test_warc.warc' in caplog.text
        assert 'Found 0 record(s)' in caplog.text
        assert tmpdir.listdir() == [tmpdir / 'test_warc.warc.meta.gz']
        mock_warcwriter.assert_not_called()
        writer = mock_warcwriter.return_value
        m_create_warc_record = writer.create_warc_record.return_value
        sidecar.metadata_sidecar(str(tmpdir), 'tests/warc.warc')
        assert 'Logging WARC metadata record information for tests/warc.warc' in caplog.text
        assert 'Found 1 record(s)' in caplog.text
        assert tmpdir / 'warc.warc.meta.gz' in tmpdir.listdir()
        mock_warcwriter.assert_called_once()
        writer.write_record.assert_called_once_with(m_create_warc_record)

    def test_find_mime_and_puid(self):
        fido = sidecar.ExtendFido()
        url, rawPayload, decodedPayload = self.get_record()
        sidecar.find_mime_and_puid(fido, rawPayload, url)
        assert url == 'https://www.unt.edu'
        assert fido.puid == 'fmt/471'
        assert fido.mime == 'text/html'

    def test_find_character_set(self):
        url, rawpayload, decodedPayload = self.get_record()
        result_dict = sidecar.find_character_set(decodedPayload)
        assert result_dict['encoding'] == 'utf-8'

    def test_find_language(self):
        url, rawPayload, decodedPayload = self.get_record()
        language = sidecar.find_language(decodedPayload)
        assert language['languages']['name'] == 'ENGLISH'
