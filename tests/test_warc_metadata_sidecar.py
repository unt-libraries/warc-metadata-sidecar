import io
import os
from logging import INFO

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

    def test_metadata_sidecar(self, caplog, tmpdir):
        print(tmpdir)
        caplog.set_level(INFO)
        sidecar.metadata_sidecar(str(tmpdir), 'test_warc.warc')
        assert 'Logging WARC metadata record information for test_warc.warc' in caplog.text
        assert 'Http headers not present for dns:cio.gov' in caplog.text
        assert tmpdir.listdir() == [tmpdir / 'test_warc.warc.meta']

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
