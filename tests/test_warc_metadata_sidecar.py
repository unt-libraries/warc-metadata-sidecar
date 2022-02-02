import io
import os
import socket
import pkg_resources
from logging import INFO
from unittest.mock import patch

import warc_metadata_sidecar as sidecar


hostname = socket.gethostname()

text_test_file = os.path.join(os.path.dirname(__file__), 'text.warc')

dns_test_file = os.path.join(os.path.dirname(__file__), 'dns.warc')

image_test_file = os.path.join(os.path.dirname(__file__), 'gif.warc')

records = {'url': 'https://www.unt.edu',
           'payload': io.BytesIO(b'<!DOCTYPE html>\n<!--[if IE 8]>\n'
                                 b'<html class="no-js lt-ie9" lang="en" dir="ltr"> <![endif]-->\n'
                                 b'<!--[if gt IE 8]><!-->\n'
                                 b'<html class="no-js" lang="en" dir="ltr"> <!--<![endif]-->\n'
                                 b'<head>\n'
                                 b'<meta charset="utf-8" />\n'
                                 b'</head>\n'
                                 b'<body>some text</body>\n'
                                 b'</html>\n'
                                 b'</html>\n')}

warcinfo_payload = io.BytesIO(b'software: Webrecorder Platform v3.7\r\n'
                              b'format: WARC File Format 1.0\r\n'
                              b'isPartOf: Temporary Collection\r\n')

warcinfo_dict = {'software': 'warc-metadata-sidecar/1.0',
                 'hostname': hostname,
                 'ip': socket.gethostbyname(hostname),
                 'conformsTo': 'http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1_latestdraft.pdf',
                 'description': 'WARC metdata sidecar for sample.warc',
                 'publisher': 'University of North Texas - Digital Projects Unit',
                 'isPartOf': 'Temporary Collection'}


def test_find_mime_and_puid():
    fido = sidecar.ExtendFido()
    sidecar.find_mime_and_puid(fido, records['payload'], records['url'])
    assert fido.puid == 'fmt/471'
    assert fido.mime == 'text/html'


def test_find_character_set():
    records['payload'].seek(0)
    decoded_payload = records['payload'].read()
    result_dict = sidecar.find_character_set(decoded_payload)
    assert result_dict == {'encoding': 'ascii', 'confidence': 1.0}


def test_find_language():
    records['payload'].seek(0)
    decoded_payload = records['payload'].read()
    language = sidecar.find_language(decoded_payload)
    assert language == {'reliable': True,
                        'text-bytes': 11,
                        'languages': [{'name': 'ENGLISH',
                                       'code': 'en',
                                       'text-covered': 90,
                                       'score': 2048.0}]}


def test_create_warcinfo_payload():
    payload = warcinfo_payload
    publisher = 'University of North Texas - Digital Projects Unit'
    version = pkg_resources.require("warc-metadata-sidecar")[0].version
    warcinfo = sidecar.create_warcinfo_payload(payload, None,
                                               publisher, 'sample.warc',
                                               version)
    assert warcinfo == warcinfo_dict


class Test_Warc_Metadata_Sidecar:

    @patch('warc_metadata_sidecar.WARCWriter')
    def test_metadata_sidecar(self, mock_warcwriter, caplog, tmpdir):
        caplog.set_level(INFO)
        writer = mock_warcwriter.return_value
        m_create_warc_record = writer.create_warc_record.return_value
        sidecar.metadata_sidecar(str(tmpdir), text_test_file)
        assert 'Logging WARC metadata record information for %s', text_test_file in caplog.text
        assert 'Found 2 record(s)' in caplog.text
        assert tmpdir / 'text.warc.meta.gz' in tmpdir.listdir()
        assert mock_warcwriter.call_count == 2
        writer.write_record.assert_called_with(m_create_warc_record)

    @patch('warc_metadata_sidecar.WARCWriter')
    def test_metadata_sidecar_dns_record(self, mock_warcwriter, caplog, tmpdir):
        caplog.set_level(INFO)
        writer = mock_warcwriter.return_value
        m_create_warc_record = writer.create_warc_record
        sidecar.metadata_sidecar(str(tmpdir), dns_test_file)
        assert 'Logging WARC metadata record information for %s', dns_test_file in caplog.text
        assert 'Deleted sidecar, no records to collect.' in caplog.text
        assert tmpdir / 'dns.warc.meta.gz' not in tmpdir.listdir()
        mock_warcwriter.assert_called_once()
        m_create_warc_record.assert_not_called()

    @patch('warc_metadata_sidecar.find_character_set')
    @patch('warc_metadata_sidecar.find_language')
    def test_metadata_sidecar_image_record(self, mock_language, mock_character, tmpdir):
        sidecar.metadata_sidecar(str(tmpdir), image_test_file)
        mock_language.assert_not_called()
        mock_character.assert_not_called()

    @patch('warc_metadata_sidecar.find_character_set')
    @patch('warc_metadata_sidecar.find_language')
    def test_metadata_sidecar_text_record(self, mock_language, mock_character, tmpdir):
        sidecar.metadata_sidecar(str(tmpdir), text_test_file)
        mock_language.assert_called_once()
        mock_character.assert_called_once()
