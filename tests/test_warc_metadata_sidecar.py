import io
import json
import os
import socket
from logging import INFO
from unittest.mock import patch, call

import pycld2 as cld2
from warcio.archiveiterator import ArchiveIterator
import warc_metadata_sidecar as sidecar


HOSTNAME = socket.gethostname()

TEST_DIR = os.path.dirname(__file__)

TEXT_TEST_FILE = os.path.join(TEST_DIR, 'text.warc')
DNS_TEST_FILE = os.path.join(TEST_DIR, 'dns.warc')
IMAGE_TEST_FILE = os.path.join(TEST_DIR, 'gif.warc')
REVISIT_TEST_FILE = os.path.join(TEST_DIR, 'revisit.warc')
ARC_TEST_FILE = os.path.join(TEST_DIR, 'text.arc')
DIGEST_TEST_FILE = os.path.join(TEST_DIR, 'digest_multiples.warc')

RECORD1 = {'url': 'https://www.unt.edu',
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

RECORD_LANG_DICT = {'reliable': True,
                    'text-bytes': 11,
                    'languages': [{'name': 'ENGLISH',
                                   'code': 'en',
                                   'text-covered': 90,
                                   'score': 2048.0}]}

CLD2 = (True,
        7896,
        (('Unknown', 'un', 99, 1070.0), ('Unknown', 'un', 0, 0.0), ('Unknown', 'un', 0, 0.0)))

WARCINFO_DICT = {'software': 'warc-metadata-sidecar/1.0',
                 'hostname': HOSTNAME,
                 'ip': socket.gethostbyname(HOSTNAME),
                 'conformsTo': 'http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1_latestdraft.pdf',
                 'description': 'WARC metdata sidecar for sample.warc',
                 'publisher': 'University of North Texas - Digital Projects Unit'}


def test_find_mime_and_puid():
    fido = sidecar.ExtendFido()
    mime_and_puid = sidecar.find_mime_and_puid(fido, RECORD1['payload'])
    assert mime_and_puid == ({'fido': 'text/html', 'python-magic': 'text/html'}, 'fmt/471')


def test_find_character_set():
    RECORD1['payload'].seek(0)
    result_dict = sidecar.find_character_set(RECORD1['payload'])
    assert result_dict == {'encoding': 'ascii', 'confidence': 1.0}


def test_find_language():
    RECORD1['payload'].seek(0)
    decoded_payload = RECORD1['payload'].read()
    language = sidecar.find_language(decoded_payload)
    assert language == RECORD_LANG_DICT


def test_unknown_language():
    with patch.object(cld2, 'detect', return_value=CLD2):
        language = sidecar.find_language(b'some_bytes')
    assert language is None


@patch('soft404.probability', return_value='0.978654321')
def test_determine_soft404(m_soft404):
    soft404_page = b'<h1>Page Not Found<h1>'
    detected = sidecar.determine_soft404(soft404_page)
    m_soft404.assert_called_once()
    assert detected == '0.978654321'


def test_create_warcinfo_payload():
    publisher = 'University of North Texas - Digital Projects Unit'
    warcinfo = sidecar.create_warcinfo_payload('sample.warc', None, publisher)
    assert warcinfo == WARCINFO_DICT


def test_create_string_payload():
    mime_dict = {'fido': 'text/html', 'python-magic': 'text/html'}
    puid = 'fmt/471'
    result_dict = {'encoding': 'ascii', 'confidence': 1.0}
    lang_cld = RECORD_LANG_DICT
    soft_404 = '0.022243212227210058'
    payload = sidecar.create_string_payload(mime_dict, puid, result_dict, lang_cld, soft_404)
    assert payload == '{0} {1}\n{2} {3}\n{4} {5}\n{6} {7}\n{8} {9}'.format(
                            sidecar.MIME_TITLE, json.dumps(mime_dict),
                            sidecar.PUID_TITLE, puid,
                            sidecar.CHARSET_TITLE, json.dumps(result_dict),
                            sidecar.LANGUAGE_TITLE, json.dumps(lang_cld),
                            sidecar.SOFT404_TITLE, soft_404)


class Test_Warc_Metadata_Sidecar:

    @patch('warc_metadata_sidecar.determine_soft404')
    @patch('warc_metadata_sidecar.find_mime_and_puid')
    @patch('warc_metadata_sidecar.find_character_set')
    @patch('warc_metadata_sidecar.find_language')
    @patch('warc_metadata_sidecar.create_string_payload', return_value='payload')
    @patch('warc_metadata_sidecar.create_warcinfo_payload')
    @patch('warc_metadata_sidecar.WARCWriter')
    def test_metadata_sidecar(self, mock_warcwriter, m_warcinfo, m_create_payload, m_lang,
                              m_charset, m_find_mime, m_soft404, caplog, tmpdir):
        # Get record digest to test DIGEST_CACHE
        with open(TEXT_TEST_FILE, 'rb') as stream:
            for record in ArchiveIterator(stream):
                record_digest = record.rec_headers.get_header('WARC-Payload-Digest')
        caplog.set_level(INFO)
        writer = mock_warcwriter.return_value
        m_find_mime.return_value = ({'fido': 'text/html'}, 'fmt/471')
        metadata_sidecar_return = sidecar.metadata_sidecar(str(tmpdir), TEXT_TEST_FILE)
        assert 'Logging WARC metadata record information for %s', TEXT_TEST_FILE in caplog.text
        assert 'Determined sidecar information for 1 response/resource record(s)' in caplog.text
        assert tmpdir / 'text.warc.meta.gz' in tmpdir.listdir()
        assert writer.write_record.call_count == 2
        m_warcinfo.assert_called_with('text.warc', None, None)
        calls = [call(writer.create_warcinfo_record.return_value),
                 call(writer.create_warc_record.return_value)]
        writer.write_record.assert_has_calls(calls)
        m_create_payload.assert_called_once()
        m_lang.assert_called_once()
        m_charset.assert_called_once()
        m_find_mime.assert_called_once()
        m_soft404.assert_called_once()
        assert metadata_sidecar_return == (tmpdir / 'text.warc.meta.gz', 1, 1)
        assert record_digest in sidecar.DIGEST_CACHE

    def test_metadata_sidecar_dns_record(self, caplog, tmpdir):
        caplog.set_level(INFO)
        metadata_sidecar_return = sidecar.metadata_sidecar(str(tmpdir), DNS_TEST_FILE)
        assert 'Logging WARC metadata record information for %s', DNS_TEST_FILE in caplog.text
        assert 'No metadata records to write, updating warcinfo' in caplog.text
        assert 'Determined sidecar information for 0 response/resource record(s)' in caplog.text
        with open(os.path.join(tmpdir, 'dns.warc.meta.gz'), 'rb') as stream:
            for record in ArchiveIterator(stream):
                assert b'; 0 metadata sidecar records' in record.raw_stream.read()
        assert metadata_sidecar_return == (tmpdir / 'dns.warc.meta.gz', 1, 0)

    @patch('warc_metadata_sidecar.find_character_set')
    @patch('warc_metadata_sidecar.find_language')
    @patch('warc_metadata_sidecar.determine_soft404')
    def test_metadata_sidecar_image_record(self, mock_404, mock_language, mock_character, tmpdir):
        mime_dict = '{"fido": "image/gif", "python-magic": "image/gif"}'
        puid = 'fmt/4'
        img_payload = '{0} {1}\n{2} {3}'.format(
                            sidecar.MIME_TITLE, mime_dict,
                            sidecar.PUID_TITLE, puid).encode('utf-8')
        metadata_sidecar_return = sidecar.metadata_sidecar(str(tmpdir), IMAGE_TEST_FILE)
        mock_language.assert_not_called()
        mock_character.assert_not_called()
        mock_404.assert_not_called()
        assert tmpdir / 'gif.warc.meta.gz' in tmpdir.listdir()
        path = os.path.join(tmpdir / 'gif.warc.meta.gz')
        with open(path, 'rb') as stream:
            for record in ArchiveIterator(stream):
                if record.rec_type == 'metadata':
                    payload = record.content_stream().read()
        assert payload == img_payload
        assert metadata_sidecar_return == (tmpdir / 'gif.warc.meta.gz', 1, 1)

    def test_metadata_sidecar_revisit_record(self, caplog, tmpdir):
        caplog.set_level(INFO)
        metadata_sidecar_return = sidecar.metadata_sidecar(str(tmpdir), REVISIT_TEST_FILE)
        assert 'Logging WARC metadata record information for %s', REVISIT_TEST_FILE in caplog.text
        assert 'No metadata records to write, updating warcinfo' in caplog.text
        assert 'Determined sidecar information for 0 response/resource record(s)' in caplog.text
        with open(os.path.join(tmpdir, 'revisit.warc.meta.gz'), 'rb') as stream:
            for record in ArchiveIterator(stream):
                assert b'; 0 metadata sidecar records' in record.raw_stream.read()
        assert metadata_sidecar_return == (tmpdir / 'revisit.warc.meta.gz', 1, 0)

    def test_arc_record_has_no_concurrent_or_warcinfo_id(self, tmpdir):
        metadata_sidecar_return = sidecar.metadata_sidecar(str(tmpdir), ARC_TEST_FILE)
        path = os.path.join(tmpdir / 'text.warc.meta.gz')
        assert path in tmpdir.listdir()
        assert metadata_sidecar_return == (tmpdir / 'text.warc.meta.gz', 2, 1)
        with open(path, 'rb') as stream:
            for record in ArchiveIterator(stream):
                if record.rec_type == 'metadata':
                    assert record.rec_headers.get_header('WARC-Concurrent-ID') is None
                    assert record.rec_headers.get_header('WARC-Warcinfo-ID') is None

    @patch('warc_metadata_sidecar.determine_soft404')
    @patch('warc_metadata_sidecar.find_mime_and_puid')
    @patch('warc_metadata_sidecar.find_character_set')
    @patch('warc_metadata_sidecar.find_language')
    @patch('warc_metadata_sidecar.create_string_payload', return_value='payload')
    @patch('warc_metadata_sidecar.create_warcinfo_payload')
    @patch('warc_metadata_sidecar.WARCWriter')
    def test_digest_multiples_use_cache(self, mock_warcwriter, m_warcinfo, m_create_payload,
                                        m_lang, m_charset, m_find_mime, m_soft404, caplog,
                                        tmpdir):
        # Clear the cache from previous tests
        sidecar.DIGEST_CACHE = {}
        # Get record digest from file to test DIGEST_CACHE
        digest_list = []
        with open(DIGEST_TEST_FILE, 'rb') as stream:
            for record in ArchiveIterator(stream):
                digest = record.rec_headers.get_header('WARC-Payload-Digest')
                if digest and digest not in digest_list:
                    digest_list.append(digest)
        caplog.set_level(INFO)
        writer = mock_warcwriter.return_value
        m_find_mime.side_effect = [({'python-magic': 'image/gif'}, None),
                                   ({'python-magic': 'text/plain'}, None)]
        metadata_sidecar_return = sidecar.metadata_sidecar(str(tmpdir), DIGEST_TEST_FILE)
        assert m_warcinfo.call_count == 1
        assert m_create_payload.call_count == 2
        assert m_lang.call_count == 1
        assert m_charset.call_count == 1
        assert m_find_mime.call_count == 2
        assert m_soft404.call_count == 0
        assert 'Determined sidecar information for 4 response/resource record(s)' in caplog.text
        assert writer.write_record.call_count == 5
        assert metadata_sidecar_return == (tmpdir / 'digest_multiples.warc.meta.gz', 5, 4)
        for digest in digest_list:
            assert digest in sidecar.DIGEST_CACHE
