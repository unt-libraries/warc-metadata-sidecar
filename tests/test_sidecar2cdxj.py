import json
import os
from unittest.mock import patch

from warcio.archiveiterator import ArchiveIterator

import sidecar2cdxj


TEST_DIR = os.path.dirname(__file__)

TEXT_META_FILE = os.path.join(TEST_DIR, 'warc.warc.meta.gz')

CDXJ_JSON = json.dumps({'Identified-Payload-Type': {'fido': 'text/html',
                                                    'python-magic': 'text/html'},
                        'Preservation-Identifier': 'fmt/471',
                        'Charset-Detected': {'encoding': 'utf-8', 'confidence': 0.99},
                        'Languages-cld2': {'reliable': True,
                                           'text-bytes': 7896,
                                           'languages': [{'name': 'ENGLISH',
                                                          'code': 'en',
                                                          'text-covered': 99,
                                                          'score': 1070.0}]},
                        'Soft-404-Detected': 0.022243212227210058})


def get_sidecar_record(sidecar_file):
    with open(sidecar_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'warcinfo':
                continue
            return record


def test_create_cdxj_path(tmpdir):
    cdxj_path = sidecar2cdxj.create_cdxj_path(TEXT_META_FILE, str(tmpdir))
    expected_path = os.path.join(tmpdir / 'warc.cdxj')
    assert cdxj_path == expected_path


def test_convert_payload_to_dict():
    record = get_sidecar_record(TEXT_META_FILE)
    new_dict = sidecar2cdxj.convert_payload_to_dict(record)
    assert new_dict == json.loads(CDXJ_JSON)


def test_record_data_to_string():
    record = get_sidecar_record(TEXT_META_FILE)
    record_string = sidecar2cdxj.record_data_to_string(record, json.loads(CDXJ_JSON))
    expected = 'edu,unt)/' + ' ' + '20211111211111' + ' ' + CDXJ_JSON + '\n'
    assert record_string == expected


class Test_Create_Sidecar_Cdxj:
    @patch('sidecar2cdxj.record_data_to_string')
    @patch('sidecar2cdxj.convert_payload_to_dict')
    @patch('sidecar2cdxj.create_cdxj_path')
    def test_create_sidecar_cdxj(self, m_path, m_to_dict, m_to_string, tmpdir):
        m_to_string.return_value = 'edu,unt)/' + ' ' + '20211111211111' + ' ' + CDXJ_JSON + '\n'
        m_path.return_value = os.path.join(tmpdir / 'warc.cdxj')
        sidecar2cdxj.create_sidecar_cdxj(TEXT_META_FILE, str(tmpdir))
        m_to_string.assert_called_once()
        m_to_dict.assert_called_once()
        m_path.assert_called_once_with(TEXT_META_FILE, str(tmpdir))
        path = os.path.join(tmpdir / 'warc.cdxj')
        assert path in tmpdir.listdir()
        with open(path, 'r') as out:
            lines = out.readlines()
            # Confirm that warcinfo record was skipped.
            assert len(lines) == 1
            assert m_to_string.return_value in lines
