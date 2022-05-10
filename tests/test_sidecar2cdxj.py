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


def test_convert_payload_to_json():
    record = get_sidecar_record(TEXT_META_FILE)
    new_dict = sidecar2cdxj.convert_payload_to_json(record)
    assert new_dict == CDXJ_JSON


@patch('sidecar2cdxj.convert_payload_to_json')
def test_record_data_to_string(m_json):
    m_json.return_value = CDXJ_JSON
    record = get_sidecar_record(TEXT_META_FILE)
    record_string = sidecar2cdxj.record_data_to_string(record)
    m_json.assert_called_once_with(record)
    expected = 'edu,unt)/ 20211111211111 {}\n'.format(CDXJ_JSON)
    assert record_string == expected


class Test_Create_Sidecar_Cdxj:
    @patch('sidecar2cdxj.surt.surt')
    @patch('sidecar2cdxj.iso_date_to_timestamp')
    @patch('sidecar2cdxj.convert_payload_to_json')
    @patch('sidecar2cdxj.create_cdxj_path')
    def test_create_sidecar_cdxj(self, m_path, m_to_json, m_ts, m_surt, tmpdir):
        m_ts.return_value = '20211111211111'
        m_surt.return_value = 'edu,unt)/'
        m_to_json.return_value = CDXJ_JSON
        m_path.return_value = os.path.join(tmpdir / 'warc.cdxj')
        sidecar2cdxj.create_sidecar_cdxj(TEXT_META_FILE, str(tmpdir))
        m_to_json.assert_called_once()
        m_ts.assert_called_once_with('2021-11-11T21:11:11Z')
        m_surt.assert_called_once_with('https://www.unt.edu')
        m_path.assert_called_once_with(TEXT_META_FILE, str(tmpdir))
        path = os.path.join(tmpdir / 'warc.cdxj')
        expected = 'edu,unt)/ 20211111211111 {}\n'.format(CDXJ_JSON)
        assert path in tmpdir.listdir()
        with open(path, 'r') as out:
            lines = out.readlines()
            # Confirm that warcinfo record was skipped.
            assert len(lines) == 1
            assert expected in lines
