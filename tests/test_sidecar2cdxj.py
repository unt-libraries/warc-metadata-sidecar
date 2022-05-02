import json
import os

import surt
from unittest.mock import patch
from warcio.timeutils import iso_date_to_timestamp

import sidecar2cdxj


TEST_DIR = os.path.dirname(__file__)

TEXT_META_FILE = os.path.join(TEST_DIR, 'text.warc.meta.gz')

WARC_PAYLOAD = json.dumps({'Identified-Payload-Type': {'fido': 'text/html',
                                                       'python-magic': 'text/html'},
                           'Preservation-Identifier': 'fmt/471',
                           'Charset-Detected': {'encoding': 'utf-8', 'confidence': 0.99},
                           'Languages-cld2': {'reliable': True,
                                              'text-bytes': 7896,
                                              'languages': [{'name': 'ENGLISH',
                                                             'code': 'en',
                                                             'text-covered': 99,
                                                             'score': 1070.0}]}})


def test_surt():
    surt_url = surt.surt('https://www.example.com/example_arg')
    assert surt_url == 'com,example)/example_arg'


def test_iso_date_to_timestamp():
    timestamp = iso_date_to_timestamp('2022-01-01T02:02:22Z')
    assert timestamp == '20220101020222'


class Test_Create_Sidecar_Cdxj:
    @patch('sidecar2cdxj.iso_date_to_timestamp')
    @patch('sidecar2cdxj.surt.surt')
    def test_create_sidecar_cdxj(self, m_surt, m_timestamp, tmpdir):
        m_surt.return_value = 'edu,unt)'
        m_timestamp.return_value = '20211111211111'
        sidecar2cdxj.create_sidecar_cdxj(TEXT_META_FILE, str(tmpdir))
        m_surt.assert_called_once_with('https://www.unt.edu')
        m_timestamp.assert_called_once_with('2021-11-11T21:11:11Z')
        path = os.path.join(tmpdir / 'text.cdxj')
        assert path in tmpdir.listdir()
        with open(path, 'r') as out:
            line = out.readline()
            assert WARC_PAYLOAD in line
