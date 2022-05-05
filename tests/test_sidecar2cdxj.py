import json
import os
from unittest.mock import patch

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


class Test_Create_Sidecar_Cdxj:
    @patch('sidecar2cdxj.iso_date_to_timestamp')
    @patch('sidecar2cdxj.surt.surt')
    def test_create_sidecar_cdxj(self, m_surt, m_timestamp, tmpdir):
        m_surt.return_value = 'edu,unt)'
        m_timestamp.return_value = '20211111211111'
        sidecar2cdxj.create_sidecar_cdxj(TEXT_META_FILE, str(tmpdir))
        m_surt.assert_called_once_with('https://www.unt.edu')
        m_timestamp.assert_called_once_with('2021-11-11T21:11:11Z')
        path = os.path.join(tmpdir / 'warc.cdxj')
        assert path in tmpdir.listdir()
        with open(path, 'r') as out:
            line = out.readlines()
            # Confirm that warcinfo record was skipped.
            count = len(line)
            assert count == 1
            assert 'edu,unt)' + ' ' + '20211111211111' + ' ' + CDXJ_JSON + '\n' in line
